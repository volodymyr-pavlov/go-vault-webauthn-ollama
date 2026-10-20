// Package server runs the HTTP API of the service. It builds the handlers from a [config.Env], registers the routes
// with their middleware, and serves them with fasthttp.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/config"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/metrics"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/totp"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

const (
	// prefix is the path prefix of the versioned routes of the API.
	prefix = "/v1"

	// DefaultSessionRetention is how long the service keeps an expired session when the setting is zero. It is longer
	// than the history window of the risk engine.
	DefaultSessionRetention = 90 * 24 * time.Hour

	// DefaultRequestLogRetention is how long the service keeps the rows of the request log when the setting is zero. The
	// rows hold the address and the user agent of each request, so the service keeps them for a short time only.
	DefaultRequestLogRetention = 30 * 24 * time.Hour

	// MaxBodySize is the size limit of a request body, in bytes. A WebAuthn response is a few kilobytes.
	MaxBodySize = 64 << 10

	// readTimeout is the time that the HTTP server waits for a whole request, and idleTimeout is the time that it keeps
	// an idle connection open.
	readTimeout = 15 * time.Second
	idleTimeout = 60 * time.Second

	// metricsReadTimeout is the time that the metrics server waits for a request.
	metricsReadTimeout = 5 * time.Second
)

// Server is the HTTP server of the service, with its handlers and middleware. It has the methods of the Server
// interface of package launch. [NewServer] builds it.
type Server struct {
	sessionRetention    time.Duration
	requestLogRetention time.Duration

	addr   string
	logger *slog.Logger
	env    *config.Env
	http   *fasthttp.Server

	metricsAddr   string
	metrics       *metrics.Metrics
	metricsServer *http.Server

	sessionMiddleware    *api.SessionMiddleware
	originMiddleware     *api.Origin
	requestLogMiddleware *api.RequestLog
	observe              *api.Observe
	rateLimit            *api.RateLimit

	healthzHandler                  *api.HealthzHandler
	beginSessionHandler             *api.BeginSessionHandler
	retrieveSessionHandler          *api.RetrieveSessionHandler
	terminateSessionHandler         *api.TerminateSessionHandler
	beginRegistryHandler            *api.BeginRegistryHandler
	completeRegistryHandler         *api.CompleteRegistryHandler
	beginEnrollPasskeyHandler       *api.BeginEnrollPasskeyHandler
	completeEnrollPasskeyHandler    *api.CompleteEnrollPasskeyHandler
	beginEnrollTOTPHandler          *api.BeginEnrollTOTPHandler
	completeEnrollTOTPHandler       *api.CompleteEnrollTOTPHandler
	issueRecoveryCodesHandler       *api.IssueRecoveryCodesHandler
	beginAuthorizePasskeyHandler    *api.BeginAuthorizePasskeyHandler
	completeAuthorizePasskeyHandler *api.CompleteAuthorizePasskeyHandler
	authorizePasswordHandler        *api.AuthorizePasswordHandler
	authorizeTOTPHandler            *api.AuthorizeTOTPHandler
	authorizeRecoveryHandler        *api.AuthorizeRecoveryHandler
	requestRecoveryHandler          *api.RequestRecoveryHandler
	listSessionsHandler             *api.ListSessionsHandler
	removeSessionHandler            *api.RemoveSessionHandler
	cancelRecoveryHandler           *api.CancelRecoveryHandler
	claimRecoveryHandler            *api.ClaimRecoveryHandler
	grantRecoveryHandler            *api.GrantRecoveryHandler
	retrievePasskeysHandler         *api.RetrievePasskeysHandler
	beginRemovePasskeyHandler       *api.BeginRemovePasskeyHandler
	removePasskeyHandler            *api.RemovePasskeyHandler
	beginDeleteUserHandler          *api.BeginDeleteUserHandler
	deleteUserHandler               *api.DeleteUserHandler
	exportUserHandler               *api.ExportUserHandler
	addAuthenticatorHandler         *api.AddAccountHandler
	listAuthenticatorsHandler       *api.ListAccountsHandler
	removeAuthenticatorHandler      *api.RemoveAccountHandler
	removeTOTPHandler               *api.RemoveTOTPHandler
}

// NewServer returns a [Server] that listens on addr and uses env. The server takes the settings that it needs from
// opts.
//
// It returns an error wrapping [config.ErrMissingFromEnv] if env lacks a mandatory dependency.
func NewServer(addr string, logger *slog.Logger, env *config.Env, opts config.Options) (*Server, error) {
	if err := env.Validate(); err != nil {
		return nil, fmt.Errorf("check the environment: %w", err)
	}

	idle := opts.SessionIdle
	if idle == 0 {
		idle = api.DefaultIdleTimeout
	}

	requestLog := &api.RequestLog{
		Logger:            logger,
		SystemClock:       env.SystemClock,
		Locator:           env.Locator,
		HTTPRequestWriter: env.HTTPRequestWriter,
		BuildVersion:      opts.BuildVersion,
	}
	counters := metrics.New()
	rateLimit := &api.RateLimit{
		Limiter: env.RateLimiter,
		Locator: env.Locator,
		Metrics: counters,
	}

	// The server counts the answers of the advisor and the decisions on its own copy of the engine, so a second server
	// on the same environment does not wrap the advisor twice. The wrapper keeps whatever advisor the environment holds.
	engine := *env.Engine
	if engine.Advisor != nil {
		engine.Advisor = &metrics.Advisor{
			Next:    engine.Advisor,
			Metrics: counters,
		}
	}

	engine.OnDecision = func(outcome ai.Outcome) {
		counters.Decision(outcome.Decision.String())
	}

	assessor := &api.RiskAssessor{
		Sessions: env.SessionBatchReader,
		Transit:  env.TransitWriter,
		Engine:   &engine,

		Anonymizing: env.AnonymizingRanges,
	}

	s := &Server{
		addr:                addr,
		sessionRetention:    opts.SessionRetention,
		requestLogRetention: opts.RequestLogRetention,
		logger:              logger,
		env:                 env,
		metricsAddr:         opts.MetricsAddr,
		metrics:             counters,
		sessionMiddleware: &api.SessionMiddleware{
			SessionReader:   env.SessionReader,
			UserReader:      env.UserReader,
			RequestVerifier: env.RequestVerifier,
			SessionWriter:   env.SessionWriter,
			SystemClock:     env.SystemClock,
			PermissionValidator: &api.PermissionValidator{
				IdleTimeout: idle,
				FreshWindow: opts.FreshWindow,
				SystemClock: env.SystemClock,
			},
		},
		originMiddleware: &api.Origin{
			Origins: opts.OriginList(),
		},
		requestLogMiddleware: requestLog,
		observe: &api.Observe{
			Metrics:     counters,
			SystemClock: env.SystemClock,
		},
		rateLimit:      rateLimit,
		healthzHandler: &api.HealthzHandler{},
		beginSessionHandler: &api.BeginSessionHandler{
			SessionWriter:    env.SessionWriter,
			SessionSnowflake: env.SessionSnowflake,
			TransitWriter:    env.TransitWriter,
			RequestVerifier:  env.RequestVerifier,
			Locator:          env.Locator,
			SystemClock:      env.SystemClock,
		},
		retrieveSessionHandler: &api.RetrieveSessionHandler{},
		terminateSessionHandler: &api.TerminateSessionHandler{
			SessionGroupWriter: env.SessionGroupWriter,
			Metrics:            counters,
		},
		beginRegistryHandler: &api.BeginRegistryHandler{
			UserReader:         env.UserReader,
			SessionGroupWriter: env.SessionGroupWriter,
			UserSnowflake:      env.UserSnowflake,
			PasswordHasher:     env.PasswordHasher,
			MessageWriter:      env.MessageWriter,
			SystemClock:        env.SystemClock,
		},
		completeRegistryHandler: &api.CompleteRegistryHandler{
			SessionGroupWriter: env.SessionGroupWriter,
			SystemClock:        env.SystemClock,
		},
		beginEnrollPasskeyHandler: &api.BeginEnrollPasskeyHandler{
			PasskeyBatchReader: env.PasskeyBatchReader,
			SessionGroupWriter: env.SessionGroupWriter,
			RelyingParty:       env.RelyingParty,
			SystemClock:        env.SystemClock,
		},
		completeEnrollPasskeyHandler: &api.CompleteEnrollPasskeyHandler{
			SessionGroupWriter: env.SessionGroupWriter,
			PasskeySnowflake:   env.PasskeySnowflake,
			RelyingParty:       env.RelyingParty,
			MessageWriter:      env.MessageWriter,
			SystemClock:        env.SystemClock,
		},
		beginEnrollTOTPHandler: &api.BeginEnrollTOTPHandler{
			UserWriter:         env.UserWriter,
			PasskeyBatchReader: env.PasskeyBatchReader,
			TransitWriter:      env.TransitWriter,
			Issuer:             opts.RPName,
			Options:            totp.Options{},
		},
		completeEnrollTOTPHandler: &api.CompleteEnrollTOTPHandler{
			UserGroupWriter: env.UserGroupWriter,
			TransitWriter:   env.TransitWriter,
			Options:         totp.Options{},
			MessageWriter:   env.MessageWriter,
			SystemClock:     env.SystemClock,
		},
		issueRecoveryCodesHandler: &api.IssueRecoveryCodesHandler{
			UserGroupWriter:       env.UserGroupWriter,
			RecoveryCodeSnowflake: env.RecoveryCodeSnowflake,
			TransitWriter:         env.TransitWriter,
			MessageWriter:         env.MessageWriter,
		},
		beginAuthorizePasskeyHandler: &api.BeginAuthorizePasskeyHandler{
			UserReader:         env.UserReader,
			PasskeyBatchReader: env.PasskeyBatchReader,
			RelyingParty:       env.RelyingParty,
			TransitWriter:      env.TransitWriter,
			SystemClock:        env.SystemClock,
			SessionGroupWriter: env.SessionGroupWriter,
		},
		completeAuthorizePasskeyHandler: &api.CompleteAuthorizePasskeyHandler{
			UserReader:         env.UserReader,
			PasskeyBatchReader: env.PasskeyBatchReader,
			RelyingParty:       env.RelyingParty,
			RiskAssessor:       assessor,
			MessageWriter:      env.MessageWriter,
			SystemClock:        env.SystemClock,
			SessionGroupWriter: env.SessionGroupWriter,
		},
		authorizePasswordHandler: &api.AuthorizePasswordHandler{
			UserReader:         env.UserReader,
			PasskeyBatchReader: env.PasskeyBatchReader,
			PasswordHasher:     env.PasswordHasher,
			SessionGroupWriter: env.SessionGroupWriter,
			StandInHash:        env.StandInHash,
		},
		authorizeTOTPHandler: &api.AuthorizeTOTPHandler{
			PasskeyBatchReader: env.PasskeyBatchReader,
			TransitWriter:      env.TransitWriter,
			Options:            totp.Options{},
			RiskAssessor:       assessor,
			MessageWriter:      env.MessageWriter,
			SystemClock:        env.SystemClock,
			SessionGroupWriter: env.SessionGroupWriter,
		},
		listSessionsHandler: &api.ListSessionsHandler{
			SessionBatchReader: env.SessionBatchReader,
			SystemClock:        env.SystemClock,
			IdleTimeout:        idle,
		},
		removeSessionHandler: &api.RemoveSessionHandler{
			SessionReader:      env.SessionReader,
			SessionGroupWriter: env.SessionGroupWriter,
			Metrics:            counters,
		},
		requestRecoveryHandler: &api.RequestRecoveryHandler{
			UserReader:               env.UserReader,
			RecoveryRequestReader:    env.RecoveryRequestReader,
			RecoveryRequestSnowflake: env.RecoveryRequestSnowflake,
			MessageWriter:            env.MessageWriter,
			SystemClock:              env.SystemClock,
			Delay:                    opts.RecoveryDelay,
			RecoveryGroupWriter:      env.RecoveryGroupWriter,
			Metrics:                  counters,
		},
		cancelRecoveryHandler: &api.CancelRecoveryHandler{
			RecoveryGroupWriter: env.RecoveryGroupWriter,
			Metrics:             counters,
		},
		claimRecoveryHandler: &api.ClaimRecoveryHandler{
			UserReader:            env.UserReader,
			RecoveryRequestReader: env.RecoveryRequestReader,
			MessageWriter:         env.MessageWriter,
			SystemClock:           env.SystemClock,
			RecoveryGroupWriter:   env.RecoveryGroupWriter,
			Metrics:               counters,
		},
		grantRecoveryHandler: &api.GrantRecoveryHandler{
			RecoveryRequestReader: env.RecoveryRequestReader,
			UserReader:            env.UserReader,
			MessageWriter:         env.MessageWriter,
			RecoveryGroupWriter:   env.RecoveryGroupWriter,
			SessionGroupWriter:    env.SessionGroupWriter,
			Metrics:               counters,
		},
		authorizeRecoveryHandler: &api.AuthorizeRecoveryHandler{
			UserReader:         env.UserReader,
			TransitWriter:      env.TransitWriter,
			MessageWriter:      env.MessageWriter,
			SessionGroupWriter: env.SessionGroupWriter,
		},
		retrievePasskeysHandler: &api.RetrievePasskeysHandler{
			PasskeyBatchReader: env.PasskeyBatchReader,
		},
		beginDeleteUserHandler: &api.BeginDeleteUserHandler{
			PasskeyBatchReader: env.PasskeyBatchReader,
			RelyingParty:       env.RelyingParty,
			SystemClock:        env.SystemClock,
			SessionGroupWriter: env.SessionGroupWriter,
		},
		deleteUserHandler: &api.DeleteUserHandler{
			AccountBatchReader:     env.AccountBatchReader,
			AuthenticatorKeyWriter: env.AuthenticatorKeyWriter,
			PasskeyBatchReader:     env.PasskeyBatchReader,
			RelyingParty:           env.RelyingParty,
			SystemClock:            env.SystemClock,
			UserGroupWriter:        env.UserGroupWriter,
			SessionGroupWriter:     env.SessionGroupWriter,
			MessageWriter:          env.MessageWriter,
		},
		addAuthenticatorHandler: &api.AddAccountHandler{
			AccountBatchReader:     env.AccountBatchReader,
			AccountGroupWriter:     env.AccountGroupWriter,
			AuthenticatorKeyWriter: env.AuthenticatorKeyWriter,
			AccountSnowflake:       env.AccountSnowflake,
		},
		listAuthenticatorsHandler: &api.ListAccountsHandler{
			AccountBatchReader:     env.AccountBatchReader,
			AuthenticatorKeyReader: env.AuthenticatorKeyReader,
			SystemClock:            env.SystemClock,
		},
		removeAuthenticatorHandler: &api.RemoveAccountHandler{
			AccountReader:          env.AccountReader,
			AccountGroupWriter:     env.AccountGroupWriter,
			AuthenticatorKeyWriter: env.AuthenticatorKeyWriter,
		},
		exportUserHandler: &api.ExportUserHandler{
			PasskeyBatchReader:     env.PasskeyBatchReader,
			SessionBatchReader:     env.SessionBatchReader,
			HTTPRequestBatchReader: env.HTTPRequestBatchReader,
			AccountBatchReader:     env.AccountBatchReader,
		},
		beginRemovePasskeyHandler: &api.BeginRemovePasskeyHandler{
			PasskeyReader:      env.PasskeyReader,
			PasskeyBatchReader: env.PasskeyBatchReader,
			RelyingParty:       env.RelyingParty,
			SystemClock:        env.SystemClock,
			SessionGroupWriter: env.SessionGroupWriter,
		},
		removePasskeyHandler: &api.RemovePasskeyHandler{
			UserReader:         env.UserReader,
			PasskeyReader:      env.PasskeyReader,
			PasskeyBatchReader: env.PasskeyBatchReader,
			RelyingParty:       env.RelyingParty,
			SystemClock:        env.SystemClock,
			UserGroupWriter:    env.UserGroupWriter,
			SessionGroupWriter: env.SessionGroupWriter,
			MessageWriter:      env.MessageWriter,
		},
		removeTOTPHandler: &api.RemoveTOTPHandler{
			UserGroupWriter: env.UserGroupWriter,
			MessageWriter:   env.MessageWriter,
		},
	}
	s.metricsServer = &http.Server{
		Handler:           metricsMux(counters),
		ReadHeaderTimeout: metricsReadTimeout,
		ReadTimeout:       metricsReadTimeout,
		IdleTimeout:       idleTimeout,
	}
	s.http = &fasthttp.Server{
		Handler:            s.Routes().Handler(),
		ErrorHandler:       web.ErrorHandler,
		MaxRequestBodySize: MaxBodySize,
		ReadTimeout:        readTimeout,
		IdleTimeout:        idleTimeout,
		Logger:             slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	return s, nil
}

// Metrics returns the [metrics.Metrics] that the server records into. Tests use it to scrape the registry.
func (s *Server) Metrics() *metrics.Metrics {
	return s.metrics
}

// metricsMux returns the handler of the metrics server. It serves GET /metrics and nothing else.
func metricsMux(counters *metrics.Metrics) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", counters.Handler())

	return mux
}

// Handler returns the fasthttp handler of the server. Tests use it to serve the API on their own listener.
func (s *Server) Handler() fasthttp.RequestHandler {
	return s.http.Handler
}

// Routes returns the [web.Mux] of the API.
//
// Every route runs the panic recovery, the security headers, the origin check and the rate limit. Every route except
// healthz also runs the request log middleware. Every route except healthz and the start of a session then runs the session
// middleware of its resource code.
func (s *Server) Routes() *web.Mux {
	m := web.NewMux(s.logger, web.Chain(web.Recover(), api.SecurityHeaders(), s.originMiddleware.Middleware(), s.rateLimit.Middleware()))
	m.Preflight(web.Chain(web.Recover(), api.SecurityHeaders(), s.originMiddleware.Middleware()))
	m.GET("/healthz", s.healthzHandler)
	m.POST(prefix+"/session", s.beginSessionHandler, s.logged(api.BeginSession), s.rateLimit.SessionOpenMiddleware())
	m.GET(prefix+"/session", s.retrieveSessionHandler, s.logged(api.RetrieveSession), s.session(api.RetrieveSession))
	m.DELETE(prefix+"/session", s.terminateSessionHandler, s.logged(api.TerminateSession), s.session(api.TerminateSession))
	m.POST(prefix+"/register", s.beginRegistryHandler, s.logged(api.BeginRegistry), s.session(api.BeginRegistry), s.userLimited())
	m.POST(prefix+"/register/complete", s.completeRegistryHandler, s.logged(api.CompleteRegistry), s.session(api.CompleteRegistry))
	m.POST(prefix+"/enroll/passkey", s.beginEnrollPasskeyHandler, s.logged(api.BeginEnrollPasskey), s.session(api.BeginEnrollPasskey))
	m.POST(prefix+"/enroll/passkey/complete", s.completeEnrollPasskeyHandler, s.logged(api.CompleteEnrollPasskey), s.session(api.CompleteEnrollPasskey))
	m.POST(prefix+"/enroll/totp", s.beginEnrollTOTPHandler, s.logged(api.BeginEnrollTOTP), s.session(api.BeginEnrollTOTP))
	m.POST(prefix+"/enroll/totp/complete", s.completeEnrollTOTPHandler, s.logged(api.CompleteEnrollTOTP), s.session(api.CompleteEnrollTOTP))
	m.POST(prefix+"/enroll/recovery", s.issueRecoveryCodesHandler, s.logged(api.IssueRecoveryCodes), s.session(api.IssueRecoveryCodes))
	m.POST(prefix+"/auth/passkey", s.beginAuthorizePasskeyHandler, s.logged(api.BeginAuthorizePasskey), s.session(api.BeginAuthorizePasskey), s.userLimited())
	m.POST(prefix+"/auth/passkey/complete", s.completeAuthorizePasskeyHandler, s.logged(api.CompleteAuthorizePasskey), s.session(api.CompleteAuthorizePasskey))
	m.POST(prefix+"/auth/password", s.authorizePasswordHandler, s.logged(api.AuthorizePassword), s.session(api.AuthorizePassword), s.userLimited())
	m.POST(prefix+"/auth/totp", s.authorizeTOTPHandler, s.logged(api.AuthorizeTOTP), s.session(api.AuthorizeTOTP))
	m.POST(prefix+"/auth/recovery", s.authorizeRecoveryHandler, s.logged(api.AuthorizeRecovery), s.session(api.AuthorizeRecovery), s.userLimited())
	m.POST(prefix+"/recover/request", s.requestRecoveryHandler, s.logged(api.RequestRecovery), s.session(api.RequestRecovery), s.userLimited())
	m.POST(prefix+"/recover/cancel", s.cancelRecoveryHandler, s.logged(api.CancelRecovery), s.session(api.CancelRecovery))
	m.POST(prefix+"/recover/claim", s.claimRecoveryHandler, s.logged(api.ClaimRecovery), s.session(api.ClaimRecovery), s.userLimited())
	m.POST(prefix+"/recover/grant", s.grantRecoveryHandler, s.logged(api.GrantRecovery), s.session(api.GrantRecovery))
	m.GET(prefix+"/passkeys", s.retrievePasskeysHandler, s.logged(api.RetrievePasskeys), s.session(api.RetrievePasskeys))
	m.GET(prefix+"/sessions", s.listSessionsHandler, s.logged(api.ListSessions), s.session(api.ListSessions))
	m.DELETE(prefix+"/sessions/{session_xid}", s.removeSessionHandler, s.logged(api.RemoveSession), s.session(api.RemoveSession))
	m.POST(prefix+"/user/deletion", s.beginDeleteUserHandler, s.logged(api.BeginDeleteUser), s.session(api.BeginDeleteUser))
	m.POST(prefix+"/user/deletion/confirm", s.deleteUserHandler, s.logged(api.DeleteUser), s.session(api.DeleteUser))
	m.POST(prefix+"/accounts", s.addAuthenticatorHandler, s.logged(api.AddAccount), s.session(api.AddAccount))
	m.GET(prefix+"/accounts", s.listAuthenticatorsHandler, s.logged(api.ListAccounts), s.session(api.ListAccounts))
	m.DELETE(prefix+"/accounts/{account_xid}", s.removeAuthenticatorHandler, s.logged(api.RemoveAccount), s.session(api.RemoveAccount))
	m.GET(prefix+"/user/export", s.exportUserHandler, s.logged(api.ExportUser), s.session(api.ExportUser))
	m.POST(prefix+"/passkeys/{passkey_xid}/removal", s.beginRemovePasskeyHandler, s.logged(api.BeginRemovePasskey), s.session(api.BeginRemovePasskey))
	m.POST(prefix+"/passkeys/{passkey_xid}/removal/confirm", s.removePasskeyHandler, s.logged(api.RemovePasskey), s.session(api.RemovePasskey))
	m.DELETE(prefix+"/totp", s.removeTOTPHandler, s.logged(api.RemoveTOTP), s.session(api.RemoveTOTP))
	return m
}

// userLimited returns the middleware that limits the request rate for each account. It takes the user from the
// email in the request body.
func (s *Server) userLimited() web.Middleware {
	return s.rateLimit.UserMiddleware()
}

// logged returns the metrics middleware and the request log middleware for the endpoint with the resource code.
func (s *Server) logged(code es.ResourceCode) web.Middleware {
	return web.Chain(s.observe.Middleware(code), s.requestLogMiddleware.Middleware(code))
}

// session returns the session middleware for the endpoint with the resource code.
func (s *Server) session(code es.ResourceCode) web.Middleware {
	return s.sessionMiddleware.Middleware(code)
}

// Startup runs the HTTP server and the Vault lease until one of them stops or ctx ends.
//
// It returns the error of the one that failed, wrapped with its name. It returns the error of ctx when ctx ends.
func (s *Server) Startup(ctx context.Context) error {
	// The metrics port opens first, so a failure to listen returns before anything else runs.
	var metricsListener net.Listener
	if s.metricsAddr != "" {
		var err error

		metricsListener, err = net.Listen("tcp", s.metricsAddr)
		if err != nil {
			return fmt.Errorf("listen for the metrics: %w", err)
		}
	}

	leaseCh := make(chan error, 1)
	httpCh := make(chan error, 1)
	go func() { leaseCh <- s.env.VaultLease.Run(ctx) }()
	go func() { httpCh <- s.http.ListenAndServe(s.addr) }()

	metricsCh := make(chan error, 1)
	if metricsListener != nil {
		go func() { metricsCh <- s.metricsServer.Serve(metricsListener) }()
	}

	go s.purgeSessions(ctx)
	go s.purgeRequestLog(ctx)

	select {
	case err := <-leaseCh:
		if err != nil {
			return fmt.Errorf("the vault lease: %w", err)
		}
	case err := <-metricsCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("the metrics server: %w", err)
		}
	case err := <-httpCh:
		if err != nil {
			return fmt.Errorf("the HTTP server: %w", err)
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

// Shutdown stops the HTTP server and closes the environment. Requests in progress may finish until ctx ends.
func (s *Server) Shutdown(ctx context.Context) error {
	var metricsErr error
	if s.metricsServer != nil {
		metricsErr = s.metricsServer.Shutdown(ctx)
	}

	return errors.Join(s.http.ShutdownWithContext(ctx), metricsErr, s.env.Close())
}

// purgeSessions deletes the sessions that expired longer ago than the retention time, once an hour, until ctx ends. The
// expired sessions stay for a while because the risk engine reads them as login history. A failure is logged and the
// next round tries again.
func (s *Server) purgeSessions(ctx context.Context) {
	retention := s.sessionRetention
	if retention == 0 {
		retention = DefaultSessionRetention
	}

	everyHour(ctx, func() {
		purged, err := s.env.SessionWriter.WriteOne(ctx, es.Session{
			ExpiresAt: s.env.SystemClock.Now().Add(-retention),
		}, es.PurgeExpiredSessions)
		s.metrics.Session(metrics.SessionExpiredPurged, purged.ID)

		if err != nil && ctx.Err() == nil {
			s.logger.Error("purge the expired sessions", slog.String("error", err.Error()))
		}
	})
}

// purgeRequestLog deletes the rows of the request log that are older than the retention time, once an hour, until ctx
// ends. The rows hold the address and the user agent of each request, so they must not stay for ever. A failure is
// logged and the next round tries again.
func (s *Server) purgeRequestLog(ctx context.Context) {
	retention := s.requestLogRetention
	if retention == 0 {
		retention = DefaultRequestLogRetention
	}

	everyHour(ctx, func() {
		_, err := s.env.HTTPRequestWriter.WriteOne(ctx, es.HTTPRequest{
			CreatedAt: s.env.SystemClock.Now().Add(-retention),
		}, es.PurgeHTTPRequests)
		if err != nil && ctx.Err() == nil {
			s.logger.Error("purge the request log", slog.String("error", err.Error()))
		}
	})
}

// everyHour calls work once an hour, starting an hour from now, until ctx ends.
func everyHour(ctx context.Context, work func()) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			work()
		}
	}
}
