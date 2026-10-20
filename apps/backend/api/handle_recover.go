package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/metrics"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/snowid"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/validate"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &RequestRecoveryHandler{}
var _ web.Handler = &CancelRecoveryHandler{}
var _ web.Handler = &ClaimRecoveryHandler{}
var _ web.Handler = &GrantRecoveryHandler{}

var emailBodyArgsPool web.Pool[EmailBodyArgs]
var tokenBodyArgsPool web.Pool[TokenBodyArgs]

const (
	// DefaultRecoveryDelay is how long a recovery request waits before an operator can approve it. During this time the
	// owner of the user can cancel the request.
	DefaultRecoveryDelay = 72 * time.Hour

	// RecoveryGrantTTL is how long the grant token of an approved recovery works.
	RecoveryGrantTTL = time.Hour
)

// EmailBodyArgs are the arguments of the endpoints that take only an email: POST /recover/request and POST
// /recover/claim.
type EmailBodyArgs struct {
	Email string `json:"email"`
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *EmailBodyArgs) DecodeJSON(value gjson.Result) error {
	return web.VisitObject(value, func(key string, member gjson.Result) error {
		var err error
		switch key {
		case "email":
			a.Email, err = web.JSONString(member)
		default:
			err = web.ErrUnknownBody
		}
		return err
	})
}

// Validate checks the arguments and converts the email to lower case.
//
// It returns [ErrNoBodyEmail] or [ErrMalformedBodyEmail] for a bad email.
func (a *EmailBodyArgs) Validate() error {
	a.Email = strings.ToLower(strings.TrimSpace(a.Email))

	if (validate.Validate{Input: a.Email}).IsEmpty() {
		return ErrNoBodyEmail
	}

	if !validate.IsEmail(a.Email) {
		return ErrMalformedBodyEmail
	}

	return nil
}

// TokenBodyArgs are the arguments of the endpoints that take only a token: POST /recover/cancel and POST
// /recover/grant.
type TokenBodyArgs struct {
	Token string `json:"token"`

	token []byte
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *TokenBodyArgs) DecodeJSON(value gjson.Result) error {
	return web.VisitObject(value, func(key string, member gjson.Result) error {
		var err error
		switch key {
		case "token":
			a.Token, err = web.JSONString(member)
		default:
			err = web.ErrUnknownBody
		}
		return err
	})
}

// Validate checks the arguments and decodes the token.
//
// It returns [ErrNoBodyToken] if the token is empty and [ErrMalformedBodyToken] if it is not 64 hexadecimal digits.
func (a *TokenBodyArgs) Validate() error {
	a.Token = strings.TrimSpace(a.Token)

	if (validate.Validate{Input: a.Token}).IsEmpty() {
		return ErrNoBodyToken
	}

	token, ok := validate.HexToken(a.Token)
	if !ok {
		return ErrMalformedBodyToken
	}

	a.token = token

	return nil
}

// RecoveryStatusResult is the response of the recovery endpoints that do not reveal whether the user exists. It
// depends only on the session, so it is the same for a known and an unknown address.
type RecoveryStatusResult struct {
	// Flags are the flag bits of the session, which these endpoints leave as they are.
	Flags es.SessionFlag `json:"flags"`
}

// RequestRecoveryHandler handles POST /recover/request. It starts the recovery of a user whose owner lost every
// factor and every recovery code. An email alone never grants access, so the request only starts a delay. The handler
// tells the owner by email and gives a cancel token.
//
// An unknown email, a user that cannot authenticate and a user with a request that is open already get the
// same response as a new request. The response does not show which case it is.
type RequestRecoveryHandler struct {
	UserReader               es.Reader[es.User]
	RecoveryRequestReader    es.Reader[es.RecoveryRequest]
	RecoveryRequestSnowflake *snowid.Snowflake
	MessageWriter            es.Writer[es.Message]
	SystemClock              clock.Clock

	// RecoveryGroupWriter stores the request in one transaction.
	RecoveryGroupWriter es.Writer[es.RecoveryGroup]

	// Metrics counts the recovery events after the commit. It may be nil.
	Metrics *metrics.Metrics

	// Delay is how long the request waits for the approval. Zero means [DefaultRecoveryDelay].
	Delay time.Duration
}

// ServeHTTP implements [web.Handler]. It responds with status 202.
func (h *RequestRecoveryHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := emailBodyArgsPool.Get()
	defer emailBodyArgsPool.Put(bodyArgs)

	if err := web.Unmarshal(ctx, bodyArgs); err != nil {
		return err
	}

	if err := bodyArgs.Validate(); err != nil {
		return err
	}

	session, err := Session(ctx)
	if err != nil {
		return err
	}

	user, err := h.UserReader.ReadOne(ctx, es.User{
		Email: bodyArgs.Email,
	}, 0)
	if err != nil && !errors.Is(err, es.ErrNotFound) {
		return fmt.Errorf("read the user: %w", err)
	}

	if !user.CanAuthenticate() {
		return web.Write(ctx, fasthttp.StatusAccepted, RecoveryStatusResult{
			Flags: session.Flags,
		})
	}

	_, err = h.RecoveryRequestReader.ReadOne(ctx, es.RecoveryRequest{
		UserID: user.ID,
	}, 0)
	if err == nil {
		return web.Write(ctx, fasthttp.StatusAccepted, RecoveryStatusResult{
			Flags: session.Flags,
		})
	} else if !errors.Is(err, es.ErrNotFound) {
		return fmt.Errorf("read the recovery request: %w", err)
	}

	token := make([]byte, 32)

	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("make the cancel token: %w", err)
	}

	cancelHash := sha256.Sum256(token)

	delay := h.Delay
	if delay == 0 {
		delay = DefaultRecoveryDelay
	}

	_, err = h.RecoveryGroupWriter.WriteOne(ctx, es.RecoveryGroup{
		Request: es.RecoveryRequest{
			RecoveryRequestXID: h.RecoveryRequestSnowflake.Next(),
			UserID:             user.ID,
			CancelHash:         cancelHash[:],
			ReadyAt:            h.SystemClock.Now().Add(delay),
		},
	}, es.OpenRecoveryRequest)
	if err != nil {
		return fmt.Errorf("create the recovery request: %w", err)
	}

	SetEvent(ctx, es.EventRecoveryRequested)

	h.Metrics.Recovery(metrics.RecoveryRequested)

	_, err = h.MessageWriter.WriteOne(ctx, es.Message{
		Email: user.Email,
		Token: hex.EncodeToString(token),
		TTL:   delay,
	}, es.WriteCreate|es.SendRecoveryRequested)
	if err != nil {
		return fmt.Errorf("send the notice: %w", err)
	}

	return web.Write(ctx, fasthttp.StatusAccepted, RecoveryStatusResult{
		Flags: session.Flags,
	})
}

// CancelRecoveryHandler handles POST /recover/cancel. The cancel token from the notice closes the open request. The
// token works once.
type CancelRecoveryHandler struct {
	// RecoveryGroupWriter cancels the request in one transaction.
	RecoveryGroupWriter es.Writer[es.RecoveryGroup]

	// Metrics counts the recovery events after the commit. It may be nil.
	Metrics *metrics.Metrics
}

// ServeHTTP implements [web.Handler]. It responds with status 204.
//
// It returns [ErrAuthenticationFailed] if no open request has the token.
func (h *CancelRecoveryHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := tokenBodyArgsPool.Get()
	defer tokenBodyArgsPool.Put(bodyArgs)

	if err := web.Unmarshal(ctx, bodyArgs); err != nil {
		return err
	}

	if err := bodyArgs.Validate(); err != nil {
		return err
	}

	cancelHash := sha256.Sum256(bodyArgs.token)

	_, err := h.RecoveryGroupWriter.WriteOne(ctx, es.RecoveryGroup{
		Request: es.RecoveryRequest{
			CancelHash: cancelHash[:],
			Flags:      es.RecoveryRequestFlagCancelled,
		},
	}, es.CancelRecoveryRequest)
	if errors.Is(err, es.ErrNoUpdatedRows) {
		return ErrAuthenticationFailed
	} else if err != nil {
		return fmt.Errorf("cancel the recovery request: %w", err)
	}

	SetEvent(ctx, es.EventRecoveryCancelled)

	h.Metrics.Recovery(metrics.RecoveryCancelled)

	ctx.SetStatusCode(fasthttp.StatusNoContent)

	return nil
}

// ClaimRecoveryHandler handles POST /recover/claim. After an operator approves the request, the owner claims it. The
// handler makes a grant token and sends it by email.
//
// An unknown email and a request that is not approved get the same response as an approved one.
type ClaimRecoveryHandler struct {
	UserReader            es.Reader[es.User]
	RecoveryRequestReader es.Reader[es.RecoveryRequest]
	MessageWriter         es.Writer[es.Message]
	SystemClock           clock.Clock

	// RecoveryGroupWriter stores the grant in one transaction.
	RecoveryGroupWriter es.Writer[es.RecoveryGroup]

	// Metrics counts the recovery events after the commit. It may be nil.
	Metrics *metrics.Metrics
}

// ServeHTTP implements [web.Handler]. It responds with status 202.
func (h *ClaimRecoveryHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := emailBodyArgsPool.Get()
	defer emailBodyArgsPool.Put(bodyArgs)

	if err := web.Unmarshal(ctx, bodyArgs); err != nil {
		return err
	}

	if err := bodyArgs.Validate(); err != nil {
		return err
	}

	session, err := Session(ctx)
	if err != nil {
		return err
	}

	user, err := h.UserReader.ReadOne(ctx, es.User{
		Email: bodyArgs.Email,
	}, 0)
	if err != nil && !errors.Is(err, es.ErrNotFound) {
		return fmt.Errorf("read the user: %w", err)
	}

	if !user.CanAuthenticate() {
		return web.Write(ctx, fasthttp.StatusAccepted, RecoveryStatusResult{
			Flags: session.Flags,
		})
	}

	request, err := h.RecoveryRequestReader.ReadOne(ctx, es.RecoveryRequest{
		UserID: user.ID,
	}, 0)
	if errors.Is(err, es.ErrNotFound) || (err == nil && request.Flags&es.RecoveryRequestFlagApproved == 0) {
		return web.Write(ctx, fasthttp.StatusAccepted, RecoveryStatusResult{
			Flags: session.Flags,
		})
	} else if err != nil {
		return fmt.Errorf("read the recovery request: %w", err)
	}

	token := make([]byte, 32)

	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("make the grant token: %w", err)
	}

	grantHash := sha256.Sum256(token)

	_, err = h.RecoveryGroupWriter.WriteOne(ctx, es.RecoveryGroup{
		Request: es.RecoveryRequest{
			ID:             request.ID,
			GrantHash:      grantHash[:],
			GrantExpiresAt: h.SystemClock.Now().Add(RecoveryGrantTTL),
		},
	}, es.IssueRecoveryGrant)
	if err != nil {
		return fmt.Errorf("issue the grant: %w", err)
	}

	SetEvent(ctx, es.EventRecoveryClaimed)

	h.Metrics.Recovery(metrics.RecoveryClaimed)

	_, err = h.MessageWriter.WriteOne(ctx, es.Message{
		Email: user.Email,
		Token: hex.EncodeToString(token),
		TTL:   RecoveryGrantTTL,
	}, es.WriteCreate|es.SendRecoveryGrant)
	if err != nil {
		return fmt.Errorf("send the grant: %w", err)
	}

	return web.Write(ctx, fasthttp.StatusAccepted, RecoveryStatusResult{
		Flags: session.Flags,
	})
}

// GrantRecoveryHandler handles POST /recover/grant. An unused grant token binds the session to the user and revokes
// every other session of the user. The session may then enroll a factor and do nothing else, as after a recovery
// code. The handler uses the grant up, writes a security event and notifies the user.
type GrantRecoveryHandler struct {
	RecoveryRequestReader es.Reader[es.RecoveryRequest]
	UserReader            es.Reader[es.User]
	MessageWriter         es.Writer[es.Message]

	// RecoveryGroupWriter uses the grant up, revokes the other sessions of the user and binds the session in one
	// transaction.
	RecoveryGroupWriter es.Writer[es.RecoveryGroup]

	// SessionGroupWriter writes the outcome of the attempt in one transaction: the binding of the session, or the failure
	// counters of a refusal.
	SessionGroupWriter es.Writer[es.SessionGroup]

	// Metrics counts the recovery events after the commit. It may be nil.
	Metrics *metrics.Metrics
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrAuthenticationFailed] if the grant is wrong, used or expired. Each refusal adds one to the failure
// count of the session.
func (h *GrantRecoveryHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := tokenBodyArgsPool.Get()
	defer tokenBodyArgsPool.Put(bodyArgs)

	if err := web.Unmarshal(ctx, bodyArgs); err != nil {
		return err
	}

	if err := bodyArgs.Validate(); err != nil {
		return err
	}

	session, err := Session(ctx)
	if err != nil {
		return err
	}

	grantHash := sha256.Sum256(bodyArgs.token)

	request, err := h.RecoveryRequestReader.ReadOne(ctx, es.RecoveryRequest{
		GrantHash: grantHash[:],
	}, 0)
	if errors.Is(err, es.ErrNotFound) {
		return h.refuse(ctx, session)
	} else if err != nil {
		return fmt.Errorf("read the recovery request: %w", err)
	}

	user, err := h.UserReader.ReadOne(ctx, es.User{
		ID: request.UserID,
	}, 0)
	if err != nil {
		return fmt.Errorf("read the user: %w", err)
	}

	// The write revokes the other sessions of the user before it binds this one, and it uses the grant up last. The
	// current session has no user yet, so it is not among the sessions that the write revokes.
	_, err = h.RecoveryGroupWriter.WriteOne(ctx, es.RecoveryGroup{
		Request: es.RecoveryRequest{
			GrantHash: grantHash[:],
		},
		Session: es.Session{
			ID:     session.ID,
			UserID: user.ID,
			Flags:  es.SessionFlagRecoveryApproved,
		},
	}, es.RedeemRecoveryGrant)
	if errors.Is(err, es.ErrNoUpdatedRows) {
		return h.refuse(ctx, session)
	} else if err != nil {
		return fmt.Errorf("redeem the grant: %w", err)
	}

	SetEvent(ctx, es.EventRecoveryGranted)

	h.Metrics.Recovery(metrics.RecoveryGranted)

	SetUser(ctx, user)

	_, err = h.MessageWriter.WriteOne(ctx, es.Message{
		Email: user.Email,
	}, es.WriteCreate|es.SendRecoveryUsed)
	if err != nil {
		return fmt.Errorf("send the notice: %w", err)
	}

	return web.Write(ctx, fasthttp.StatusOK, AuthorizeRecoveryHandlerResult{
		Flags: session.Flags | es.SessionFlagRecoveryApproved,
	})
}

// refuse counts the failure on the session in one transaction and returns [ErrAuthenticationFailed].
func (h *GrantRecoveryHandler) refuse(ctx *fasthttp.RequestCtx, session es.Session) error {
	_, err := h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID:       session.ID,
			Failures: session.Failures + 1,
		},
	}, es.RefuseLogin)
	if err != nil {
		return fmt.Errorf("record the refusal: %w", err)
	}

	SetEvent(ctx, es.EventRecoveryRefused)

	return ErrAuthenticationFailed
}
