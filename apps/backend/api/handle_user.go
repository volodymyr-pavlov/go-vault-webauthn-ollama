package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/auth"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &BeginDeleteUserHandler{}
var _ web.Handler = &DeleteUserHandler{}
var _ web.Handler = &ExportUserHandler{}

var deleteUserHandlerBodyArgsPool web.Pool[DeleteUserHandlerBodyArgs]

// Methods that BeginDeleteUserHandler offers.
const (
	// DeleteMethodPasskey means the user must confirm the deletion with a passkey assertion.
	DeleteMethodPasskey = "passkey"

	// DeleteMethodFreshLogin means the user has no passkey, so the fresh login that the permission checks is the
	// confirmation.
	DeleteMethodFreshLogin = "fresh_login"
)

// BeginDeleteUserHandlerResult is the response of POST /user/deletion. Method says how to confirm. Options holds
// the request options for the browser when Method is [DeleteMethodPasskey], and it is empty otherwise.
type BeginDeleteUserHandlerResult struct {
	Method  string          `json:"method"`
	Options json.RawMessage `json:"options,omitempty"`
}

// BeginDeleteUserHandler handles POST /user/deletion. It starts the deletion of the user of the session, which
// needs a fresh login. If the user has a passkey, the response holds request options whose challenge is bound to the
// deletion and to the user, and the session keeps the state of the ceremony. If it has none, the response says that the
// fresh login is the confirmation.
type BeginDeleteUserHandler struct {
	PasskeyBatchReader es.BatchReader[es.Passkey]
	RelyingParty       *auth.RelyingParty
	SystemClock        clock.Clock
	SessionGroupWriter es.Writer[es.SessionGroup]

	// ChallengeTTL is how long the challenge stays valid. Zero means [DefaultChallengeTTL].
	ChallengeTTL time.Duration
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrSessionWithoutUser] if the session is bound to no user.
func (h *BeginDeleteUserHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	user, err := User(ctx)
	if err != nil {
		return ErrSessionWithoutUser
	}

	session, err := Session(ctx)
	if err != nil {
		return err
	}

	passkeys, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
		UserID: user.ID,
	}, es.DefaultPaginator, 0)
	if err != nil {
		return fmt.Errorf("read the passkeys: %w", err)
	}

	usable := false
	for _, passkey := range passkeys {
		if passkey.Usable() {
			usable = true
		}
	}

	if !usable {
		return web.Write(ctx, fasthttp.StatusOK, BeginDeleteUserHandlerResult{
			Method: DeleteMethodFreshLogin,
		})
	}

	options, state, err := h.RelyingParty.BeginConfirmation(user, passkeys, auth.ConfirmationActionDeleteUser, user.UserXID)
	if err != nil {
		return fmt.Errorf("begin the confirmation: %w", err)
	}

	ttl := h.ChallengeTTL
	if ttl == 0 {
		ttl = DefaultChallengeTTL
	}

	_, err = h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID:                 session.ID,
			Flags:              es.SessionFlagChallengeLogin | es.SessionFlagChallengeConfirmation,
			Challenge:          state,
			ChallengeExpiresAt: h.SystemClock.Now().Add(ttl),
		},
	}, es.OpenConfirmation)
	if err != nil {
		return fmt.Errorf("keep the challenge: %w", err)
	}

	return web.Write(ctx, fasthttp.StatusOK, BeginDeleteUserHandlerResult{
		Method:  DeleteMethodPasskey,
		Options: json.RawMessage(options),
	})
}

// DeleteUserHandlerBodyArgs are the arguments of POST /user/deletion/confirm. Response is the passkey assertion.
// A user without a passkey sends none.
type DeleteUserHandlerBodyArgs struct {
	Response json.RawMessage `json:"response"`
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *DeleteUserHandlerBodyArgs) DecodeJSON(value gjson.Result) error {
	return web.VisitObject(value, func(key string, member gjson.Result) error {
		var err error
		switch key {
		case "response":
			a.Response = web.JSONRaw(member)
		default:
			err = web.ErrUnknownBody
		}
		return err
	})
}

// DeleteUserHandler handles POST /user/deletion/confirm. It deletes the user of the session with its passkeys,
// recovery codes, recovery requests and sessions, and removes the identity from the rows of the request log of the
// user. If the user has a passkey, the request must carry an assertion for the challenge that
// [BeginDeleteUserHandler] bound to this deletion. A user without a passkey needs only the fresh login.
//
// The writer locks the user row and runs all the deletes in one transaction. The challenge is used up whether the
// assertion verifies or not.
type DeleteUserHandler struct {
	PasskeyBatchReader     es.BatchReader[es.Passkey]
	RelyingParty           *auth.RelyingParty
	SystemClock            clock.Clock
	UserGroupWriter        es.Writer[es.UserGroup]
	SessionGroupWriter     es.Writer[es.SessionGroup]
	MessageWriter          es.Writer[es.Message]
	AccountBatchReader     es.BatchReader[es.Account]
	AuthenticatorKeyWriter es.Writer[es.AuthenticatorKey]
}

// ServeHTTP implements [web.Handler]. It responds with status 204.
//
// It returns [ErrSessionWithoutUser] if the session is bound to no user. It returns [ErrAuthenticationFailed] if the user
// has a passkey and the session holds no confirmation challenge, the challenge expired or was bound to another action
// or user, or the assertion does not verify.
func (h *DeleteUserHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := deleteUserHandlerBodyArgsPool.Get()
	defer deleteUserHandlerBodyArgsPool.Put(bodyArgs)

	if err := web.Unmarshal(ctx, bodyArgs); err != nil {
		return err
	}

	user, err := User(ctx)
	if err != nil {
		return ErrSessionWithoutUser
	}

	session, err := Session(ctx)
	if err != nil {
		return err
	}

	passkeys, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
		UserID: user.ID,
	}, es.DefaultPaginator, 0)
	if err != nil {
		return fmt.Errorf("read the passkeys: %w", err)
	}

	usable := false
	for _, passkey := range passkeys {
		if passkey.Usable() {
			usable = true
		}
	}

	if usable {
		now := h.SystemClock.Now()
		confirming := session.Flags&es.SessionFlagChallengeConfirmation != 0
		if len(session.Challenge) == 0 || !confirming || !now.Before(session.ChallengeExpiresAt) || len(bodyArgs.Response) == 0 {
			return h.refuse(ctx, session)
		}

		_, regressed, err := h.RelyingParty.FinishConfirmation(user, passkeys, session.Challenge, auth.ConfirmationActionDeleteUser, user.UserXID, bodyArgs.Response)
		if errors.Is(err, auth.ErrVerify) || regressed {
			return h.refuse(ctx, session)
		} else if err != nil {
			return fmt.Errorf("finish the confirmation: %w", err)
		}
	}

	// The secrets of the authenticator live in Vault, outside the transaction, so they go first. A repeat of the request
	// finds the keys gone and deletes nothing twice.
	accounts, err := h.AccountBatchReader.ReadAll(ctx, es.Account{
		UserID: user.ID,
	}, es.PageNumberPagination{
		PageSize: es.MaxAccounts,
	}, 0)
	if err != nil {
		return fmt.Errorf("read the accounts: %w", err)
	}

	for _, account := range accounts {
		_, err := h.AuthenticatorKeyWriter.WriteOne(ctx, es.AuthenticatorKey{
			Name: account.VaultKey,
		}, es.DeleteAuthenticatorKey)
		if err != nil {
			return fmt.Errorf("delete a secret from Vault: %w", err)
		}
	}

	_, err = h.UserGroupWriter.WriteOne(ctx, es.UserGroup{
		User: es.User{
			ID: user.ID,
		},
	}, es.DeleteUser)
	if errors.Is(err, es.ErrNotFound) {
		// A parallel request with the same assertion deleted the user first.
		return ErrAuthenticationFailed
	} else if err != nil {
		return fmt.Errorf("delete the user: %w", err)
	}

	SetEvent(ctx, es.EventUserDeleted)

	_, err = h.MessageWriter.WriteOne(ctx, es.Message{
		Email: user.Email,
	}, es.WriteCreate|es.SendUserDeleted)
	if err != nil {
		return fmt.Errorf("send the notice: %w", err)
	}

	ctx.SetStatusCode(fasthttp.StatusNoContent)
	return nil
}

// refuse uses up the confirmation challenge of the session, counts the failure and returns [ErrAuthenticationFailed].
func (h *DeleteUserHandler) refuse(ctx *fasthttp.RequestCtx, session es.Session) error {
	_, err := h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID:       session.ID,
			Failures: session.Failures + 1,
		},
	}, es.RefuseLogin|es.ConsumeChallenge)
	if err != nil && !errors.Is(err, es.ErrNoUpdatedRows) {
		return fmt.Errorf("record the refusal: %w", err)
	}

	SetEvent(ctx, es.EventUserDeletionRefused)

	return ErrAuthenticationFailed
}

// ExportPasskey is a passkey in the export of a user.
type ExportPasskey struct {
	PasskeyXID uint64    `json:"passkey_xid,string"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
}

// ExportSession is a session in the export of a user.
type ExportSession struct {
	SessionXID uint64    `json:"session_xid,string"`
	IP         string    `json:"ip,omitempty"`
	Country    string    `json:"country,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// ExportRequest is a row of the request log in the export of a user.
type ExportRequest struct {
	At         time.Time `json:"at"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Status     uint16    `json:"status"`
	Event      string    `json:"event,omitempty"`
	EventAttrs string    `json:"event_attrs,omitempty"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
}

// ExportUserHandlerResult is the response of GET /user/export. It holds the personal data that the service keeps
// about the user. It holds no secret: the password hash, the TOTP secret, the recovery codes and the public keys of
// the passkeys stay out.
type ExportUserHandlerResult struct {
	UserXID   uint64          `json:"user_xid,string"`
	Email     string          `json:"email"`
	CreatedAt time.Time       `json:"created_at"`
	HasTOTP   bool            `json:"has_totp"`
	Passkeys  []ExportPasskey `json:"passkeys"`
	Sessions  []ExportSession `json:"sessions"`

	// Accounts lists the accounts of the authenticator by issuer and label. It holds no secret and no code.
	Accounts []AccountView   `json:"accounts"`
	Requests []ExportRequest `json:"requests"`
}

// ExportUserHandler handles GET /user/export. It returns the personal data that the service keeps about the
// user of the session: the email, the names of the passkeys, the sessions with their address, and the newest rows of
// the request log of the user. It needs a fresh login.
type ExportUserHandler struct {
	PasskeyBatchReader     es.BatchReader[es.Passkey]
	SessionBatchReader     es.BatchReader[es.Session]
	HTTPRequestBatchReader es.BatchReader[es.HTTPRequest]
	AccountBatchReader     es.BatchReader[es.Account]
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrSessionWithoutUser] if the session is bound to no user.
func (h *ExportUserHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	user, err := User(ctx)
	if err != nil {
		return ErrSessionWithoutUser
	}

	passkeys, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
		UserID: user.ID,
	}, es.DefaultPaginator, 0)
	if err != nil {
		return fmt.Errorf("read the passkeys: %w", err)
	}

	sessions, err := h.SessionBatchReader.ReadAll(ctx, es.Session{
		UserID: user.ID,
	}, es.PageNumberPagination{
		PageSize: 100,
	}, 0)
	if err != nil {
		return fmt.Errorf("read the sessions: %w", err)
	}

	accounts, err := h.AccountBatchReader.ReadAll(ctx, es.Account{
		UserID: user.ID,
	}, es.PageNumberPagination{
		PageSize: es.MaxAccounts,
	}, 0)
	if err != nil {
		return fmt.Errorf("read the accounts: %w", err)
	}

	requests, err := h.HTTPRequestBatchReader.ReadAll(ctx, es.HTTPRequest{
		UserXID: user.UserXID,
	}, es.PageNumberPagination{
		PageSize: 1000,
	}, 0)
	if err != nil {
		return fmt.Errorf("read the request log: %w", err)
	}

	result := ExportUserHandlerResult{
		UserXID:   user.UserXID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt.UTC(),
		HasTOTP:   user.HasTOTP(),
		Passkeys:  []ExportPasskey{},
		Sessions:  []ExportSession{},
		Requests:  []ExportRequest{},

		Accounts: []AccountView{},
	}

	for _, account := range accounts {
		result.Accounts = append(result.Accounts, accountView(account))
	}

	for _, passkey := range passkeys {
		if !passkey.Present() {
			continue
		}

		result.Passkeys = append(result.Passkeys, ExportPasskey{
			PasskeyXID: passkey.PasskeyXID,
			Name:       passkey.Name,
			CreatedAt:  passkey.CreatedAt.UTC(),
		})
	}

	for _, session := range sessions {
		result.Sessions = append(result.Sessions, ExportSession{
			SessionXID: session.SessionXID,
			IP:         exportAddress(session.IP),
			Country:    session.Country,
			CreatedAt:  session.CreatedAt.UTC(),
			LastSeenAt: session.LastSeenAt.UTC(),
		})
	}

	for _, request := range requests {
		result.Requests = append(result.Requests, ExportRequest{
			At:         request.CreatedAt.UTC(),
			Method:     request.Method,
			Path:       request.Path,
			Status:     request.StatusCode,
			Event:      string(request.Event),
			EventAttrs: request.EventAttrs,
			IP:         exportAddress(request.IP),
			UserAgent:  request.UserAgent,
		})
	}

	SetEvent(ctx, es.EventUserExported, slog.Int("requests", len(result.Requests)))

	return web.Write(ctx, fasthttp.StatusOK, result)
}
