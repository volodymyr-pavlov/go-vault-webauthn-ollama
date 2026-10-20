package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/auth"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/snowid"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/validate"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &BeginEnrollPasskeyHandler{}
var _ web.Handler = &CompleteEnrollPasskeyHandler{}
var _ web.Handler = &RetrievePasskeysHandler{}
var _ web.Handler = &RemovePasskeyHandler{}

var completeEnrollPasskeyHandlerBodyArgsPool web.Pool[CompleteEnrollPasskeyHandlerBodyArgs]

const (
	// DefaultChallengeTTL is the default time a WebAuthn challenge stays valid.
	DefaultChallengeTTL = 2 * time.Minute
)

// BeginEnrollPasskeyHandler handles POST /enroll/passkey. It starts the passkey registration for the account of the
// session and keeps the challenge on the session. The response holds the creation options for the browser.
type BeginEnrollPasskeyHandler struct {
	PasskeyBatchReader es.BatchReader[es.Passkey]
	SessionGroupWriter es.Writer[es.SessionGroup]
	RelyingParty       *auth.RelyingParty
	SystemClock        clock.Clock

	// ChallengeTTL is how long the challenge stays valid. Zero means [DefaultChallengeTTL].
	ChallengeTTL time.Duration
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrNoAccount] if the session is bound to no account.
func (h *BeginEnrollPasskeyHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	session, err := Session(ctx)
	if err != nil {
		return err
	}

	user, err := User(ctx)
	if err != nil {
		return ErrNoAccount
	}

	passkeys, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
		UserID: user.ID,
	}, es.DefaultPaginator, 0)
	if err != nil {
		return fmt.Errorf("read the passkeys: %w", err)
	}

	options, state, err := h.RelyingParty.BeginRegistration(user, passkeys)
	if err != nil {
		return fmt.Errorf("begin the registration: %w", err)
	}

	ttl := h.ChallengeTTL
	if ttl == 0 {
		ttl = DefaultChallengeTTL
	}

	_, err = h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID:                 session.ID,
			Flags:              es.SessionFlagChallengeRegistration,
			Challenge:          state,
			ChallengeExpiresAt: h.SystemClock.Now().Add(ttl),
		},
	}, es.OpenPasskeyEnrollment)
	if err != nil {
		return fmt.Errorf("keep the challenge: %w", err)
	}

	return web.Write(ctx, fasthttp.StatusOK, json.RawMessage(options))
}

// CompleteEnrollPasskeyHandlerBodyArgs are the arguments of POST /enroll/passkey/complete. Name is the label the user
// gives the passkey. Response is the response of the authenticator.
type CompleteEnrollPasskeyHandlerBodyArgs struct {
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response"`
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *CompleteEnrollPasskeyHandlerBodyArgs) DecodeJSON(value gjson.Result) error {
	return web.VisitObject(value, func(key string, member gjson.Result) error {
		var err error
		switch key {
		case "name":
			a.Name, err = web.JSONString(member)
		case "response":
			a.Response = web.JSONRaw(member)
		default:
			err = web.ErrUnknownBody
		}
		return err
	})
}

// Validate checks the arguments.
//
// It returns [ErrNoBodyName] or [ErrMaxLenBodyName] if the name is empty or too long, and [ErrNoBodyResponse] if the
// response is empty.
func (a *CompleteEnrollPasskeyHandlerBodyArgs) Validate() error {
	a.Name = strings.TrimSpace(a.Name)

	name := validate.Validate{
		Input: a.Name,
		Max:   validate.MaxNameLength,
	}
	if name.IsEmpty() {
		return ErrNoBodyName
	}

	if name.TooLong() {
		return ErrMaxLenBodyName
	}

	if len(a.Response) == 0 {
		return ErrNoBodyResponse
	}

	return nil
}

// CompleteEnrollPasskeyHandlerResult is the response of POST /enroll/passkey/complete.
type CompleteEnrollPasskeyHandlerResult struct {
	PasskeyXID uint64 `json:"passkey_xid,string"`
}

// CompleteEnrollPasskeyHandler handles POST /enroll/passkey/complete. It verifies the response of the browser against
// the challenge on the session, stores the passkey and notifies the user.
//
// The challenge is used up whether the response verifies or not. Enrolling does not log the session in: the user logs
// in with the new passkey.
type CompleteEnrollPasskeyHandler struct {
	SessionGroupWriter es.Writer[es.SessionGroup]
	PasskeySnowflake   *snowid.Snowflake
	RelyingParty       *auth.RelyingParty
	MessageWriter      es.Writer[es.Message]
	SystemClock        clock.Clock
}

// ServeHTTP implements [web.Handler]. It responds with status 201.
//
// It returns [ErrNoAccount] if the session is bound to no account. It returns [ErrAuthenticationFailed] if the
// challenge is missing or expired, the response does not verify or the passkey exists already.
func (h *CompleteEnrollPasskeyHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := completeEnrollPasskeyHandlerBodyArgsPool.Get()
	defer completeEnrollPasskeyHandlerBodyArgsPool.Put(bodyArgs)

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

	user, err := User(ctx)
	if err != nil {
		return ErrNoAccount
	}

	if len(session.Challenge) == 0 || !h.SystemClock.Now().Before(session.ChallengeExpiresAt) {
		return ErrAuthenticationFailed
	}

	registered, err := h.RelyingParty.FinishRegistration(user, session.Challenge, bodyArgs.Response)
	if errors.Is(err, auth.ErrVerify) {
		// The challenge is used up whether the response verifies or not.
		_, refuseErr := h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
			Session: es.Session{
				ID: session.ID,
			},
		}, es.RefusePasskeyEnrollment)
		if refuseErr != nil && !errors.Is(refuseErr, es.ErrNoUpdatedRows) {
			return fmt.Errorf("record the refusal: %w", refuseErr)
		}

		SetEvent(ctx, es.EventPasskeyEnrollmentRefused)

		return ErrAuthenticationFailed.Wrap(err)
	} else if err != nil {
		return fmt.Errorf("finish the registration: %w", err)
	}

	registered.PasskeyXID = h.PasskeySnowflake.Next()
	registered.UserID = user.ID
	registered.Name = bodyArgs.Name

	// The writer uses up the challenge in the same transaction and finds none for a second response to it.
	enrolled, err := h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID: session.ID,
		},
		Passkey: registered,
	}, es.EnrollPasskey)
	if errors.Is(err, es.ErrNoUpdatedRows) || errors.Is(err, es.ErrDuplicate) {
		return ErrAuthenticationFailed
	} else if err != nil {
		return fmt.Errorf("store the passkey: %w", err)
	}

	SetEvent(ctx, es.EventPasskeyEnrolled, slog.Uint64("passkey_xid", enrolled.Passkey.PasskeyXID))

	_, err = h.MessageWriter.WriteOne(ctx, es.Message{
		Email: user.Email,
		Name:  bodyArgs.Name,
	}, es.WriteCreate|es.SendPasskeyAdded)
	if err != nil {
		return fmt.Errorf("send the notice: %w", err)
	}

	return web.Write(ctx, fasthttp.StatusCreated, CompleteEnrollPasskeyHandlerResult{
		PasskeyXID: enrolled.Passkey.PasskeyXID,
	})
}

// PasskeyView is one passkey as the API returns it, without key material.
type PasskeyView struct {
	PasskeyXID uint64    `json:"passkey_xid,string"`
	Name       string    `json:"name"`
	Transports []string  `json:"transports"`
	BackedUp   bool      `json:"backed_up"`
	Disabled   bool      `json:"disabled"`
	CreatedAt  time.Time `json:"created_at"`
}

// RetrievePasskeysHandlerResult is the response of GET /passkeys.
type RetrievePasskeysHandlerResult struct {
	Passkeys []PasskeyView `json:"passkeys"`
}

// RetrievePasskeysHandler handles GET /passkeys. It returns the passkeys of the account that are not removed.
type RetrievePasskeysHandler struct {
	PasskeyBatchReader es.BatchReader[es.Passkey]
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrNoAccount] if the session is bound to no account.
func (h *RetrievePasskeysHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	user, err := User(ctx)
	if err != nil {
		return ErrNoAccount
	}

	passkeys, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
		UserID: user.ID,
	}, es.DefaultPaginator, 0)
	if err != nil {
		return fmt.Errorf("read the passkeys: %w", err)
	}

	result := RetrievePasskeysHandlerResult{
		Passkeys: []PasskeyView{},
	}
	for _, p := range passkeys {
		if !p.Present() {
			continue
		}

		result.Passkeys = append(result.Passkeys, PasskeyView{
			PasskeyXID: p.PasskeyXID,
			Name:       p.Name,
			Transports: p.Transports.Names(),
			BackedUp:   p.Flags&es.PasskeyFlagBackedUp != 0,
			Disabled:   p.Flags&es.PasskeyFlagDisabled != 0,
			CreatedAt:  p.CreatedAt.UTC(),
		})
	}
	return web.Write(ctx, fasthttp.StatusOK, result)
}

var removePasskeyHandlerBodyArgsPool web.Pool[ResponseHandlerBodyArgs]

var _ web.Handler = &BeginRemovePasskeyHandler{}
var _ web.Handler = &RemovePasskeyHandler{}

// BeginRemovePasskeyHandler handles POST /passkeys/{passkey_xid}/removal. It starts the removal of a passkey, which
// needs a fresh passkey assertion. The response holds the request options for the browser. Their challenge is bound to
// the action and to the passkey, and the session keeps the state of the ceremony.
//
// The assertion may come from any usable passkey of the account, not only from the one that goes away.
type BeginRemovePasskeyHandler struct {
	PasskeyReader      es.Reader[es.Passkey]
	PasskeyBatchReader es.BatchReader[es.Passkey]
	RelyingParty       *auth.RelyingParty
	SystemClock        clock.Clock

	// SessionGroupWriter saves the challenge on the session in one transaction.
	SessionGroupWriter es.Writer[es.SessionGroup]

	// ChallengeTTL is how long the challenge stays valid. Zero means [DefaultChallengeTTL].
	ChallengeTTL time.Duration
}

// ServeHTTP implements [web.Handler]. It responds with the request options for the browser.
//
// It returns [ErrNoParamPasskeyXID] if the path has no passkey ID and [ErrNoAccount] if the session is bound to no
// account. It returns [ErrNotFoundPasskey] if the account has no such passkey.
func (h *BeginRemovePasskeyHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	passkeyXID := web.ParamUint[uint64](ctx, "passkey_xid")
	if passkeyXID == 0 {
		return ErrNoParamPasskeyXID
	}

	user, err := User(ctx)
	if err != nil {
		return ErrNoAccount
	}

	session, err := Session(ctx)
	if err != nil {
		return err
	}

	target, err := h.PasskeyReader.ReadOne(ctx, es.Passkey{
		PasskeyXID: passkeyXID,
	}, 0)
	if errors.Is(err, es.ErrNotFound) || (err == nil && (target.UserID != user.ID || !target.Present())) {
		return ErrNotFoundPasskey
	} else if err != nil {
		return fmt.Errorf("read the passkey: %w", err)
	}

	passkeys, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
		UserID: user.ID,
	}, es.DefaultPaginator, 0)
	if err != nil {
		return fmt.Errorf("read the passkeys: %w", err)
	}

	options, state, err := h.RelyingParty.BeginConfirmation(user, passkeys, auth.ConfirmationActionRemovePasskey, passkeyXID)
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

	return web.Write(ctx, fasthttp.StatusOK, json.RawMessage(options))
}

// RemovePasskeyHandler handles POST /passkeys/{passkey_xid}/removal/confirm. It checks the passkey assertion against
// the challenge that [BeginRemovePasskeyHandler] bound to the removal of this passkey, and then removes the passkey
// unless it is the last factor.
//
// The writer locks the user row while it counts the factors, uses up the challenge and marks the passkey in one
// transaction, so two removals cannot both pass and the challenge works once.
type RemovePasskeyHandler struct {
	UserReader         es.Reader[es.User]
	PasskeyReader      es.Reader[es.Passkey]
	PasskeyBatchReader es.BatchReader[es.Passkey]
	RelyingParty       *auth.RelyingParty
	SystemClock        clock.Clock
	AccountGroupWriter es.Writer[es.AccountGroup]
	SessionGroupWriter es.Writer[es.SessionGroup]
	MessageWriter      es.Writer[es.Message]
}

// ServeHTTP implements [web.Handler]. It responds with status 204.
//
// It returns [ErrNoParamPasskeyXID] if the path has no passkey ID and [ErrNoAccount] if the session is bound to no
// account. It returns [ErrNotFoundPasskey] if the account has no such passkey. It returns [ErrAuthenticationFailed] if
// the session holds no confirmation challenge, if the challenge expired or was bound to another action or passkey, or
// if the assertion does not verify. It returns [ErrLastFactor] if the passkey is the last factor.
func (h *RemovePasskeyHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := removePasskeyHandlerBodyArgsPool.Get()
	defer removePasskeyHandlerBodyArgsPool.Put(bodyArgs)

	if err := web.Unmarshal(ctx, bodyArgs); err != nil {
		return err
	}

	if err := bodyArgs.Validate(); err != nil {
		return err
	}

	passkeyXID := web.ParamUint[uint64](ctx, "passkey_xid")
	if passkeyXID == 0 {
		return ErrNoParamPasskeyXID
	}

	user, err := User(ctx)
	if err != nil {
		return ErrNoAccount
	}

	session, err := Session(ctx)
	if err != nil {
		return err
	}

	removed, err := h.PasskeyReader.ReadOne(ctx, es.Passkey{
		PasskeyXID: passkeyXID,
	}, 0)
	if errors.Is(err, es.ErrNotFound) || (err == nil && (removed.UserID != user.ID || !removed.Present())) {
		return ErrNotFoundPasskey
	} else if err != nil {
		return fmt.Errorf("read the passkey: %w", err)
	}

	now := h.SystemClock.Now()
	confirming := session.Flags&es.SessionFlagChallengeConfirmation != 0
	if len(session.Challenge) == 0 || !confirming || !now.Before(session.ChallengeExpiresAt) {
		return h.refuse(ctx, session)
	}

	passkeys, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
		UserID: user.ID,
	}, es.DefaultPaginator, 0)
	if err != nil {
		return fmt.Errorf("read the passkeys: %w", err)
	}

	_, regressed, err := h.RelyingParty.FinishConfirmation(user, passkeys, session.Challenge, auth.ConfirmationActionRemovePasskey, passkeyXID, bodyArgs.Response)
	if errors.Is(err, auth.ErrVerify) || regressed {
		return h.refuse(ctx, session)
	} else if err != nil {
		return fmt.Errorf("finish the confirmation: %w", err)
	}

	// The writer uses up the challenge in the same transaction and finds none for a second response to it.
	_, err = h.AccountGroupWriter.WriteOne(ctx, es.AccountGroup{
		User: es.User{
			ID: user.ID,
		},
		Passkey: es.Passkey{
			ID: removed.ID,
		},
		Session: es.Session{
			ID: session.ID,
		},
	}, es.RemovePasskey|es.ConsumeChallenge)
	switch {
	case errors.Is(err, es.ErrLastFactor):
		return ErrLastFactor
	case errors.Is(err, es.ErrNoUpdatedRows):
		return ErrAuthenticationFailed
	case err != nil:
		return fmt.Errorf("remove the passkey: %w", err)
	}

	SetEvent(ctx, es.EventPasskeyRemoved, slog.Uint64("passkey_xid", removed.PasskeyXID))

	_, err = h.MessageWriter.WriteOne(ctx, es.Message{
		Email: user.Email,
		Name:  removed.Name,
	}, es.WriteCreate|es.SendPasskeyRemoved)
	if err != nil {
		return fmt.Errorf("send the notice: %w", err)
	}

	ctx.SetStatusCode(fasthttp.StatusNoContent)
	return nil
}

// refuse uses up the confirmation challenge of the session, counts the failure and returns [ErrAuthenticationFailed],
// all in one transaction. A session that holds no challenge any more gets the same answer.
func (h *RemovePasskeyHandler) refuse(ctx *fasthttp.RequestCtx, session es.Session) error {
	_, err := h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID:       session.ID,
			Failures: session.Failures + 1,
		},
	}, es.RefuseLogin|es.ConsumeChallenge)
	if err != nil && !errors.Is(err, es.ErrNoUpdatedRows) {
		return fmt.Errorf("record the refusal: %w", err)
	}

	SetEvent(ctx, es.EventPasskeyRemovalRefused)

	return ErrAuthenticationFailed
}
