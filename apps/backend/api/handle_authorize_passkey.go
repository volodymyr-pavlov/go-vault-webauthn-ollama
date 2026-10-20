package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/auth"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/validate"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &BeginAuthorizePasskeyHandler{}
var _ web.Handler = &CompleteAuthorizePasskeyHandler{}

var beginAuthorizePasskeyHandlerBodyArgsPool web.Pool[BeginAuthorizePasskeyHandlerBodyArgs]
var responseHandlerBodyArgsPool web.Pool[ResponseHandlerBodyArgs]

// BeginAuthorizePasskeyHandlerBodyArgs are the arguments of POST /auth/passkey. Email is optional: without it, the
// login is discoverable and the passkey names the user.
type BeginAuthorizePasskeyHandlerBodyArgs struct {
	Email string `json:"email"`
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *BeginAuthorizePasskeyHandlerBodyArgs) DecodeJSON(value gjson.Result) error {
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

// Validate checks the arguments and converts the email, if there is one, to lower case.
//
// It returns [ErrMalformedBodyEmail] if the email is not an address.
func (a *BeginAuthorizePasskeyHandlerBodyArgs) Validate() error {
	a.Email = strings.ToLower(strings.TrimSpace(a.Email))

	if (validate.Validate{Input: a.Email}).IsEmpty() {
		return nil
	}

	if !validate.IsEmail(a.Email) {
		return ErrMalformedBodyEmail
	}

	return nil
}

// BeginAuthorizePasskeyHandler handles POST /auth/passkey. It starts the passkey login for the email and keeps the
// challenge on the session. A request without an email starts a discoverable login: the options list no credentials,
// the browser offers the passkeys it holds for this site, and the passkey names the user when the login finishes.
//
// An email with no usable passkey, known or not, gets options with a fake credential list. The list comes from a keyed
// hash of the email, so the response does not show whether the email is registered. The completing step then fails in
// the same way as a bad assertion.
type BeginAuthorizePasskeyHandler struct {
	UserReader         es.Reader[es.User]
	PasskeyBatchReader es.BatchReader[es.Passkey]
	RelyingParty       *auth.RelyingParty
	TransitWriter      es.Writer[es.Transit]
	SystemClock        clock.Clock

	// SessionGroupWriter clears the earlier attempt from the session and saves the new challenge in one transaction.
	SessionGroupWriter es.Writer[es.SessionGroup]

	// ChallengeTTL is how long the challenge stays valid. Zero means [DefaultChallengeTTL].
	ChallengeTTL time.Duration
}

// ServeHTTP implements [web.Handler]. It responds with the request options for the browser.
func (h *BeginAuthorizePasskeyHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := beginAuthorizePasskeyHandlerBodyArgsPool.Get()
	defer beginAuthorizePasskeyHandlerBodyArgsPool.Put(bodyArgs)

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

	var (
		options []byte
		state   []byte
		userID  uint64
		kind    = es.SessionFlagChallengeLogin
	)

	if bodyArgs.Email == "" {
		kind |= es.SessionFlagChallengeDiscoverable

		options, state, err = h.RelyingParty.BeginDiscoverableLogin()
		if err != nil {
			return fmt.Errorf("begin the discoverable login: %w", err)
		}
	} else {
		// The stand-in handle and credential are made for every email, so a known email takes the same time.
		standIn, err := macBytesOf(ctx, h.TransitWriter, "handle", bodyArgs.Email)
		if err != nil {
			return fmt.Errorf("make the stand-in handle: %w", err)
		}

		second := sha256.Sum256(standIn)
		handle := append(append([]byte{}, standIn...), second[:]...)
		credentialIDs := [][]byte{standIn}

		user, err := h.UserReader.ReadOne(ctx, es.User{
			Email: bodyArgs.Email,
		}, 0)
		if err != nil && !errors.Is(err, es.ErrNotFound) {
			return fmt.Errorf("read the user: %w", err)
		}

		if err == nil && user.CanAuthenticate() {
			passkeys, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
				UserID: user.ID,
			}, es.DefaultPaginator, 0)
			if err != nil {
				return fmt.Errorf("read the passkeys: %w", err)
			}

			var usable [][]byte
			for _, p := range passkeys {
				if p.Usable() {
					usable = append(usable, p.CredentialID)
				}
			}

			if len(usable) != 0 {
				handle = user.Handle
				credentialIDs = usable
				userID = user.ID
			}
		}

		options, state, err = h.RelyingParty.BeginLogin(handle, credentialIDs)
		if err != nil {
			return fmt.Errorf("begin the login: %w", err)
		}
	}

	ttl := h.ChallengeTTL
	if ttl == 0 {
		ttl = DefaultChallengeTTL
	}

	// A new attempt starts clean: the opener clears the flags of earlier factors and logins and the earlier challenge.
	_, err = h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID:                 session.ID,
			Flags:              kind,
			UserID:             userID,
			Challenge:          state,
			ChallengeExpiresAt: h.SystemClock.Now().Add(ttl),
		},
	}, es.OpenPasskeyLogin)
	if err != nil {
		return fmt.Errorf("keep the challenge: %w", err)
	}

	return web.Write(ctx, fasthttp.StatusOK, json.RawMessage(options))
}

// ResponseHandlerBodyArgs are the arguments of the endpoints that take only an authenticator response.
type ResponseHandlerBodyArgs struct {
	Response json.RawMessage `json:"response"`
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *ResponseHandlerBodyArgs) DecodeJSON(value gjson.Result) error {
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

// Validate checks the arguments.
//
// It returns [ErrNoBodyResponse] if the response is empty.
func (a *ResponseHandlerBodyArgs) Validate() error {
	if len(a.Response) == 0 {
		return ErrNoBodyResponse
	}

	return nil
}

// CompleteAuthorizePasskeyHandler handles POST /auth/passkey/complete. It verifies the assertion against the challenge
// on the session and the passkeys of the user, advances the counter and completes the login. The risk engine decides
// what the session may do.
//
// A counter that went backwards disables the passkey and refuses the login. The challenge is used up whether the
// assertion verifies or not.
type CompleteAuthorizePasskeyHandler struct {
	UserReader         es.Reader[es.User]
	PasskeyBatchReader es.BatchReader[es.Passkey]
	RelyingParty       *auth.RelyingParty
	RiskAssessor       es.Reader[LoginAttempt]
	MessageWriter      es.Writer[es.Message]
	SystemClock        clock.Clock

	// SessionGroupWriter writes the outcome of the login in one transaction: the authorization, or the refusal with its
	// counters, and it uses up the challenge.
	SessionGroupWriter es.Writer[es.SessionGroup]
}

// ServeHTTP implements [web.Handler]. It responds with an [AuthorizeResult].
//
// It returns [ErrAuthenticationFailed] if the challenge is missing or expired, the assertion does not verify, the
// counter went backwards or the user cannot authenticate. It returns [ErrRiskDenied] if the risk engine refuses the
// login.
func (h *CompleteAuthorizePasskeyHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := responseHandlerBodyArgsPool.Get()
	defer responseHandlerBodyArgsPool.Put(bodyArgs)

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

	now := h.SystemClock.Now()

	discoverable := session.Flags&es.SessionFlagChallengeDiscoverable != 0

	// A session without a challenge has nothing to refuse. Every other refusal uses the challenge up in the same
	// transaction that counts the failure, so a challenge works once, whatever the assertion is.
	if len(session.Challenge) == 0 {
		return ErrAuthenticationFailed
	}

	if !now.Before(session.ChallengeExpiresAt) || (!discoverable && session.UserID == 0) {
		if err := h.recordRefusal(ctx, session, es.Passkey{}); err != nil {
			return err
		}

		SetEvent(ctx, es.EventPasskeyRefused)

		return ErrAuthenticationFailed
	}

	var (
		user      es.User
		passkeys  []es.Passkey
		signed    es.Passkey
		regressed bool
	)

	if discoverable {
		user, signed, regressed, err = h.RelyingParty.FinishDiscoverableLogin(func(userHandle []byte) (es.User, []es.Passkey, error) {
			found, err := h.UserReader.ReadOne(ctx, es.User{
				Handle: userHandle,
			}, 0)
			if err != nil {
				return es.User{}, nil, err
			}

			owned, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
				UserID: found.ID,
			}, es.DefaultPaginator, 0)
			if err != nil {
				return es.User{}, nil, fmt.Errorf("read the passkeys: %w", err)
			}

			passkeys = owned

			return found, owned, nil
		}, session.Challenge, bodyArgs.Response)
	} else {
		user, err = h.UserReader.ReadOne(ctx, es.User{
			ID: session.UserID,
		}, 0)
		if err != nil {
			return fmt.Errorf("read the user: %w", err)
		}

		passkeys, err = h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
			UserID: user.ID,
		}, es.DefaultPaginator, 0)
		if err != nil {
			return fmt.Errorf("read the passkeys: %w", err)
		}

		signed, regressed, err = h.RelyingParty.FinishLogin(user, passkeys, session.Challenge, bodyArgs.Response)
	}

	if errors.Is(err, auth.ErrVerify) || (err == nil && !user.CanAuthenticate()) {
		if err := h.recordRefusal(ctx, session, es.Passkey{}); err != nil {
			return err
		}

		SetEvent(ctx, es.EventPasskeyRefused)

		return ErrAuthenticationFailed.Wrap(err)
	} else if err != nil {
		return fmt.Errorf("finish the login: %w", err)
	}

	if regressed {
		err := h.recordRefusal(ctx, session, es.Passkey{
			ID:    signed.ID,
			Flags: es.PasskeyFlagDisabled,
		})
		if err != nil {
			return err
		}

		SetEvent(ctx, es.EventCounterRegression, slog.Uint64("passkey_xid", signed.PasskeyXID))

		_, err = h.MessageWriter.WriteOne(ctx, es.Message{
			Email: user.Email,
			Name:  signed.Name,
		}, es.WriteCreate|es.SendPasskeyDisabled)
		if err != nil {
			return fmt.Errorf("send the notice: %w", err)
		}

		return ErrAuthenticationFailed
	}

	SetUser(ctx, user)

	attempt, err := h.RiskAssessor.ReadOne(ctx, LoginAttempt{
		Session:  session,
		User:     user,
		Passkeys: passkeys,
		Factor:   es.FactorPasskey,
		Now:      now,
	}, 0)
	if err != nil {
		return err
	}

	outcome := attempt.Outcome

	group := es.SessionGroup{
		Passkey: es.Passkey{
			ID:        signed.ID,
			Flags:     signed.Flags,
			SignCount: signed.SignCount,
		},
	}
	op := es.AuthorizeLogin | es.ConsumeChallenge

	flags := es.SessionFlagPasskeyApproved | es.SessionFlagAuthorized
	switch outcome.Decision {
	case ai.DecisionDeny:
		op = op&^es.AuthorizeLogin | es.DenyLogin
		group.Session = es.Session{
			ID:        session.ID,
			RiskScore: outcome.Score,
		}
	case ai.DecisionLimit:
		flags |= es.SessionFlagLimited
	case ai.DecisionReview:
		flags |= es.SessionFlagLimited | es.SessionFlagReview
	}

	if op&es.DenyLogin == 0 {
		group.Session = es.Session{
			ID:        session.ID,
			UserID:    user.ID,
			Flags:     flags,
			AuthTime:  now,
			RiskScore: outcome.Score,
		}
	}

	// One transaction uses up the challenge, stores the counter, writes the outcome on the session and, for an allowed
	// login, ends the open recovery requests of the user. The mail goes out after the commit.
	_, err = h.SessionGroupWriter.WriteOne(ctx, group, op)
	if errors.Is(err, es.ErrNoUpdatedRows) {
		return ErrAuthenticationFailed
	} else if err != nil {
		return fmt.Errorf("record the login: %w", err)
	}

	if op&es.DenyLogin != 0 {
		SetEvent(ctx, es.EventLoginDenied,
			slog.Uint64("score", uint64(outcome.Score)),
			slog.String("decision", outcome.Decision.String()),
		)

		_, err = h.MessageWriter.WriteOne(ctx, es.Message{
			Email: user.Email,
		}, es.WriteCreate|es.SendLoginRefused)
		if err != nil {
			return fmt.Errorf("send the notice: %w", err)
		}

		return ErrRiskDenied
	}

	SetEvent(ctx, es.EventLogin,
		slog.String("factor", es.FactorPasskey.String()),
		slog.Uint64("passkey_xid", signed.PasskeyXID),
		slog.Uint64("score", uint64(outcome.Score)),
		slog.String("decision", outcome.Decision.String()),
		slog.Bool("advised", outcome.Advised()),
		slog.Bool("raised", outcome.Raised()),
	)

	return web.Write(ctx, fasthttp.StatusOK, AuthorizeResult{
		Flags:    (session.Flags &^ es.SessionFlagChallenge) | flags,
		Decision: outcome.Decision.String(),
		UserXID:  user.UserXID,
	})
}

// recordRefusal uses up the challenge of the session, counts the failure, adds the flags of passkey to the stored
// passkey if it names one, all in one transaction.
//
// It returns [ErrAuthenticationFailed] if the session holds no challenge any more, for example after a replay.
func (h *CompleteAuthorizePasskeyHandler) recordRefusal(ctx *fasthttp.RequestCtx, session es.Session, passkey es.Passkey) error {
	_, err := h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID:       session.ID,
			Failures: session.Failures + 1,
		},
		Passkey: passkey,
	}, es.RefuseLogin|es.ConsumeChallenge)
	if errors.Is(err, es.ErrNoUpdatedRows) {
		return ErrAuthenticationFailed
	} else if err != nil {
		return fmt.Errorf("record the refusal: %w", err)
	}

	return nil
}
