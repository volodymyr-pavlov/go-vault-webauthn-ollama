package api

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/totp"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/vault"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &AuthorizeTOTPHandler{}

// HistoryWindow is how far back the handlers read the sessions of a user to compute the risk signals.
const HistoryWindow = 30 * 24 * time.Hour

// AuthorizeResult is the response of the endpoints that complete a login. It holds the flags of the session and the
// decision of the risk engine.
type AuthorizeResult struct {
	Flags    es.SessionFlag `json:"flags"`
	Decision string         `json:"decision"`
	UserXID  uint64         `json:"user_xid,string"`
}

// AuthorizeTOTPHandler handles POST /auth/totp. It is the second factor of an account without a passkey. A valid code
// from a time step after the last accepted one completes the login.
//
// The risk engine decides what the session may do: the session is authorized, limited, flagged for review or refused.
type AuthorizeTOTPHandler struct {
	PasskeyBatchReader es.BatchReader[es.Passkey]
	TransitWriter      es.Writer[es.Transit]
	Options            totp.Options
	RiskAssessor       es.Reader[LoginAttempt]
	MessageWriter      es.Writer[es.Message]
	SystemClock        clock.Clock

	// SessionGroupWriter writes the outcome of the login in one transaction: the authorization, or the failure counters of a
	// refusal.
	SessionGroupWriter es.Writer[es.SessionGroup]
}

// ServeHTTP implements [web.Handler]. It responds with an [AuthorizeResult].
//
// It returns [ErrNoAccount] if the session is bound to no account. It returns [ErrAuthenticationFailed] if the code is
// wrong or reused, or the account has a passkey, has no confirmed TOTP factor or cannot authenticate. It returns
// [ErrRiskDenied] if the risk engine refuses the login.
func (h *AuthorizeTOTPHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := codeHandlerBodyArgsPool.Get()
	defer codeHandlerBodyArgsPool.Put(bodyArgs)

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

	passkeys, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
		UserID: user.ID,
	}, es.DefaultPaginator, 0)
	if err != nil {
		return fmt.Errorf("read the passkeys: %w", err)
	}

	refused := !user.CanAuthenticate() || !user.HasTOTP()
	for _, p := range passkeys {
		if p.Present() {
			refused = true
		}
	}

	if refused {
		SetEvent(ctx, es.EventTOTPRefused)

		return ErrAuthenticationFailed
	}

	now := h.SystemClock.Now()
	decrypted, err := h.TransitWriter.WriteOne(ctx, es.Transit{
		Key:        TOTPKey,
		Context:    TOTPContext(user.UserXID),
		Ciphertext: user.TOTPCiphertext,
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if errors.Is(err, vault.ErrDecrypt) {
		// The ciphertext was not made for this user. For example, the row was copied from another account.
		SetEvent(ctx, es.EventTOTPCiphertextRefused)

		return ErrAuthenticationFailed
	} else if err != nil {
		return fmt.Errorf("decrypt the secret: %w", err)
	}

	secret := decrypted.Plaintext

	step, verifyErr := h.Options.Verify(secret, bodyArgs.Code, now, user.TOTPLastStep)
	if verifyErr != nil {
		if err := h.recordRefusal(ctx, es.SessionGroup{
			Session: es.Session{
				ID:       session.ID,
				Failures: session.Failures + 1,
			},
			User: es.User{
				ID:             user.ID,
				TOTPCiphertext: user.TOTPCiphertext,
				TOTPLastStep:   user.TOTPLastStep,
				TOTPFailures:   user.TOTPFailures + 1,
			},
		}); err != nil {
			return err
		}

		SetEvent(ctx, es.EventTOTPRefused, slog.Bool("reused", errors.Is(verifyErr, totp.ErrReused)))

		return ErrAuthenticationFailed
	}

	attempt, err := h.RiskAssessor.ReadOne(ctx, LoginAttempt{
		Session:  session,
		User:     user,
		Passkeys: passkeys,
		Factor:   es.FactorPassword | es.FactorTOTP,
		Now:      now,
	}, 0)
	if err != nil {
		return err
	}

	outcome := attempt.Outcome

	group := es.SessionGroup{
		User: es.User{
			ID:             user.ID,
			TOTPCiphertext: user.TOTPCiphertext,
			TOTPLastStep:   step,
		},
	}
	op := es.AuthorizeLogin

	flags := es.SessionFlagTOTPApproved | es.SessionFlagAuthorized
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

	// One transaction stores the code step, writes the outcome on the session and, for an allowed login, ends the open
	// recovery requests of the user. The mail goes out after the commit.
	_, err = h.SessionGroupWriter.WriteOne(ctx, group, op)
	if errors.Is(err, es.ErrNoUpdatedRows) {
		SetEvent(ctx, es.EventTOTPRefused, slog.Bool("reused", true))

		return ErrAuthenticationFailed
	}

	if err != nil {
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
		slog.String("factor", (es.FactorPassword|es.FactorTOTP).String()),
		slog.Uint64("score", uint64(outcome.Score)),
		slog.String("decision", outcome.Decision.String()),
		slog.Bool("advised", outcome.Advised()),
		slog.Bool("raised", outcome.Raised()),
	)

	return web.Write(ctx, fasthttp.StatusOK, AuthorizeResult{
		Flags:    session.Flags | flags,
		Decision: outcome.Decision.String(),
		UserXID:  user.UserXID,
	})
}

// recordRefusal appends the refusal in one transaction with the counters that it holds.
func (h *AuthorizeTOTPHandler) recordRefusal(ctx *fasthttp.RequestCtx, refusal es.SessionGroup) error {
	if _, err := h.SessionGroupWriter.WriteOne(ctx, refusal, es.RefuseLogin); err != nil {
		return fmt.Errorf("record the refusal: %w", err)
	}

	return nil
}
