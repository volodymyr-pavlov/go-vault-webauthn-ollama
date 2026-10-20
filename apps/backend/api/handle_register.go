package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
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

var _ web.Handler = &BeginRegistryHandler{}
var _ web.Handler = &CompleteRegistryHandler{}

var beginRegistryHandlerBodyArgsPool web.Pool[BeginRegistryHandlerBodyArgs]
var completeRegistryHandlerBodyArgsPool web.Pool[CompleteRegistryHandlerBodyArgs]

const (
	// DefaultVerifyTTL is the default time the verification token of a registration stays valid.
	DefaultVerifyTTL = 15 * time.Minute
)

// BeginRegistryHandlerBodyArgs are the arguments of POST /register.
type BeginRegistryHandlerBodyArgs struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *BeginRegistryHandlerBodyArgs) DecodeJSON(value gjson.Result) error {
	return web.VisitObject(value, func(key string, member gjson.Result) error {
		var err error
		switch key {
		case "email":
			a.Email, err = web.JSONString(member)
		case "password":
			a.Password, err = web.JSONString(member)
		default:
			err = web.ErrUnknownBody
		}
		return err
	})
}

// Validate checks the arguments and converts the email to lower case.
//
// It returns [ErrNoBodyEmail] or [ErrMalformedBodyEmail] for a bad email. It returns [ErrNoBodyPassword],
// [ErrMinLenBodyPassword] or [ErrMaxLenBodyPassword] for a bad password.
func (a *BeginRegistryHandlerBodyArgs) Validate() error {
	a.Email = strings.ToLower(strings.TrimSpace(a.Email))

	if (validate.Validate{Input: a.Email}).IsEmpty() {
		return ErrNoBodyEmail
	}

	if !validate.IsEmail(a.Email) {
		return ErrMalformedBodyEmail
	}

	passwordSize := validate.Validate{
		Input: a.Password,
		Max:   auth.MaxLength,
		Min:   validate.MinPasswordLength,
	}
	if passwordSize.IsEmpty() {
		return ErrNoBodyPassword
	}

	if passwordSize.TooShort() {
		return ErrMinLenBodyPassword
	}

	if passwordSize.TooLong() {
		return ErrMaxLenBodyPassword
	}

	return nil
}

// BeginRegistryHandlerResult is the response of POST /register. It is the same for a new email and for a taken one.
type BeginRegistryHandlerResult struct {
	// Flags are the flag bits of the session after the step. They include [es.SessionFlagRegistryBegun], which says
	// that the registration waits for its verification token.
	Flags es.SessionFlag `json:"flags"`
}

// BeginRegistryHandler handles POST /register. It creates the user and sends a verification token to the email. If
// the email is taken, it sends a notice to that email instead.
//
// Both cases respond in the same way and set the same flags on the session. The response does not show whether the
// email is registered. For a new user, the session is bound to the user. For a taken email, the session is bound
// to nothing and keeps the hash of a verification token that nobody received. The completing step then fails like a
// wrong verification token.
type BeginRegistryHandler struct {
	UserReader         es.Reader[es.User]
	SessionGroupWriter es.Writer[es.SessionGroup]
	UserSnowflake      *snowid.Snowflake
	PasswordHasher     *auth.Hasher
	MessageWriter      es.Writer[es.Message]
	SystemClock        clock.Clock

	// VerifyTTL is how long the verification token stays valid. Zero means [DefaultVerifyTTL].
	VerifyTTL time.Duration
}

// ServeHTTP implements [web.Handler]. It responds with status 202.
func (h *BeginRegistryHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := beginRegistryHandlerBodyArgsPool.Get()
	defer beginRegistryHandlerBodyArgsPool.Put(bodyArgs)

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

	// The password is hashed before the email is looked up, so a taken email takes the same time as a new one.
	passwordHash, err := h.PasswordHasher.Hash(bodyArgs.Password)
	if err != nil {
		return fmt.Errorf("hash the password: %w", err)
	}

	token := make([]byte, 32)

	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("make the verification token: %w", err)
	}

	verifyHash := sha256.Sum256(token)

	ttl := h.VerifyTTL
	if ttl == 0 {
		ttl = DefaultVerifyTTL
	}

	now := h.SystemClock.Now()

	_, err = h.UserReader.ReadOne(ctx, es.User{
		Email: bodyArgs.Email,
	}, 0)
	switch {
	case errors.Is(err, es.ErrNotFound):
		handle := make([]byte, 64)

		if _, err := rand.Read(handle); err != nil {
			return fmt.Errorf("make the user handle: %w", err)
		}

		_, err = h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
			User: es.User{
				UserXID:      h.UserSnowflake.Next(),
				Email:        bodyArgs.Email,
				Handle:       handle,
				PasswordHash: passwordHash,
			},
			Session: es.Session{
				ID:              session.ID,
				Flags:           es.SessionFlagRegistryBegun,
				VerifyHash:      verifyHash[:],
				VerifyExpiresAt: now.Add(ttl),
			},
		}, es.OpenRegistry)
		if errors.Is(err, es.ErrDuplicate) {
			// Another request took the email between the read and the write, so the email counts as taken.
			break
		} else if err != nil {
			return fmt.Errorf("open the registration: %w", err)
		}

		SetEvent(ctx, es.EventRegistrationBegun)

		_, err = h.MessageWriter.WriteOne(ctx, es.Message{
			Email: bodyArgs.Email,
			Token: hex.EncodeToString(token),
			TTL:   ttl,
		}, es.WriteCreate|es.SendRegistryToken)
		if err != nil {
			return fmt.Errorf("send the verification token: %w", err)
		}

		return web.Write(ctx, fasthttp.StatusAccepted, BeginRegistryHandlerResult{
			Flags: session.Flags | es.SessionFlagRegistryBegun,
		})
	case err != nil:
		return fmt.Errorf("read the user: %w", err)
	}

	// The email is taken. The session gets the same flags and the hash of a verification token that nobody received.
	_, err = h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID:              session.ID,
			Flags:           es.SessionFlagRegistryBegun,
			VerifyHash:      verifyHash[:],
			VerifyExpiresAt: now.Add(ttl),
		},
	}, es.OpenTakenRegistry)
	if err != nil {
		return fmt.Errorf("open the registration: %w", err)
	}

	SetEvent(ctx, es.EventRegistrationBegun)

	_, err = h.MessageWriter.WriteOne(ctx, es.Message{
		Email: bodyArgs.Email,
	}, es.WriteCreate|es.SendRegistryTaken)
	if err != nil {
		return fmt.Errorf("send the notice: %w", err)
	}

	return web.Write(ctx, fasthttp.StatusAccepted, BeginRegistryHandlerResult{
		Flags: session.Flags | es.SessionFlagRegistryBegun,
	})
}

// CompleteRegistryHandlerBodyArgs are the arguments of POST /register/complete.
type CompleteRegistryHandlerBodyArgs struct {
	Token string `json:"token"`

	token []byte
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *CompleteRegistryHandlerBodyArgs) DecodeJSON(value gjson.Result) error {
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

// Validate checks that the verification token is 64 hex digits.
//
// It returns [ErrNoBodyToken] if the verification token is empty. It returns [ErrMalformedBodyToken] if the token is
// not 64 hex digits.
func (a *CompleteRegistryHandlerBodyArgs) Validate() error {
	if (validate.Validate{Input: a.Token}).IsEmpty() {
		return ErrNoBodyToken
	}

	var ok bool

	a.token, ok = validate.HexToken(strings.TrimSpace(a.Token))
	if !ok {
		return ErrMalformedBodyToken
	}

	return nil
}

// CompleteRegistryHandlerResult is the response of POST /register/complete.
type CompleteRegistryHandlerResult struct {
	UserXID uint64 `json:"user_xid,string"`
}

// CompleteRegistryHandler handles POST /register/complete. It accepts the verification token on the session that began
// the registration, marks the user as verified and lets the session enroll a factor. A verification token works
// once, because the update that accepts it clears it.
type CompleteRegistryHandler struct {
	SessionGroupWriter es.Writer[es.SessionGroup]
	SystemClock        clock.Clock
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrAuthenticationFailed] if the verification token is wrong, expired or was never issued for a user.
func (h *CompleteRegistryHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := completeRegistryHandlerBodyArgsPool.Get()
	defer completeRegistryHandlerBodyArgsPool.Put(bodyArgs)

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
	presented := sha256.Sum256(bodyArgs.token)
	if subtle.ConstantTimeCompare(session.VerifyHash, presented[:]) != 1 || !now.Before(session.VerifyExpiresAt) || session.UserID == 0 {
		SetEvent(ctx, es.EventRegistrationTokenRefused)

		return ErrAuthenticationFailed
	}

	user, err := User(ctx)
	if err != nil {
		return err
	}

	_, err = h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		User: es.User{
			ID:    session.UserID,
			Flags: es.UserFlagVerified,
		},
		Session: es.Session{
			ID:    session.ID,
			Flags: es.SessionFlagRegistryVerified,
		},
	}, es.VerifyRegistry)
	if err != nil {
		return fmt.Errorf("verify the registration: %w", err)
	}

	SetEvent(ctx, es.EventRegistrationVerified)

	return web.Write(ctx, fasthttp.StatusOK, CompleteRegistryHandlerResult{
		UserXID: user.UserXID,
	})
}
