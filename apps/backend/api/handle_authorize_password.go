package api

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/auth"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/validate"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &AuthorizePasswordHandler{}

var authorizePasswordHandlerBodyArgsPool web.Pool[AuthorizePasswordHandlerBodyArgs]

// AuthorizePasswordHandlerBodyArgs are the arguments of POST /auth/password.
type AuthorizePasswordHandlerBodyArgs struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *AuthorizePasswordHandlerBodyArgs) DecodeJSON(value gjson.Result) error {
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
// It returns [ErrNoBodyEmail] or [ErrMalformedBodyEmail] for a bad email. It returns [ErrNoBodyPassword] or
// [ErrMaxLenBodyPassword] for a bad password.
func (a *AuthorizePasswordHandlerBodyArgs) Validate() error {
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
	}
	if passwordSize.IsEmpty() {
		return ErrNoBodyPassword
	}

	if passwordSize.TooLong() {
		return ErrMaxLenBodyPassword
	}

	return nil
}

// AuthorizePasswordHandlerResult is the response of POST /auth/password.
type AuthorizePasswordHandlerResult struct {
	// Flags are the flag bits of the session after the step. They include [es.SessionFlagPasswordApproved], which
	// says that the login waits for the code of the authenticator app.
	Flags es.SessionFlag `json:"flags"`
}

// AuthorizePasswordHandler handles POST /auth/password. It is the first factor of an account without a passkey. A
// correct password binds the session to the account, and the TOTP code is the next step.
//
// A wrong password, an unknown email, an account that cannot authenticate and an account with a passkey all fail in the
// same way. They also take about the same time. The handler always checks a password hash, and uses a stand-in hash if
// there is no account.
type AuthorizePasswordHandler struct {
	UserReader         es.Reader[es.User]
	PasskeyBatchReader es.BatchReader[es.Passkey]
	PasswordHasher     *auth.Hasher

	// SessionGroupWriter writes the outcome of the attempt in one transaction: the binding of the session, or the failure
	// counters of a refusal.
	SessionGroupWriter es.Writer[es.SessionGroup]

	// StandInHash is the hash of a random password, made at startup. The handler checks the password against it if no
	// account exists.
	StandInHash string
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrAuthenticationFailed] if the password is not accepted. Each refusal adds one to the failure count of
// the session.
func (h *AuthorizePasswordHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := authorizePasswordHandlerBodyArgsPool.Get()
	defer authorizePasswordHandlerBodyArgsPool.Put(bodyArgs)

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
	hash := user.PasswordHash
	if errors.Is(err, es.ErrNotFound) {
		hash = h.StandInHash
	} else if err != nil {
		return fmt.Errorf("read the user: %w", err)
	}

	verifyErr := h.PasswordHasher.Verify(hash, bodyArgs.Password)

	refused := user.ID == 0 || !user.CanAuthenticate() || verifyErr != nil
	if user.ID != 0 {
		passkeys, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
			UserID: user.ID,
		}, es.DefaultPaginator, 0)
		if err != nil {
			return fmt.Errorf("read the passkeys: %w", err)
		}

		for _, p := range passkeys {
			if p.Present() {
				// The account has a passkey, so the password is not a factor for it, whatever the password was.
				refused = true
			}
		}
	}

	if refused {
		_, err := h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
			Session: es.Session{
				ID:       session.ID,
				Failures: session.Failures + 1,
			},
		}, es.RefuseLogin)
		if err != nil {
			return fmt.Errorf("record the refusal: %w", err)
		}

		SetEvent(ctx, es.EventPasswordRefused)

		return ErrAuthenticationFailed
	}

	SetUser(ctx, user)

	// A new attempt starts clean: the binder clears the flags of earlier factors and logins.
	_, err = h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID:     session.ID,
			UserID: user.ID,
			Flags:  es.SessionFlagPasswordApproved,
		},
	}, es.ApprovePassword)
	if err != nil {
		return fmt.Errorf("bind the session: %w", err)
	}

	SetEvent(ctx, es.EventPasswordApproved)

	return web.Write(ctx, fasthttp.StatusOK, AuthorizePasswordHandlerResult{
		Flags: session.Flags&^es.SessionFlagLoginAttempt | es.SessionFlagPasswordApproved,
	})
}
