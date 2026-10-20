package api

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/snowid"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/validate"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &IssueRecoveryCodesHandler{}
var _ web.Handler = &AuthorizeRecoveryHandler{}

var authorizeRecoveryHandlerBodyArgsPool web.Pool[AuthorizeRecoveryHandlerBodyArgs]

const (
	// RecoveryCodeCount is the number of codes in a set. RecoveryCodeBytes is the size of each code in bytes: 80 bits,
	// shown as 16 base32 characters.
	RecoveryCodeCount = 8
	RecoveryCodeBytes = 10
)

// IssueRecoveryCodesHandlerResult is the response of POST /enroll/recovery. It holds the codes, which the API shows
// once.
type IssueRecoveryCodesHandlerResult struct {
	Codes []string `json:"codes"`
}

// IssueRecoveryCodesHandler handles POST /enroll/recovery. It makes a new set of recovery codes for the account, stores
// their keyed hashes, notifies the user and returns the codes. The API shows the codes once. The earlier set stops
// working.
type IssueRecoveryCodesHandler struct {
	AccountGroupWriter    es.Writer[es.AccountGroup]
	RecoveryCodeSnowflake *snowid.Snowflake
	TransitWriter         es.Writer[es.Transit]
	MessageWriter         es.Writer[es.Message]
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrNoAccount] if the session is bound to no account.
func (h *IssueRecoveryCodesHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	user, err := User(ctx)
	if err != nil {
		return ErrNoAccount
	}

	codes := make([]string, 0, RecoveryCodeCount)
	items := make([]es.RecoveryCode, 0, RecoveryCodeCount)
	for range RecoveryCodeCount {
		raw := make([]byte, RecoveryCodeBytes)

		if _, err := rand.Read(raw); err != nil {
			return fmt.Errorf("make a recovery code: %w", err)
		}

		code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)

		mac, err := macOf(ctx, h.TransitWriter, "recovery", code)
		if err != nil {
			return fmt.Errorf("hash a recovery code: %w", err)
		}

		codes = append(codes, code)
		items = append(items, es.RecoveryCode{
			RecoveryCodeXID: h.RecoveryCodeSnowflake.Next(),
			UserID:          user.ID,
			MAC:             mac,
		})
	}

	_, err = h.AccountGroupWriter.WriteOne(ctx, es.AccountGroup{
		User: es.User{
			ID: user.ID,
		},
		Codes: items,
	}, es.ReissueRecoveryCodes)
	if err != nil {
		return fmt.Errorf("store the recovery codes: %w", err)
	}

	SetEvent(ctx, es.EventRecoveryCodesIssued)

	_, err = h.MessageWriter.WriteOne(ctx, es.Message{
		Email: user.Email,
	}, es.WriteCreate|es.SendRecoveryIssued)
	if err != nil {
		return fmt.Errorf("send the notice: %w", err)
	}

	return web.Write(ctx, fasthttp.StatusOK, IssueRecoveryCodesHandlerResult{
		Codes: codes,
	})
}

// AuthorizeRecoveryHandlerBodyArgs are the arguments of POST /auth/recovery.
type AuthorizeRecoveryHandlerBodyArgs struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *AuthorizeRecoveryHandlerBodyArgs) DecodeJSON(value gjson.Result) error {
	return web.VisitObject(value, func(key string, member gjson.Result) error {
		var err error
		switch key {
		case "email":
			a.Email, err = web.JSONString(member)
		case "code":
			a.Code, err = web.JSONString(member)
		default:
			err = web.ErrUnknownBody
		}
		return err
	})
}

// Validate checks the arguments, converts the email to lower case and normalizes the code. The code is 16 base32
// characters. Case and dashes do not matter.
//
// It returns [ErrNoBodyEmail] or [ErrMalformedBodyEmail] for a bad email, and [ErrMalformedBodyCode] for a bad code.
func (a *AuthorizeRecoveryHandlerBodyArgs) Validate() error {
	a.Email = strings.ToLower(strings.TrimSpace(a.Email))

	if (validate.Validate{Input: a.Email}).IsEmpty() {
		return ErrNoBodyEmail
	}

	if !validate.IsEmail(a.Email) {
		return ErrMalformedBodyEmail
	}

	a.Code = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(a.Code), "-", ""))

	if !validate.IsRecoveryCode(a.Code) {
		return ErrMalformedBodyCode
	}

	return nil
}

// AuthorizeRecoveryHandlerResult is the response of POST /auth/recovery and POST /recover/grant.
type AuthorizeRecoveryHandlerResult struct {
	// Flags are the flag bits of the session after the step. They include [es.SessionFlagRecoveryApproved], which lets
	// the session enroll a factor.
	Flags es.SessionFlag `json:"flags"`
}

// AuthorizeRecoveryHandler handles POST /auth/recovery. An unused recovery code binds the session to the account. The
// session may then enroll a factor and do nothing else, because a recovery code does not log in. The handler uses the
// code up, writes a security event and notifies the user.
//
// An unknown email and a wrong code fail in the same way. They also take about the same time, because the handler
// computes the keyed hash for every request.
type AuthorizeRecoveryHandler struct {
	UserReader    es.Reader[es.User]
	TransitWriter es.Writer[es.Transit]
	MessageWriter es.Writer[es.Message]

	// SessionGroupWriter writes the outcome of the attempt in one transaction: the binding of the session, or the failure
	// counters of a refusal.
	SessionGroupWriter es.Writer[es.SessionGroup]
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrAuthenticationFailed] if the code is wrong or already used, or the account cannot authenticate. Each
// refusal adds one to the failure count of the session.
func (h *AuthorizeRecoveryHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := authorizeRecoveryHandlerBodyArgsPool.Get()
	defer authorizeRecoveryHandlerBodyArgsPool.Put(bodyArgs)

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

	mac, err := macOf(ctx, h.TransitWriter, "recovery", bodyArgs.Code)
	if err != nil {
		return fmt.Errorf("hash the code: %w", err)
	}

	user, err := h.UserReader.ReadOne(ctx, es.User{
		Email: bodyArgs.Email,
	}, 0)
	if err != nil && !errors.Is(err, es.ErrNotFound) {
		return fmt.Errorf("read the user: %w", err)
	}

	used := false
	if user.CanAuthenticate() {
		_, err = h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
			Session: es.Session{
				ID:     session.ID,
				UserID: user.ID,
				Flags:  es.SessionFlagRecoveryApproved,
			},
			RecoveryCode: es.RecoveryCode{
				MAC: mac,
			},
		}, es.ApproveRecoveryCode)
		if err != nil && !errors.Is(err, es.ErrNoUpdatedRows) {
			return fmt.Errorf("accept the code: %w", err)
		}

		used = err == nil
	}

	if !used {
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

	SetUser(ctx, user)

	SetEvent(ctx, es.EventRecoveryUsed)

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
