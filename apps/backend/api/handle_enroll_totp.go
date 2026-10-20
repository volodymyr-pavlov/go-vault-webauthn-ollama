package api

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/totp"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/validate"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/vault"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &BeginEnrollTOTPHandler{}
var _ web.Handler = &CompleteEnrollTOTPHandler{}
var _ web.Handler = &RemoveTOTPHandler{}

var codeHandlerBodyArgsPool web.Pool[CodeHandlerBodyArgs]

// TOTPKey is the name of the Transit key that encrypts TOTP secrets. The external ID of the user is the key context.
const TOTPKey = "totp"

// TOTPContext returns the Transit key context of the TOTP secret of the user with the external ID userXID. Encrypting
// and decrypting under this context binds a ciphertext to its user.
func TOTPContext(userXID uint64) []byte {
	context := make([]byte, 8)
	binary.BigEndian.PutUint64(context, userXID)

	return context
}

// BeginEnrollTOTPHandlerResult is the response of POST /enroll/totp. It holds the secret and the URI for an
// authenticator app. The API shows them once.
type BeginEnrollTOTPHandlerResult struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// BeginEnrollTOTPHandler handles POST /enroll/totp. It makes a secret for the user, stores it encrypted and shows it
// once.
//
// The secret is not a factor until the first valid code confirms it. A user with a passkey cannot add a code
// generator, and a user with a confirmed one cannot add a second.
type BeginEnrollTOTPHandler struct {
	UserWriter         es.Writer[es.User]
	PasskeyBatchReader es.BatchReader[es.Passkey]
	TransitWriter      es.Writer[es.Transit]
	Issuer             string
	Options            totp.Options
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrSessionWithoutUser] if the session is bound to no user. It returns [ErrAlreadyEnrolledTOTP] if the user
// has a confirmed TOTP factor, and [ErrPasskeyUser] if it has a passkey.
func (h *BeginEnrollTOTPHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	user, err := User(ctx)
	if err != nil {
		return ErrSessionWithoutUser
	}

	if user.HasTOTP() {
		return ErrAlreadyEnrolledTOTP
	}

	passkeys, err := h.PasskeyBatchReader.ReadAll(ctx, es.Passkey{
		UserID: user.ID,
	}, es.DefaultPaginator, 0)
	if err != nil {
		return fmt.Errorf("read the passkeys: %w", err)
	}

	for _, p := range passkeys {
		if p.Present() {
			return ErrPasskeyUser
		}
	}

	secret, err := totp.NewSecret()
	if err != nil {
		return err
	}

	encrypted, err := h.TransitWriter.WriteOne(ctx, es.Transit{
		Key:       TOTPKey,
		Context:   TOTPContext(user.UserXID),
		Plaintext: secret,
	}, es.WriteCreate|es.EncryptTOTPSecret)
	if err != nil {
		return fmt.Errorf("encrypt the secret: %w", err)
	}

	ciphertext := encrypted.Ciphertext

	_, err = h.UserWriter.WriteOne(ctx, es.User{
		ID:             user.ID,
		Flags:          es.UserFlagTOTPConfirmed,
		TOTPCiphertext: ciphertext,
	}, es.WriteUpdate|es.ClearFlag|es.ResetTOTP)
	if err != nil {
		return fmt.Errorf("store the secret: %w", err)
	}

	return web.Write(ctx, fasthttp.StatusOK, BeginEnrollTOTPHandlerResult{
		Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret),
		URI:    totp.URI(h.Issuer, user.Email, secret, h.Options),
	})
}

// CodeHandlerBodyArgs are the arguments of the endpoints that take a six-digit code.
type CodeHandlerBodyArgs struct {
	Code string `json:"code"`
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *CodeHandlerBodyArgs) DecodeJSON(value gjson.Result) error {
	return web.VisitObject(value, func(key string, member gjson.Result) error {
		var err error
		switch key {
		case "code":
			a.Code, err = web.JSONString(member)
		default:
			err = web.ErrUnknownBody
		}
		return err
	})
}

// Validate checks that the code has [totp.DefaultDigits] digits.
//
// It returns [ErrMalformedBodyCode] if it does not.
func (a *CodeHandlerBodyArgs) Validate() error {
	a.Code = strings.TrimSpace(a.Code)

	if !validate.IsDigits(a.Code, totp.DefaultDigits) {
		return ErrMalformedBodyCode
	}

	return nil
}

// CompleteEnrollTOTPHandler handles POST /enroll/totp/complete. The first valid code confirms the secret, and the
// secret becomes a factor. Enrolling does not log the session in: the user logs in with the password and a code.
type CompleteEnrollTOTPHandler struct {
	UserGroupWriter es.Writer[es.UserGroup]
	TransitWriter   es.Writer[es.Transit]
	Options         totp.Options
	MessageWriter   es.Writer[es.Message]
	SystemClock     clock.Clock
}

// ServeHTTP implements [web.Handler]. It responds with status 204.
//
// It returns [ErrSessionWithoutUser] if the session is bound to no user. It returns [ErrNoEnrolledTOTP] if the user has no
// secret that waits for confirmation, and [ErrAuthenticationFailed] if the code is wrong.
func (h *CompleteEnrollTOTPHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := codeHandlerBodyArgsPool.Get()
	defer codeHandlerBodyArgsPool.Put(bodyArgs)

	if err := web.Unmarshal(ctx, bodyArgs); err != nil {
		return err
	}

	if err := bodyArgs.Validate(); err != nil {
		return err
	}

	user, err := User(ctx)
	if err != nil {
		return ErrSessionWithoutUser
	}

	if user.TOTPCiphertext == "" || user.HasTOTP() {
		return ErrNoEnrolledTOTP
	}

	decrypted, err := h.TransitWriter.WriteOne(ctx, es.Transit{
		Key:        TOTPKey,
		Context:    TOTPContext(user.UserXID),
		Ciphertext: user.TOTPCiphertext,
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if errors.Is(err, vault.ErrDecrypt) {
		SetEvent(ctx, es.EventTOTPCiphertextRefused)

		return ErrAuthenticationFailed
	} else if err != nil {
		return fmt.Errorf("decrypt the secret: %w", err)
	}

	secret := decrypted.Plaintext

	step, err := h.Options.Verify(secret, bodyArgs.Code, h.SystemClock.Now(), 0)
	if err != nil {
		SetEvent(ctx, es.EventTOTPEnrollmentRefused)

		return ErrAuthenticationFailed
	}

	_, err = h.UserGroupWriter.WriteOne(ctx, es.UserGroup{
		User: es.User{
			ID:             user.ID,
			TOTPCiphertext: user.TOTPCiphertext,
			TOTPLastStep:   step,
		},
	}, es.ConfirmTOTP)
	if err != nil {
		return fmt.Errorf("confirm the secret: %w", err)
	}

	SetEvent(ctx, es.EventTOTPEnrolled)

	_, err = h.MessageWriter.WriteOne(ctx, es.Message{
		Email: user.Email,
	}, es.WriteCreate|es.SendTOTPAdded)
	if err != nil {
		return fmt.Errorf("send the notice: %w", err)
	}

	ctx.SetStatusCode(fasthttp.StatusNoContent)
	return nil
}

// RemoveTOTPHandler handles DELETE /totp. It removes the TOTP factor of the user unless it is the last factor.
// The writer locks the user row while it counts the factors.
type RemoveTOTPHandler struct {
	UserGroupWriter es.Writer[es.UserGroup]
	MessageWriter   es.Writer[es.Message]
}

// ServeHTTP implements [web.Handler]. It responds with status 204.
//
// It returns [ErrSessionWithoutUser] if the session is bound to no user. It returns [ErrNoEnrolledTOTP] if the user has no
// TOTP factor, and [ErrLastFactor] if the user has no usable passkey.
func (h *RemoveTOTPHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	user, err := User(ctx)
	if err != nil {
		return ErrSessionWithoutUser
	}

	_, err = h.UserGroupWriter.WriteOne(ctx, es.UserGroup{
		User: es.User{
			ID: user.ID,
		},
	}, es.RemoveTOTP)
	switch {
	case errors.Is(err, es.ErrNoTOTPSecret):
		return ErrNoEnrolledTOTP
	case errors.Is(err, es.ErrLastFactor):
		return ErrLastFactor
	case err != nil:
		return fmt.Errorf("remove the secret: %w", err)
	}

	SetEvent(ctx, es.EventTOTPRemoved)

	_, err = h.MessageWriter.WriteOne(ctx, es.Message{
		Email: user.Email,
	}, es.WriteCreate|es.SendTOTPRemoved)
	if err != nil {
		return fmt.Errorf("send the notice: %w", err)
	}

	ctx.SetStatusCode(fasthttp.StatusNoContent)
	return nil
}
