//go:build integration

package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tidwall/gjson"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/auth"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/authtest"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/totp"
)

const testPassword = "correct horse battery staple"

// newDevice generates the key of a new device and returns its handle. The device has no session yet.
func (s *stand) newDevice() string {
	s.t.Helper()
	public, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		s.t.Fatal(err)
	}
	handle := base64.RawURLEncoding.EncodeToString(public)
	s.devices[handle] = key

	return handle
}

// openSession asks to open a session for the device and returns the raw response. On success it also records the
// session identifier, which the later requests of the device name in their tag.
func (s *stand) openSession(handle string) apiResponse {
	s.t.Helper()
	public := s.devices[handle].Public().(ed25519.PublicKey)
	response := s.call(http.MethodPost, "/v1/session", handle, map[string]string{
		"device_id":  "test-device",
		"device_key": base64.StdEncoding.EncodeToString(public),
	})
	if response.Error == nil {
		var result api.SessionResult
		s.decode(response, &result)
		s.tags[handle] = strconv.FormatUint(result.SessionXID, 10)
	}

	return response
}

// open generates a device key, opens a session bound to it and returns the session with the handle of the key.
func (s *stand) open() device {
	s.t.Helper()
	handle := s.newDevice()
	var result api.SessionResult
	s.decode(s.openSession(handle), &result)

	return device{SessionResult: result, Handle: handle}
}

// register registers email on the session and confirms it with the verification token from the recorded messages.
func (s *stand) register(token, email string) uint64 {
	s.t.Helper()
	a := s.call(http.MethodPost, "/v1/register", token, map[string]string{
		"email":    email,
		"password": testPassword,
	})
	if a.Status != http.StatusAccepted || a.Error != nil {
		s.t.Fatalf("register: %d %+v", a.Status, a.Error)
	}
	var result api.CompleteRegistryHandlerResult
	s.decode(s.call(http.MethodPost, "/v1/register/complete", token, map[string]string{
		"token": s.tokenFromMessages(email),
	}), &result)
	return result.UserXID
}

// enrollPasskey runs the passkey registration ceremony on the session with authenticator and returns the passkey.
func (s *stand) enrollPasskey(token string, authenticator *authtest.Authenticator, name string) (uint64, apiResponse) {
	s.t.Helper()
	begin := s.call(http.MethodPost, "/v1/enroll/passkey", token, nil)
	if begin.Error != nil {
		return 0, begin
	}
	challenge, err := authtest.Challenge(begin.Data)
	if err != nil {
		s.t.Fatal(err)
	}
	response, err := authenticator.Register(challenge)
	if err != nil {
		s.t.Fatal(err)
	}
	complete := s.call(http.MethodPost, "/v1/enroll/passkey/complete", token, map[string]any{
		"name":     name,
		"response": json.RawMessage(response),
	})
	if complete.Error != nil {
		return 0, complete
	}
	var result api.CompleteEnrollPasskeyHandlerResult
	s.decode(complete, &result)
	return result.PasskeyXID, complete
}

// loginPasskey runs the passkey login ceremony for email with authenticator and returns the final response.
func (s *stand) loginPasskey(token, email string, authenticator *authtest.Authenticator) apiResponse {
	s.t.Helper()
	begin := s.call(http.MethodPost, "/v1/auth/passkey", token, map[string]string{
		"email": email,
	})
	if begin.Error != nil {
		return begin
	}
	challenge, err := authtest.Challenge(begin.Data)
	if err != nil {
		s.t.Fatal(err)
	}
	if !gjson.ValidBytes(begin.Data) || len(gjson.GetBytes(begin.Data, "publicKey.allowCredentials").Array()) == 0 {
		s.t.Fatalf("the login options must list credentials: %s", begin.Data)
	}
	response, err := authenticator.Assert(challenge, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	return s.call(http.MethodPost, "/v1/auth/passkey/complete", token, map[string]any{
		"response": json.RawMessage(response),
	})
}

// enrollTOTP enrolls a TOTP factor on the session and returns its secret.
func (s *stand) enrollTOTP(token string) []byte {
	s.t.Helper()
	var result api.BeginEnrollTOTPHandlerResult
	s.decode(s.call(http.MethodPost, "/v1/enroll/totp", token, nil), &result)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(result.Secret)
	if err != nil {
		s.t.Fatal(err)
	}
	complete := s.call(http.MethodPost, "/v1/enroll/totp/complete", token, map[string]string{
		"code": s.code(secret),
	})
	if complete.Status != http.StatusNoContent {
		s.t.Fatalf("confirm the code generator: %d %+v", complete.Status, complete.Error)
	}
	// The confirming code used up its time step. The next code must come from the next step.
	s.clock.Advance(30 * time.Second)
	return secret
}

// code returns the one-time code of secret at the time of the stand clock.
func (s *stand) code(secret []byte) string {
	var opts totp.Options
	return opts.Code(secret, opts.Step(s.clock.Now()))
}

// loginPassword sends the password step of a login.
func (s *stand) loginPassword(token, email, password string) apiResponse {
	s.t.Helper()
	return s.call(http.MethodPost, "/v1/auth/password", token, map[string]string{
		"email":    email,
		"password": password,
	})
}

// loginTOTP sends the one-time code step of a login.
func (s *stand) loginTOTP(token, code string) apiResponse {
	s.t.Helper()
	return s.call(http.MethodPost, "/v1/auth/totp", token, map[string]string{
		"code": code,
	})
}

// authenticator returns a software authenticator that matches the relying party of the stand.
func (s *stand) authenticator() *authtest.Authenticator {
	s.t.Helper()
	authenticator, err := authtest.NewAuthenticator(testRPID, testOrigin)
	if err != nil {
		s.t.Fatal(err)
	}
	return authenticator
}

// refuses fails the test unless a is a refusal with the given HTTP status and error code.
func (s *stand) refuses(a apiResponse, status int, code string) {
	s.t.Helper()
	if a.Error == nil || a.Status != status || a.Error.Code != code {
		s.t.Fatalf("want %d %s, got %d %+v %s", status, code, a.Status, a.Error, a.Data)
	}
}

func TestPasskeyLifecycle(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("alice-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)

	authenticator := s.authenticator()
	if _, a := s.enrollPasskey(session.Handle, authenticator, "phone"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}

	var login api.AuthorizeResult
	s.decode(s.loginPasskey(session.Handle, email, authenticator), &login)
	if login.Decision != "allow" || login.Flags&es.SessionFlagAuthorized == 0 {
		t.Fatalf("login: %+v", login)
	}
	var current api.RetrieveSessionHandlerResult
	s.decode(s.call(http.MethodGet, "/v1/session", session.Handle, nil), &current)
	if current.Flags&es.SessionFlagAuthorized == 0 || current.UserXID == 0 {
		t.Fatalf("session: %+v", current)
	}
	var passkeys api.RetrievePasskeysHandlerResult
	s.decode(s.call(http.MethodGet, "/v1/passkeys", session.Handle, nil), &passkeys)
	if len(passkeys.Passkeys) != 1 || passkeys.Passkeys[0].Name != "phone" {
		t.Fatalf("passkeys: %+v", passkeys)
	}

	// A second session logs in with the same passkey. After logout its key finds no authorized session.
	again := s.open()
	s.decode(s.loginPasskey(again.Handle, email, authenticator), &login)
	if a := s.call(http.MethodDelete, "/v1/session", again.Handle, nil); a.Status != http.StatusNoContent {
		t.Fatalf("logout: %d %+v", a.Status, a.Error)
	}
	s.refuses(s.call(http.MethodGet, "/v1/session", again.Handle, nil), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
}

func TestPasswordAndTOTPLifecycle(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("bob-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	secret := s.enrollTOTP(session.Handle)

	login := s.open()
	s.refuses(s.loginPassword(login.Handle, email, "wrong password"), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
	s.refuses(s.loginTOTP(login.Handle, s.code(secret)), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
	var next api.AuthorizePasswordHandlerResult
	s.decode(s.loginPassword(login.Handle, email, testPassword), &next)
	if next.Flags&es.SessionFlagPasswordApproved == 0 {
		t.Fatalf("after the password: %+v", next)
	}
	s.refuses(s.loginTOTP(login.Handle, "000000"), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
	code := s.code(secret)
	var result api.AuthorizeResult
	s.decode(s.loginTOTP(login.Handle, code), &result)
	if result.Decision != "allow" || result.Flags&es.SessionFlagAuthorized == 0 {
		t.Fatalf("login: %+v", result)
	}

	// A one-time code works once. A replay inside the same time step fails, and a code from a later step works.
	replay := s.open()
	s.decode(s.loginPassword(replay.Handle, email, testPassword), &next)
	s.refuses(s.loginTOTP(replay.Handle, code), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
	s.clock.Advance(60 * time.Second)
	s.decode(s.loginTOTP(replay.Handle, s.code(secret)), &result)
	if result.Decision != "allow" {
		t.Fatalf("the next step: %+v", result)
	}
}

func TestUniformResponses(t *testing.T) {
	s := newStand(t)
	known := fmt.Sprintf("known-%d@example.com", time.Now().UnixNano())
	unknown := fmt.Sprintf("unknown-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, known)

	// Registration of a taken address returns the same response as a new address, so it does not reveal users.
	second := s.open()
	taken := s.call(http.MethodPost, "/v1/register", second.Handle, map[string]string{
		"email":    known,
		"password": testPassword,
	})
	fresh := s.call(http.MethodPost, "/v1/register", s.open().Handle, map[string]string{
		"email":    unknown,
		"password": testPassword,
	})
	if taken.Status != fresh.Status || string(taken.Data) != string(fresh.Data) {
		t.Fatalf("registration responses differ: %d %s vs %d %s", taken.Status, taken.Data, fresh.Status, fresh.Data)
	}
	s.refuses(s.call(http.MethodPost, "/v1/register/complete", second.Handle, map[string]string{
		"token": strings.Repeat("00", 32),
	}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")

	// Passkey options for an unknown address list credentials as for a known one, so they do not reveal users.
	for _, email := range []string{known, unknown, "nobody@example.com"} {
		a := s.call(http.MethodPost, "/v1/auth/passkey", s.open().Handle, map[string]string{
			"email": email,
		})
		if a.Error != nil || !gjson.ValidBytes(a.Data) || len(gjson.GetBytes(a.Data, "publicKey.allowCredentials").Array()) == 0 {
			t.Fatalf("passkey options for %s: %d %+v %s", email, a.Status, a.Error, a.Data)
		}
	}

	// The password step fails the same way for an unknown address and for a wrong password.
	a := s.loginPassword(s.open().Handle, "nobody@example.com", testPassword)
	b := s.loginPassword(s.open().Handle, known, "wrong password")
	if a.Status != b.Status || a.Error == nil || b.Error == nil || a.Error.Code != b.Error.Code {
		t.Fatalf("password responses differ: %+v vs %+v", a.Error, b.Error)
	}
}

func TestNoDowngrade(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("carol-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	if _, a := s.enrollPasskey(session.Handle, s.authenticator(), "key"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	s.refuses(s.loginPassword(s.open().Handle, email, testPassword), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
	s.refuses(s.call(http.MethodPost, "/v1/enroll/totp", session.Handle, nil), http.StatusForbidden, "PASSKEY_USER")
}

func TestPasskeyRefusals(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("dave-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	authenticator := s.authenticator()
	if _, a := s.enrollPasskey(session.Handle, authenticator, "key"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	cases := []struct {
		name string
		bend func()
		undo func()
	}{
		{"wrong origin", func() { authenticator.Origin = "https://evil.example" }, func() { authenticator.Origin = testOrigin }},
		{"wrong RP ID hash", func() { authenticator.RPID = "evil.example" }, func() { authenticator.RPID = testRPID }},
		{"missing user verification", func() { authenticator.UserVerified = false }, func() { authenticator.UserVerified = true }},
		{"changed backup-eligible flag", func() { authenticator.BackupEligible = false; authenticator.BackedUp = false }, func() { authenticator.BackupEligible = true; authenticator.BackedUp = true }},
	}
	for _, c := range cases {
		c.bend()
		s.refuses(s.loginPasskey(s.open().Handle, email, authenticator), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
		c.undo()
	}
	var login api.AuthorizeResult
	s.decode(s.loginPasskey(s.open().Handle, email, authenticator), &login)

	// A replayed assertion fails. The first success consumes the challenge of the session.
	replay := s.open()
	begin := s.call(http.MethodPost, "/v1/auth/passkey", replay.Handle, map[string]string{
		"email": email,
	})
	challenge, err := authtest.Challenge(begin.Data)
	if err != nil {
		t.Fatal(err)
	}
	response, err := authenticator.Assert(challenge, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.decode(s.call(http.MethodPost, "/v1/auth/passkey/complete", replay.Handle, map[string]any{
		"response": json.RawMessage(response),
	}), &login)
	s.refuses(s.call(http.MethodPost, "/v1/auth/passkey/complete", replay.Handle, map[string]any{
		"response": json.RawMessage(response),
	}), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")

	// A challenge that expired is refused even with a valid assertion.
	expired := s.open()
	begin = s.call(http.MethodPost, "/v1/auth/passkey", expired.Handle, map[string]string{
		"email": email,
	})
	challenge, err = authtest.Challenge(begin.Data)
	if err != nil {
		t.Fatal(err)
	}
	response, err = authenticator.Assert(challenge, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.clock.Advance(3 * time.Minute)
	s.refuses(s.call(http.MethodPost, "/v1/auth/passkey/complete", expired.Handle, map[string]any{
		"response": json.RawMessage(response),
	}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")

	// A body with an unknown field is rejected, so a client cannot send hidden data.
	s.refuses(s.call(http.MethodPost, "/v1/session", session.Handle, map[string]string{
		"device_id": "x",
		"extra":     "field",
	}), http.StatusBadRequest, "UNKNOWN_BODY")
}

func TestCounterRule(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("erin-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	authenticator := s.authenticator()
	authenticator.FixedCounter = true
	if _, a := s.enrollPasskey(session.Handle, authenticator, "synced"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	var login api.AuthorizeResult
	for range 2 {
		s.decode(s.loginPasskey(s.open().Handle, email, authenticator), &login)
	}
	authenticator.FixedCounter = false
	authenticator.Counter = 10
	s.decode(s.loginPasskey(s.open().Handle, email, authenticator), &login)
	authenticator.Counter = 10
	s.refuses(s.loginPasskey(s.open().Handle, email, authenticator), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
	authenticator.Counter = 50
	s.refuses(s.loginPasskey(s.open().Handle, email, authenticator), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
	found := false
	for _, sent := range s.messages.Sent() {
		if sent.Message.Email == email && sent.Op&es.SendPasskeyDisabled != 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("the user must be told about the disabled passkey")
	}
}

// removePasskey runs the two steps of the confirmed removal of a passkey: it asks for the options, signs their challenge
// with the authenticator, and sends the assertion. It returns the answer of the last step, or the refusal of the first.
func (s *stand) removePasskey(handle string, passkeyXID uint64, authenticator *authtest.Authenticator) apiResponse {
	s.t.Helper()
	begin := s.call(http.MethodPost, fmt.Sprintf("/v1/passkeys/%d/removal", passkeyXID), handle, nil)
	if begin.Error != nil {
		return begin
	}
	challenge, err := authtest.Challenge(begin.Data)
	if err != nil {
		s.t.Fatal(err)
	}
	response, err := authenticator.Assert(challenge, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	return s.call(http.MethodPost, fmt.Sprintf("/v1/passkeys/%d/removal/confirm", passkeyXID), handle, map[string]any{
		"response": json.RawMessage(response),
	})
}

func TestFreshAuthentication(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("frank-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	authenticator := s.authenticator()
	first, a := s.enrollPasskey(session.Handle, authenticator, "first")
	if a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	login := s.open()
	var result api.AuthorizeResult
	s.decode(s.loginPasskey(login.Handle, email, authenticator), &result)
	s.refuses(s.removePasskey(login.Handle, first, authenticator), http.StatusForbidden, "LAST_FACTOR")

	second := s.authenticator()
	if _, a := s.enrollPasskey(login.Handle, second, "second"); a.Error != nil {
		t.Fatalf("enroll a second passkey: %+v", a.Error)
	}
	s.clock.Advance(6 * time.Minute)
	s.refuses(s.call(http.MethodPost, "/v1/enroll/passkey", login.Handle, nil), http.StatusUnauthorized, "STALE_AUTHENTICATION")
	s.refuses(s.call(http.MethodPost, fmt.Sprintf("/v1/passkeys/%d/removal", first), login.Handle, nil), http.StatusUnauthorized, "STALE_AUTHENTICATION")
	s.decode(s.loginPasskey(login.Handle, email, second), &result)
	if a := s.removePasskey(login.Handle, first, second); a.Status != http.StatusNoContent {
		t.Fatalf("remove after a fresh login: %d %+v", a.Status, a.Error)
	}
	s.refuses(s.loginPasskey(s.open().Handle, email, authenticator), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
}

func TestTOTPCiphertextMovedBetweenUsers(t *testing.T) {
	s := newStand(t)
	owner := fmt.Sprintf("owner-%d@example.com", time.Now().UnixNano())
	thief := fmt.Sprintf("thief-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, owner)
	secret := s.enrollTOTP(session.Handle)
	other := s.open()
	s.register(other.Handle, thief)
	s.enrollTOTP(other.Handle)

	ownerRow, err := s.env.UserReader.ReadOne(t.Context(), es.User{Email: owner}, 0)
	if err != nil {
		t.Fatal(err)
	}
	thiefRow, err := s.env.UserReader.ReadOne(t.Context(), es.User{Email: thief}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.env.UserWriter.WriteOne(t.Context(), es.User{
		ID:             thiefRow.ID,
		TOTPCiphertext: ownerRow.TOTPCiphertext,
	}, es.WriteUpdate); err != nil {
		t.Fatal(err)
	}
	login := s.open()
	var next api.AuthorizePasswordHandlerResult
	s.decode(s.loginPassword(login.Handle, thief, testPassword), &next)
	s.refuses(s.loginTOTP(login.Handle, s.code(secret)), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
}

func TestAdvisorOnlyRaises(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("grace-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	authenticator := s.authenticator()
	if _, a := s.enrollPasskey(session.Handle, authenticator, "key"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	var login api.AuthorizeResult
	s.advisor.Raw = []byte(`{"risk_level":"low","reasons":["none"],"summary":"fine","approve":true}`)
	s.decode(s.loginPasskey(s.open().Handle, email, authenticator), &login)
	if login.Decision != "allow" {
		t.Fatalf("hostile advice: %+v", login)
	}
	s.advisor.Raw = nil
	s.advisor.Advice = ai.Advice{
		Level: ai.LevelHigh,
	}
	s.decode(s.loginPasskey(s.open().Handle, email, authenticator), &login)
	if login.Decision != "limit" || login.Flags&es.SessionFlagLimited == 0 {
		t.Fatalf("a high advice on a low login: %+v", login)
	}
	last := s.advisor.Last()
	if last.Pseudonym == "" || strings.Contains(last.Pseudonym, "@") || last.Factor != es.FactorPasskey {
		t.Fatalf("the summary must be minimized: %+v", last)
	}
}

func TestRecovery(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("heidi-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	authenticator := s.authenticator()
	if _, a := s.enrollPasskey(session.Handle, authenticator, "key"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	var codes api.IssueRecoveryCodesHandlerResult
	s.decode(s.call(http.MethodPost, "/v1/enroll/recovery", session.Handle, nil), &codes)
	if len(codes.Codes) != api.RecoveryCodeCount {
		t.Fatalf("codes: %+v", codes)
	}

	lost := s.open()
	s.refuses(s.call(http.MethodPost, "/v1/auth/recovery", lost.Handle, map[string]string{
		"email": email,
		"code":  "AAAAAAAAAAAAAAAA",
	}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
	var next api.AuthorizeRecoveryHandlerResult
	s.decode(s.call(http.MethodPost, "/v1/auth/recovery", lost.Handle, map[string]string{
		"email": email,
		"code":  codes.Codes[0],
	}), &next)
	if next.Flags&es.SessionFlagRecoveryApproved == 0 {
		t.Fatalf("recovery: %+v", next)
	}
	// A recovery code does not log in. It allows one enrollment and works only once.
	s.refuses(s.call(http.MethodGet, "/v1/passkeys", lost.Handle, nil), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
	replacement := s.authenticator()
	if _, a := s.enrollPasskey(lost.Handle, replacement, "replacement"); a.Error != nil {
		t.Fatalf("enroll after recovery: %+v", a.Error)
	}
	s.refuses(s.call(http.MethodPost, "/v1/auth/recovery", s.open().Handle, map[string]string{
		"email": email,
		"code":  codes.Codes[0],
	}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
	var login api.AuthorizeResult
	s.decode(s.loginPasskey(s.open().Handle, email, replacement), &login)
	if login.Decision != "allow" {
		t.Fatalf("login with the replacement: %+v", login)
	}
}

func TestRequestSignature(t *testing.T) {
	s := newStand(t)
	session := s.open()
	_, other, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := s.devices[session.Handle]
	now := s.clock.Now().Unix()

	// signed sends a request that signer signs with the creation time created and the given nonce.
	signed := func(method, path string, body []byte, signer ed25519.PrivateKey, created int64, nonce string) apiResponse {
		request := s.newRequest(method, path, body)
		s.sign(request, body, signer, created, nonce, s.tags[session.Handle])
		// The request always names the device key. A test case changes only the signature.
		return s.do(request)
	}

	// A request without signature fields is refused.
	s.refuses(s.do(s.newRequest(http.MethodGet, "/v1/session", nil)), http.StatusUnauthorized, "NO_HEADER_REQUEST_SIGNATURE")

	// A valid request passes. The same nonce a second time is a replay.
	if a := signed(http.MethodGet, "/v1/session", nil, key, now, "once"); a.Error != nil {
		t.Fatalf("a valid request: %+v", a.Error)
	}
	s.refuses(signed(http.MethodGet, "/v1/session", nil, key, now, "once"), http.StatusUnauthorized, "INVALID_REQUEST_SIGNATURE")

	// A key that no session uses finds no session.
	s.refuses(signed(http.MethodGet, "/v1/session", nil, other, now, "unknown"), http.StatusUnauthorized, "NOT_FOUND_SESSION")

	// A request outside the time window in either direction fails, and so does one whose body changed after signing.
	window := int64(auth.DefaultRequestWindow / time.Second)
	s.refuses(signed(http.MethodGet, "/v1/session", nil, key, now-window-5, "old"), http.StatusUnauthorized, "STALE_REQUEST_TIME")
	s.refuses(signed(http.MethodGet, "/v1/session", nil, key, now+window+5, "future"), http.StatusUnauthorized, "STALE_REQUEST_TIME")
	changed := s.newRequest(http.MethodPost, "/v1/register", []byte(`{"email":"b@example.com","password":"another password"}`))
	s.sign(changed, []byte(`{"email":"a@example.com","password":"another password"}`), key, now, "changed", s.tags[session.Handle])
	s.refuses(s.do(changed), http.StatusUnauthorized, "INVALID_REQUEST_SIGNATURE")

	// A signature covers the path, so it is not valid for another path.
	moved := s.newRequest(http.MethodGet, "/v1/passkeys", nil)
	same := s.newRequest(http.MethodGet, "/v1/session", nil)
	s.sign(same, nil, key, now, "moved", s.tags[session.Handle])
	moved.Header = same.Header
	s.refuses(s.do(moved), http.StatusUnauthorized, "INVALID_REQUEST_SIGNATURE")

	// A session needs a device key, and the request that opens it must be signed with that key.
	s.refuses(s.call(http.MethodPost, "/v1/session", session.Handle, map[string]string{
		"device_id": "x",
	}), http.StatusBadRequest, "NO_BODY_DEVICE_KEY")
	s.refuses(s.call(http.MethodPost, "/v1/session", session.Handle, map[string]string{
		"device_id":  "x",
		"device_key": "AAAA",
	}), http.StatusBadRequest, "MALFORMED_BODY_DEVICE_KEY")
	body := []byte(`{"device_id":"x","device_key":"` + base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) + `"}`)
	opening := s.newRequest(http.MethodPost, "/v1/session", body)
	s.sign(opening, body, other, now, "opening", "")
	s.refuses(s.do(opening), http.StatusUnauthorized, "INVALID_REQUEST_SIGNATURE")
}

func TestDiscoverableLogin(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("carol-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	authenticator := s.authenticator()
	if _, a := s.enrollPasskey(session.Handle, authenticator, "laptop"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	user, err := s.env.UserReader.ReadOne(context.Background(), es.User{Email: email}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// discover runs a login without an address. The options list no credentials. The user handle of the passkey names
	// the user.
	discover := func(handle []byte) apiResponse {
		login := s.open()
		begin := s.call(http.MethodPost, "/v1/auth/passkey", login.Handle, map[string]string{})
		if begin.Error != nil {
			t.Fatalf("begin: %+v", begin.Error)
		}
		if len(gjson.GetBytes(begin.Data, "publicKey.allowCredentials").Array()) != 0 {
			t.Fatalf("a discoverable login must list no credentials: %s", begin.Data)
		}
		challenge, err := authtest.Challenge(begin.Data)
		if err != nil {
			t.Fatal(err)
		}
		response, err := authenticator.Assert(challenge, handle)
		if err != nil {
			t.Fatal(err)
		}
		return s.call(http.MethodPost, "/v1/auth/passkey/complete", login.Handle, map[string]any{
			"response": json.RawMessage(response),
		})
	}

	var result api.AuthorizeResult
	s.decode(discover(user.Handle), &result)
	if result.UserXID != user.UserXID || result.Flags&es.SessionFlagAuthorized == 0 {
		t.Fatalf("login: %+v", result)
	}

	// A response with no user handle, or with a handle that matches no user, fails like any bad assertion.
	s.refuses(discover(nil), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
	s.refuses(discover([]byte("not a handle that exists")), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
}

// openAnother opens a second session with the key of an existing device, as a second tab of the same browser does. It
// returns the session and a new handle that signs with the shared key and names the new session.
func (s *stand) openAnother(existing device) device {
	s.t.Helper()
	key := s.devices[existing.Handle]
	handle := existing.Handle + "-tab"
	s.devices[handle] = key
	var result api.SessionResult
	s.decode(s.call(http.MethodPost, "/v1/session", handle, map[string]string{
		"device_id":  "test-device",
		"device_key": base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
	}), &result)
	s.tags[handle] = strconv.FormatUint(result.SessionXID, 10)
	return device{SessionResult: result, Handle: handle}
}

// TestSessionsOfOneKey proves that two sessions with the same device key, such as two tabs of one browser, do not
// disturb each other, and that a request cannot use a session that belongs to another key.
func TestSessionsOfOneKey(t *testing.T) {
	s := newStand(t)
	first := s.open()
	second := s.openAnother(first)
	if first.SessionXID == second.SessionXID {
		t.Fatal("two sessions must have two identifiers")
	}

	// Each tab works on its own session. A step in one does not show in the other.
	email := fmt.Sprintf("gina-%d@example.com", time.Now().UnixNano())
	s.register(first.Handle, email)
	var one, two api.RetrieveSessionHandlerResult
	s.decode(s.call(http.MethodGet, "/v1/session", first.Handle, nil), &one)
	s.decode(s.call(http.MethodGet, "/v1/session", second.Handle, nil), &two)
	if one.SessionXID != first.SessionXID || two.SessionXID != second.SessionXID {
		t.Fatalf("each request must reach the session it names: %+v %+v", one, two)
	}
	if one.Flags == two.Flags {
		t.Fatalf("a step in one session must not show in the other: %x %x", one.Flags, two.Flags)
	}

	// Logging out one tab leaves the other working.
	if a := s.call(http.MethodDelete, "/v1/session", first.Handle, nil); a.Status != http.StatusNoContent {
		t.Fatalf("logout: %d %+v", a.Status, a.Error)
	}
	s.refuses(s.call(http.MethodGet, "/v1/session", first.Handle, nil), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
	s.decode(s.call(http.MethodGet, "/v1/session", second.Handle, nil), &two)

	// A device cannot name the session of another device, even with a valid signature of its own.
	stranger := s.open()
	trespass := s.newRequest(http.MethodGet, "/v1/session", nil)
	s.sign(trespass, nil, s.devices[stranger.Handle], s.clock.Now().Unix(), s.nextNonce(), s.tags[second.Handle])
	s.refuses(s.do(trespass), http.StatusUnauthorized, "NOT_FOUND_SESSION")

	// A request of a session without the tag is refused.
	untagged := s.newRequest(http.MethodGet, "/v1/session", nil)
	s.sign(untagged, nil, s.devices[second.Handle], s.clock.Now().Unix(), s.nextNonce(), "")
	s.refuses(s.do(untagged), http.StatusUnauthorized, "INVALID_REQUEST_SIGNATURE")
}
