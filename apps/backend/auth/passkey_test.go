package auth

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/tidwall/gjson"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/authtest"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

var testUser = es.User{
	ID:     1,
	Email:  "alice@example.com",
	Handle: []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
}

func newRelyingParty(t *testing.T) *RelyingParty {
	t.Helper()

	rp, err := NewRelyingParty(RelyingPartyOptions{
		RPID:    testRPID,
		RPName:  "Vault Login",
		Origins: []string{testOrigin},
	})
	if err != nil {
		t.Fatal(err)
	}

	return rp
}

// register runs the full registration ceremony with authenticator and returns the new passkey.
func register(t *testing.T, rp *RelyingParty, authenticator *authtest.Authenticator) es.Passkey {
	t.Helper()

	options, state, err := rp.BeginRegistration(testUser, nil)
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := authtest.Challenge(options)
	if err != nil {
		t.Fatal(err)
	}

	response, err := authenticator.Register(challenge)
	if err != nil {
		t.Fatal(err)
	}

	passkey, err := rp.FinishRegistration(testUser, state, response)
	if err != nil {
		t.Fatal(err)
	}

	passkey.UserID = testUser.ID
	return passkey
}

// login runs a login ceremony with authenticator against passkeys and returns the result of FinishLogin.
func login(t *testing.T, rp *RelyingParty, authenticator *authtest.Authenticator, passkeys []es.Passkey) (es.Passkey, bool, error) {
	t.Helper()
	ids := make([][]byte, 0, len(passkeys))
	for _, passkey := range passkeys {
		ids = append(ids, passkey.CredentialID)
	}

	options, state, err := rp.BeginLogin(testUser.Handle, ids)
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := authtest.Challenge(options)
	if err != nil {
		t.Fatal(err)
	}

	response, err := authenticator.Assert(challenge, testUser.Handle)
	if err != nil {
		t.Fatal(err)
	}

	return rp.FinishLogin(testUser, passkeys, state, response)
}

func TestRegisterAndLogin(t *testing.T) {
	rp := newRelyingParty(t)

	authenticator, err := authtest.NewAuthenticator(testRPID, testOrigin)
	if err != nil {
		t.Fatal(err)
	}

	passkey := register(t, rp, authenticator)
	if string(passkey.CredentialID) != string(authenticator.CredentialID) || len(passkey.PublicKey) == 0 {
		t.Fatalf("registered: %+v", passkey)
	}

	if passkey.Flags&es.PasskeyFlagUserVerified == 0 || passkey.Flags&es.PasskeyFlagBackupEligible == 0 || passkey.Flags&es.PasskeyFlagBackedUp == 0 {
		t.Fatalf("flags: %b", passkey.Flags)
	}

	if passkey.Transports != es.TransportInternal || passkey.AttestationFormat != "none" {
		t.Fatalf("transports %v format %q", passkey.Transports.Names(), passkey.AttestationFormat)
	}

	authenticator.Counter = 5

	signed, regressed, err := login(t, rp, authenticator, []es.Passkey{passkey})
	if err != nil || regressed || signed.SignCount != 5 {
		t.Fatalf("login: %+v, regressed %v, %v", signed, regressed, err)
	}

	signed, regressed, err = login(t, rp, authenticator, []es.Passkey{signed})
	if err != nil || regressed || signed.SignCount != 6 {
		t.Fatalf("second login: %+v, regressed %v, %v", signed, regressed, err)
	}
}

func TestLoginRefusals(t *testing.T) {
	rp := newRelyingParty(t)
	cases := []struct {
		name string
		bend func(a *authtest.Authenticator)
	}{
		{"wrong origin", func(a *authtest.Authenticator) { a.Origin = "https://evil.example" }},
		{"wrong RP ID hash", func(a *authtest.Authenticator) { a.RPID = "evil.example" }},
		{"missing user verification", func(a *authtest.Authenticator) { a.UserVerified = false }},
		{"changed backup-eligible flag", func(a *authtest.Authenticator) { a.BackupEligible = false; a.BackedUp = false }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			authenticator, err := authtest.NewAuthenticator(testRPID, testOrigin)
			if err != nil {
				t.Fatal(err)
			}

			passkey := register(t, rp, authenticator)
			c.bend(authenticator)

			if _, _, err := login(t, rp, authenticator, []es.Passkey{passkey}); !errors.Is(err, ErrVerify) {
				t.Fatalf("%v, want ErrVerify", err)
			}
		})
	}
}

func TestLoginRefusesForeignCredential(t *testing.T) {
	rp := newRelyingParty(t)

	own, err := authtest.NewAuthenticator(testRPID, testOrigin)
	if err != nil {
		t.Fatal(err)
	}

	passkey := register(t, rp, own)

	other, err := authtest.NewAuthenticator(testRPID, testOrigin)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := login(t, rp, other, []es.Passkey{passkey}); !errors.Is(err, ErrVerify) {
		t.Fatalf("an assertion by another key: %v, want ErrVerify", err)
	}

	if _, _, err := login(t, rp, own, []es.Passkey{{
		Flags:        passkey.Flags | es.PasskeyFlagDisabled,
		CredentialID: passkey.CredentialID,
		PublicKey:    passkey.PublicKey,
	}}); !errors.Is(err, ErrVerify) {
		t.Fatalf("a disabled passkey: %v, want ErrVerify", err)
	}
}

func TestChallengeIsSingleUseAndExpires(t *testing.T) {
	rp := newRelyingParty(t)

	authenticator, err := authtest.NewAuthenticator(testRPID, testOrigin)
	if err != nil {
		t.Fatal(err)
	}

	passkey := register(t, rp, authenticator)

	options, state, err := rp.BeginLogin(testUser.Handle, [][]byte{passkey.CredentialID})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := authtest.Challenge(options)
	if err != nil {
		t.Fatal(err)
	}

	response, err := authenticator.Assert(challenge, testUser.Handle)
	if err != nil {
		t.Fatal(err)
	}

	signed, _, err := rp.FinishLogin(testUser, []es.Passkey{passkey}, state, response)
	if err != nil {
		t.Fatal(err)
	}

	// An assertion for another ceremony is a replay. Its challenge does not match the state.
	_, otherState, err := rp.BeginLogin(testUser.Handle, [][]byte{passkey.CredentialID})
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := rp.FinishLogin(testUser, []es.Passkey{signed}, otherState, response); !errors.Is(err, ErrVerify) {
		t.Fatalf("a replayed assertion: %v, want ErrVerify", err)
	}

	// An expired state is refused even when the response is valid.
	var session webauthn.SessionData

	if err := json.Unmarshal(state, &session); err != nil {
		t.Fatal(err)
	}

	session.Expires = time.Now().Add(-time.Minute)

	expired, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := rp.FinishLogin(testUser, []es.Passkey{signed}, expired, response); !errors.Is(err, ErrVerify) {
		t.Fatalf("an expired challenge: %v, want ErrVerify", err)
	}
}

func TestCounterRule(t *testing.T) {
	rp := newRelyingParty(t)

	authenticator, err := authtest.NewAuthenticator(testRPID, testOrigin)
	if err != nil {
		t.Fatal(err)
	}

	passkey := register(t, rp, authenticator)

	// Synced passkeys report a zero counter every time. Two zeros are not a regression.
	authenticator.FixedCounter = true

	signed, regressed, err := login(t, rp, authenticator, []es.Passkey{passkey})
	if err != nil || regressed || signed.SignCount != 0 {
		t.Fatalf("zero counters: %+v, regressed %v, %v", signed, regressed, err)
	}

	// A growing counter is fine. A repeated counter is a regression, and the caller decides what to do with it.
	authenticator.FixedCounter = false
	authenticator.Counter = 10

	signed, regressed, err = login(t, rp, authenticator, []es.Passkey{signed})
	if err != nil || regressed || signed.SignCount != 10 {
		t.Fatalf("a grown counter: %+v, regressed %v, %v", signed, regressed, err)
	}

	authenticator.Counter = 10
	stored := signed
	signed, regressed, err = login(t, rp, authenticator, []es.Passkey{stored})
	if err != nil || !regressed || signed.SignCount != stored.SignCount {
		t.Fatalf("a repeated counter: %+v, regressed %v, %v", signed, regressed, err)
	}

	authenticator.Counter = 3

	_, regressed, err = login(t, rp, authenticator, []es.Passkey{stored})
	if err != nil || !regressed {
		t.Fatalf("a smaller counter: regressed %v, %v", regressed, err)
	}
}

func TestRegistrationExcludesExistingPasskeys(t *testing.T) {
	rp := newRelyingParty(t)

	authenticator, err := authtest.NewAuthenticator(testRPID, testOrigin)
	if err != nil {
		t.Fatal(err)
	}

	passkey := register(t, rp, authenticator)

	options, _, err := rp.BeginRegistration(testUser, []es.Passkey{passkey})
	if err != nil {
		t.Fatal(err)
	}

	if !gjson.ValidBytes(options) {
		t.Fatalf("options: %s", options)
	}

	exclusions := gjson.GetBytes(options, "publicKey.excludeCredentials").Array()
	if len(exclusions) != 1 {
		t.Fatalf("exclusions: %v", exclusions)
	}

	if gjson.GetBytes(options, "publicKey.authenticatorSelection.userVerification").String() != "required" || gjson.GetBytes(options, "publicKey.attestation").String() != "none" {
		t.Fatalf("options: %s", options)
	}
}
