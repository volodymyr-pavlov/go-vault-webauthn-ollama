package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/authtest"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// TestConfirmationChallengeCoversTheActionAndTheTarget proves that the challenge changes with the nonce, the action
// and the target, so a passkey that signs it signs this action on this target.
func TestConfirmationChallengeCoversTheActionAndTheTarget(t *testing.T) {
	nonce := bytes.Repeat([]byte{1}, 32)

	base := confirmationChallenge(nonce, ConfirmationActionRemovePasskey, 7)

	if len(base) != 32 {
		t.Fatalf("a challenge has 32 bytes, got %d", len(base))
	}

	others := map[string][]byte{
		"another nonce":  confirmationChallenge(bytes.Repeat([]byte{2}, 32), ConfirmationActionRemovePasskey, 7),
		"another action": confirmationChallenge(nonce, ConfirmationAction("remove_totp"), 7),
		"another target": confirmationChallenge(nonce, ConfirmationActionRemovePasskey, 8),
	}
	for name, other := range others {
		if bytes.Equal(base, other) {
			t.Errorf("%s must give another challenge", name)
		}
	}

	// A concatenation must not give the same challenge: the fields have prefixes of their length.
	if bytes.Equal(confirmationChallenge(nonce, "ab", 1), confirmationChallenge(nonce, "a", 1)) {
		t.Error("two actions must give two challenges")
	}
}

// TestConfirmationAcceptsOnlyItsActionAndTarget proves that a confirmation finishes with a passkey assertion for the
// action and the target that it began with, refuses another action or target, and refuses a second use of a state
// whose challenge the authenticator did not sign.
func TestConfirmationAcceptsOnlyItsActionAndTarget(t *testing.T) {
	rp, err := NewRelyingParty(RelyingPartyOptions{
		RPID:    "localhost",
		RPName:  "Test",
		Origins: []string{"http://localhost:8080"},
	})
	if err != nil {
		t.Fatal(err)
	}

	authenticator, err := authtest.NewAuthenticator("localhost", "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}

	user := es.User{
		ID:     1,
		Handle: bytes.Repeat([]byte{9}, 64),
		Email:  "a@example.com",
	}

	registration, state, err := rp.BeginRegistration(user, nil)
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := authtest.Challenge(registration)
	if err != nil {
		t.Fatal(err)
	}

	response, err := authenticator.Register(challenge)
	if err != nil {
		t.Fatal(err)
	}

	passkey, err := rp.FinishRegistration(user, state, response)
	if err != nil {
		t.Fatal(err)
	}

	passkey.Flags |= es.PasskeyFlagUserVerified
	passkeys := []es.Passkey{passkey}

	options, kept, err := rp.BeginConfirmation(user, passkeys, ConfirmationActionRemovePasskey, 7)
	if err != nil {
		t.Fatal(err)
	}

	var parsed struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}

	if err := json.Unmarshal(options, &parsed); err != nil || parsed.PublicKey.Challenge == "" {
		t.Fatalf("the options must carry a challenge: %v %s", err, options)
	}

	assertionChallenge, err := authtest.Challenge(options)
	if err != nil {
		t.Fatal(err)
	}

	assertion, err := authenticator.Assert(assertionChallenge, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Another action, and another target, are refused before the assertion is looked at.
	if _, _, err := rp.FinishConfirmation(user, passkeys, kept, ConfirmationAction("remove_totp"), 7, assertion); !errors.Is(err, ErrVerify) {
		t.Fatalf("another action: %v", err)
	}

	if _, _, err := rp.FinishConfirmation(user, passkeys, kept, ConfirmationActionRemovePasskey, 8, assertion); !errors.Is(err, ErrVerify) {
		t.Fatalf("another target: %v", err)
	}

	// The same action and target finish.
	if _, _, err := rp.FinishConfirmation(user, passkeys, kept, ConfirmationActionRemovePasskey, 7, assertion); err != nil {
		t.Fatalf("the confirmation of its own action: %v", err)
	}

	// An assertion for the challenge of another confirmation is refused.
	_, otherKept, err := rp.BeginConfirmation(user, passkeys, ConfirmationActionRemovePasskey, 7)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := rp.FinishConfirmation(user, passkeys, otherKept, ConfirmationActionRemovePasskey, 7, assertion); !errors.Is(err, ErrVerify) {
		t.Fatalf("an assertion for another challenge: %v", err)
	}
}
