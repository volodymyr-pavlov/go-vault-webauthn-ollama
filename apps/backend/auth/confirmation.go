package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// confirmationDomain starts the hash of a confirmation challenge, so that the hash cannot be the challenge of another
// ceremony.
const confirmationDomain = "confirmation-v1"

// ConfirmationAction names the sensitive action that a confirmation covers. The name goes into the challenge, so an
// assertion for one action never confirms another.
type ConfirmationAction string

// The actions that a confirmation can cover.
const (
	// ConfirmationActionDeleteAccount is the action of the deletion of an account. The challenge of the confirmation
	// covers this name and the external ID of the user.
	ConfirmationActionDeleteAccount ConfirmationAction = "delete_account"

	// ConfirmationActionRemovePasskey is the action of the removal of a passkey. The challenge covers this name and the
	// external ID of the passkey.
	ConfirmationActionRemovePasskey ConfirmationAction = "remove_passkey"
)

// confirmation is the state that [RelyingParty.BeginConfirmation] keeps for the caller. It holds the action and its
// target next to the state of the ceremony, so that the server verifies the assertion for this action and no other.
type confirmation struct {
	Action ConfirmationAction `json:"action"`
	Target uint64             `json:"target"`
	State  json.RawMessage    `json:"state"`
}

// BeginConfirmation starts the confirmation of a sensitive action with a fresh passkey assertion. It returns the options
// for the browser, which name the usable passkeys of the user, and the encoded state for the caller to keep on the
// session.
//
// The challenge is the SHA-256 hash of a domain string, 32 random bytes, the action and its target. So the assertion
// that the passkey signs covers the action and the target. The state holds the action and the target too, and
// [RelyingParty.FinishConfirmation] accepts the assertion for no other action.
//
// It returns an error if the library cannot make the options.
func (rp *RelyingParty) BeginConfirmation(user es.User, passkeys []es.Passkey, action ConfirmationAction, target uint64) (options, state []byte, err error) {
	nonce := make([]byte, 32)

	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("make the nonce: %w", err)
	}

	challenge := confirmationChallenge(nonce, action, target)

	request, session, err := rp.web.BeginLogin(account{
		handle:      user.Handle,
		name:        user.Email,
		credentials: credentialsOf(passkeys),
	}, webauthn.WithUserVerification(protocol.VerificationRequired), func(request *protocol.PublicKeyCredentialRequestOptions) error {
		request.Challenge = challenge

		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("begin the confirmation: %w", err)
	}

	options, err = json.Marshal(request)
	if err != nil {
		return nil, nil, fmt.Errorf("encode the options: %w", err)
	}

	inner, err := json.Marshal(session)
	if err != nil {
		return nil, nil, fmt.Errorf("encode the state: %w", err)
	}

	state, err = json.Marshal(confirmation{
		Action: action,
		Target: target,
		State:  inner,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("encode the confirmation: %w", err)
	}

	return options, state, nil
}

// FinishConfirmation checks the assertion of the browser for the action and the target. The state is the one that
// [RelyingParty.BeginConfirmation] returned. It returns the passkey that signed, as [RelyingParty.FinishLogin] does,
// and whether its counter went back.
//
// It returns [ErrVerify] if the state was made for another action or another target, or if the assertion does not
// verify. The cause is joined to it. It returns another error if the state cannot be decoded.
func (rp *RelyingParty) FinishConfirmation(user es.User, passkeys []es.Passkey, state []byte, action ConfirmationAction, target uint64, response []byte) (es.Passkey, bool, error) {
	var kept confirmation

	if err := json.Unmarshal(state, &kept); err != nil {
		return es.Passkey{}, false, fmt.Errorf("decode the confirmation: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(kept.Action), []byte(action)) != 1 || kept.Target != target {
		return es.Passkey{}, false, ErrVerify
	}

	return rp.FinishLogin(user, passkeys, kept.State, response)
}

// confirmationChallenge returns the challenge of a confirmation: the SHA-256 hash of the domain, the nonce, the action
// and the target, each with a fixed width or a length prefix.
func confirmationChallenge(nonce []byte, action ConfirmationAction, target uint64) []byte {
	var message []byte

	field := func(b []byte) {
		message = binary.BigEndian.AppendUint64(message, uint64(len(b)))
		message = append(message, b...)
	}

	field([]byte(confirmationDomain))
	field(nonce)
	field([]byte(action))
	message = binary.BigEndian.AppendUint64(message, target)

	sum := sha256.Sum256(message)

	return sum[:]
}
