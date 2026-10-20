//go:build integration

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/authtest"
)

// TestConfirmedRemovalIsBoundToItsPasskeyAndWorksOnce proves that the removal of a passkey needs a fresh passkey
// assertion for the challenge that was bound to that action and that passkey: the challenge works for no other passkey,
// not twice, and not after it expired, and a refusal does not remove anything.
func TestConfirmedRemovalIsBoundToItsPasskeyAndWorksOnce(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("confirm-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	first, second := s.authenticator(), s.authenticator()
	firstXID, a := s.enrollPasskey(session.Handle, first, "first")
	if a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	secondXID, a := s.enrollPasskey(session.Handle, second, "second")
	if a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	login := s.open()
	var result api.AuthorizeResult
	s.decode(s.loginPasskey(login.Handle, email, first), &result)

	// assert signs the challenge of the options with the authenticator and returns the confirm body.
	assert := func(begin apiResponse, authenticator *authtest.Authenticator) map[string]any {
		challenge, err := authtest.Challenge(begin.Data)
		if err != nil {
			t.Fatal(err)
		}
		response, err := authenticator.Assert(challenge, nil)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"response": json.RawMessage(response)}
	}
	removalPath := func(xid uint64) string { return fmt.Sprintf("/v1/passkeys/%d/removal", xid) }

	// A confirmation without a begin is refused.
	s.refuses(s.call(http.MethodPost, removalPath(secondXID)+"/confirm", login.Handle, map[string]any{
		"response": json.RawMessage(`{}`),
	}), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")

	// The challenge bound to the removal of the second passkey does not remove the first one.
	begin := s.call(http.MethodPost, removalPath(secondXID), login.Handle, nil)
	if begin.Error != nil {
		t.Fatalf("begin: %+v", begin.Error)
	}
	body := assert(begin, first)
	s.refuses(s.call(http.MethodPost, removalPath(firstXID)+"/confirm", login.Handle, body), http.StatusUnauthorized, "AUTHENTICATION_FAILED")

	// The refusal used the challenge up, so the right passkey cannot reuse it.
	s.refuses(s.call(http.MethodPost, removalPath(secondXID)+"/confirm", login.Handle, body), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")

	// An expired challenge is refused.
	begin = s.call(http.MethodPost, removalPath(secondXID), login.Handle, nil)
	body = assert(begin, first)
	s.clock.Advance(3 * time.Minute)
	s.decode(s.loginPasskey(s.open().Handle, email, first), &result)
	s.refuses(s.call(http.MethodPost, removalPath(secondXID)+"/confirm", login.Handle, body), http.StatusUnauthorized, "AUTHENTICATION_FAILED")

	// Both passkeys are still there after the refusals.
	var list api.RetrievePasskeysHandlerResult
	fresh := s.open()
	s.decode(s.loginPasskey(fresh.Handle, email, first), &result)
	s.decode(s.call(http.MethodGet, "/v1/passkeys", fresh.Handle, nil), &list)
	if len(list.Passkeys) != 2 {
		t.Fatalf("the refusals must remove nothing: %+v", list.Passkeys)
	}

	// The right passkey, confirmed, is removed once. A replay of the same assertion finds no challenge.
	begin = s.call(http.MethodPost, removalPath(secondXID), fresh.Handle, nil)
	body = assert(begin, first)
	if a := s.call(http.MethodPost, removalPath(secondXID)+"/confirm", fresh.Handle, body); a.Status != http.StatusNoContent {
		t.Fatalf("the confirmed removal: %d %+v", a.Status, a.Error)
	}
	s.refuses(s.call(http.MethodPost, removalPath(secondXID)+"/confirm", fresh.Handle, body), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
	s.decode(s.call(http.MethodGet, "/v1/passkeys", fresh.Handle, nil), &list)
	if len(list.Passkeys) != 1 || list.Passkeys[0].PasskeyXID != firstXID {
		t.Fatalf("one passkey must be left: %+v", list.Passkeys)
	}
}
