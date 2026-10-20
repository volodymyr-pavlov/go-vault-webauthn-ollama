//go:build integration

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/authtest"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// TestUserExportAndDeletionWithAPasskey proves the export of the personal data and the deletion of a user that
// has a passkey: the export lists the email, the passkey, the sessions and the request log rows without a secret, the
// deletion needs a passkey assertion for its own challenge, and afterwards no row names the user, no row of the user's
// request log keeps an address or a user agent, and the user cannot log in.
func TestUserExportAndDeletionWithAPasskey(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("erase-%d@example.com", time.Now().UnixNano())
	authenticator := s.authenticator()
	session := s.open()
	userXID := s.register(session.Handle, email)
	if _, a := s.enrollPasskey(session.Handle, authenticator, "my key"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	var login api.AuthorizeResult
	s.decode(s.loginPasskey(session.Handle, email, authenticator), &login)

	var export api.ExportUserHandlerResult
	s.decode(s.call(http.MethodGet, "/v1/user/export", session.Handle, nil), &export)
	if export.Email != email || export.UserXID != userXID || len(export.Passkeys) != 1 || export.Passkeys[0].Name != "my key" {
		t.Fatalf("the export must hold the user: %+v", export)
	}

	if len(export.Sessions) == 0 || len(export.Requests) == 0 {
		t.Fatalf("the export must hold the sessions and the request log: %+v", export)
	}

	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}

	for _, secret := range []string{"password", "public_key", "ciphertext", "hash"} {
		if strings.Contains(strings.ToLower(string(raw)), secret) {
			t.Fatalf("the export must not hold %q: %s", secret, raw)
		}
	}

	// A confirmation without a begin is refused, and the user stays.
	s.refuses(s.call(http.MethodPost, "/v1/user/deletion/confirm", session.Handle, map[string]any{
		"response": json.RawMessage(`{}`),
	}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")

	begin := s.call(http.MethodPost, "/v1/user/deletion", session.Handle, nil)
	if begin.Error != nil {
		t.Fatalf("begin: %+v", begin.Error)
	}
	var started api.BeginDeleteUserHandlerResult
	s.decode(begin, &started)
	if started.Method != api.DeleteMethodPasskey || len(started.Options) == 0 {
		t.Fatalf("a user with a passkey confirms with it: %+v", started)
	}

	challenge, err := authtest.Challenge(started.Options)
	if err != nil {
		t.Fatal(err)
	}
	response, err := authenticator.Assert(challenge, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The challenge for the deletion does not confirm the removal of a passkey.
	passkeys := s.call(http.MethodGet, "/v1/passkeys", session.Handle, nil)
	var list api.RetrievePasskeysHandlerResult
	s.decode(passkeys, &list)
	s.refuses(s.call(http.MethodPost, fmt.Sprintf("/v1/passkeys/%d/removal/confirm", list.Passkeys[0].PasskeyXID), session.Handle, map[string]any{
		"response": json.RawMessage(response),
	}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")

	// The refusal used the challenge up, so the deletion starts again.
	s.decode(s.call(http.MethodPost, "/v1/user/deletion", session.Handle, nil), &started)
	challenge, err = authtest.Challenge(started.Options)
	if err != nil {
		t.Fatal(err)
	}
	response, err = authenticator.Assert(challenge, nil)
	if err != nil {
		t.Fatal(err)
	}

	if a := s.call(http.MethodPost, "/v1/user/deletion/confirm", session.Handle, map[string]any{
		"response": json.RawMessage(response),
	}); a.Status != http.StatusNoContent {
		t.Fatalf("the confirmed deletion: %d %+v", a.Status, a.Error)
	}

	s.assertErased(t, userXID, email)
	s.refuses(s.loginPasskey(s.open().Handle, email, authenticator), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
}

// TestUserDeletionWithoutAPasskeyNeedsAFreshLogin proves that a user that has only a password and a code
// generator is deleted after a fresh login, and that a stale login is refused.
func TestUserDeletionWithoutAPasskeyNeedsAFreshLogin(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("erase-totp-%d@example.com", time.Now().UnixNano())
	session := s.open()
	userXID := s.register(session.Handle, email)
	secret := s.enrollTOTP(session.Handle)

	login := s.open()
	var next api.AuthorizePasswordHandlerResult
	s.decode(s.loginPassword(login.Handle, email, testPassword), &next)
	var result api.AuthorizeResult
	s.decode(s.loginTOTP(login.Handle, s.code(secret)), &result)
	if result.Flags&es.SessionFlagAuthorized == 0 {
		t.Fatalf("login: %+v", result)
	}

	var started api.BeginDeleteUserHandlerResult
	s.decode(s.call(http.MethodPost, "/v1/user/deletion", login.Handle, nil), &started)
	if started.Method != api.DeleteMethodFreshLogin {
		t.Fatalf("a user without a passkey confirms with the fresh login: %+v", started)
	}

	s.clock.Advance(6 * time.Minute)
	s.refuses(s.call(http.MethodPost, "/v1/user/deletion/confirm", login.Handle, map[string]any{}), http.StatusUnauthorized, "STALE_AUTHENTICATION")

	again := s.open()
	s.decode(s.loginPassword(again.Handle, email, testPassword), &next)
	s.decode(s.loginTOTP(again.Handle, s.code(secret)), &result)
	if a := s.call(http.MethodPost, "/v1/user/deletion/confirm", again.Handle, map[string]any{}); a.Status != http.StatusNoContent {
		t.Fatalf("the deletion after a fresh login: %d %+v", a.Status, a.Error)
	}

	s.assertErased(t, userXID, email)
}

// assertErased checks that no row names the user and that the request log rows of the user lost their identity.
func (s *stand) assertErased(t *testing.T, userXID uint64, email string) {
	t.Helper()

	for _, query := range []string{
		"SELECT COUNT(*) FROM users WHERE user_xid = ?",
		"SELECT COUNT(*) FROM http_requests WHERE user_xid = ?",
	} {
		var count int
		if err := s.env.Database.QueryRow(query, userXID).Scan(&count); err != nil {
			t.Fatal(err)
		}

		if count != 0 {
			t.Fatalf("%s must find nothing, got %d", query, count)
		}
	}

	var leaked int
	err := s.env.Database.QueryRow(
		"SELECT COUNT(*) FROM http_requests WHERE event = ? AND created_at > ? AND (ip IS NOT NULL OR user_agent <> '' OR user_xid <> 0 OR session_xid <> 0)",
		es.EventUserDeleted, s.clock.Now().Add(-time.Hour),
	).Scan(&leaked)
	if err != nil {
		t.Fatal(err)
	}

	if leaked != 0 {
		t.Fatalf("the row of the deletion must carry no identity, got %d rows", leaked)
	}
}

// TestParallelConfirmationsWorkOnce proves that the confirmed deletion of a user and the confirmed removal of a
// passkey run in one transaction each: if several requests send the same assertion at the same time, exactly one of
// them succeeds.
func TestParallelConfirmationsWorkOnce(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("parallel-%d@example.com", time.Now().UnixNano())
	first, second := s.authenticator(), s.authenticator()
	session := s.open()
	userXID := s.register(session.Handle, email)
	if _, a := s.enrollPasskey(session.Handle, first, "first"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	secondXID, a := s.enrollPasskey(session.Handle, second, "second")
	if a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	var login api.AuthorizeResult
	s.decode(s.loginPasskey(session.Handle, email, first), &login)

	// fire sends the same body to the path from several goroutines and returns how many answered 204.
	fire := func(path string, body map[string]any) int {
		var wins atomic.Int32
		var wg sync.WaitGroup
		for range 6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := s.try(http.MethodPost, path, session.Handle, body)
				if err == nil && got.Status == http.StatusNoContent {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()

		return int(wins.Load())
	}

	// assertion signs the challenge of the options in begin.
	assertion := func(options []byte) map[string]any {
		challenge, err := authtest.Challenge(options)
		if err != nil {
			t.Fatal(err)
		}
		response, err := first.Assert(challenge, nil)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"response": json.RawMessage(response)}
	}

	removal := fmt.Sprintf("/v1/passkeys/%d/removal", secondXID)
	begin := s.call(http.MethodPost, removal, session.Handle, nil)
	if begin.Error != nil {
		t.Fatalf("begin: %+v", begin.Error)
	}
	if wins := fire(removal+"/confirm", assertion(begin.Data)); wins != 1 {
		t.Fatalf("exactly one parallel removal must succeed, got %d", wins)
	}

	var started api.BeginDeleteUserHandlerResult
	s.decode(s.call(http.MethodPost, "/v1/user/deletion", session.Handle, nil), &started)
	if wins := fire("/v1/user/deletion/confirm", assertion(started.Options)); wins != 1 {
		t.Fatalf("exactly one parallel deletion must succeed, got %d", wins)
	}

	// A request that was in flight when the user went writes its log row after the erase, so only the user is checked
	// here. The retention job deletes such rows.
	var users int
	if err := s.env.Database.QueryRow("SELECT COUNT(*) FROM users WHERE user_xid = ?", userXID).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 0 {
		t.Fatalf("the user must be gone, got %d", users)
	}
}
