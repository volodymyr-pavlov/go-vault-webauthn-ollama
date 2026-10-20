//go:build integration

package server

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/authtest"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/totp"
)

// freshAuthenticatorUser registers a user with a passkey and logs in, so that the session is authorized and fresh. It
// returns the handle of the session.
func (s *stand) freshAuthenticatorUser(t *testing.T) (handle string, email string, authenticator *authtest.Authenticator) {
	t.Helper()

	email = fmt.Sprintf("codes-%d@example.com", time.Now().UnixNano())
	authenticator = s.authenticator()
	session := s.open()
	s.register(session.Handle, email)

	if _, a := s.enrollPasskey(session.Handle, authenticator, "key"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}

	var login api.AuthorizeResult
	s.decode(s.loginPasskey(session.Handle, email, authenticator), &login)

	return session.Handle, email, authenticator
}

// expectedCodes returns the codes of the current and the previous step, because the clock of the stand-in Vault is the
// real one and a step can change between the call and the check.
func expectedCodes(secret []byte, digits int, period uint) []string {
	options := totp.Options{
		Digits: digits,
		Period: period,
	}
	step := options.Step(time.Now())

	return []string{options.Code(secret, step), options.Code(secret, step-1)}
}

// TestAuthenticatorAddsListsAndRemovesAccounts proves that the authenticator keeps secrets in Vault, shows the codes
// that Vault makes, imports a link and a Google export, refuses what it cannot import, and deletes the secret with the
// account.
func TestAuthenticatorAddsListsAndRemovesAccounts(t *testing.T) {
	s := newStand(t)
	handle, _, _ := s.freshAuthenticatorUser(t)

	secret := []byte("0123456789abcdef0123")
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)

	// A typed secret.
	var added api.AddAccountHandlerResult
	s.decode(s.call(http.MethodPost, "/v1/accounts", handle, map[string]string{
		"secret": encoded,
		"issuer": "GitHub",
		"label":  "alice@example.com",
	}), &added)
	if len(added.Accounts) != 1 || added.Accounts[0].Issuer != "GitHub" {
		t.Fatalf("one account expected: %+v", added)
	}

	// A link with another secret, eight digits and 60 seconds.
	other := []byte("ABCDEFGHIJKLMNOPQRST")
	link := "otpauth://totp/Example:bob?secret=" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(other) + "&digits=8&period=60&issuer=Example"
	s.decode(s.call(http.MethodPost, "/v1/accounts", handle, map[string]string{"uri": link}), &added)

	// A Google export with two accounts and one counter-based account.
	entry := func(secret []byte, name string, kind byte) []byte {
		out := []byte{0x0a, byte(len(secret))}
		out = append(out, secret...)
		out = append(out, 0x12, byte(len(name)))
		out = append(out, name...)
		out = append(out, 0x30, kind)

		return out
	}
	var payload []byte
	for _, e := range [][]byte{
		entry([]byte("google-secret-aaaa"), "g1", 2),
		entry([]byte("google-secret-bbbb"), "g2", 2),
		entry([]byte("google-secret-hotp"), "g3", 1),
	} {
		payload = append(payload, 0x0a, byte(len(e)))
		payload = append(payload, e...)
	}
	migration := "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))
	s.decode(s.call(http.MethodPost, "/v1/accounts", handle, map[string]string{"uri": migration}), &added)
	if len(added.Accounts) != 2 || added.Skipped != 1 {
		t.Fatalf("two accounts and one skipped expected: %+v", added)
	}

	if got := s.transit.AuthenticatorKeys(); got != 4 {
		t.Fatalf("Vault must hold 4 secrets, got %d", got)
	}

	// The list shows the codes that Vault makes, and no secret.
	var list api.ListAccountsHandlerResult
	response := s.call(http.MethodGet, "/v1/accounts", handle, nil)
	s.decode(response, &list)
	if len(list.Accounts) != 4 {
		t.Fatalf("four accounts expected: %+v", list)
	}

	matched := false
	for _, code := range expectedCodes(secret, 6, 30) {
		if list.Accounts[0].Code == code {
			matched = true
		}
	}
	if !matched || list.Accounts[0].ValidFor < 1 || list.Accounts[0].ValidFor > 30 {
		t.Fatalf("the first code must be the code of the secret: %+v", list.Accounts[0])
	}

	if len(list.Accounts[1].Code) != 8 {
		t.Fatalf("the second account has eight digits: %+v", list.Accounts[1])
	}

	if raw := string(response.Data); strings.Contains(raw, encoded) || strings.Contains(raw, "0123456789abcdef0123") {
		t.Fatalf("the list must not hold a secret: %s", raw)
	}

	// What the service cannot import is refused, and nothing is stored.
	for _, body := range []map[string]string{
		{"uri": "otpauth://hotp/x?secret=" + encoded},
		{"secret": "not base32!!"},
		{"secret": encoded, "uri": link},
		{},
	} {
		got := s.call(http.MethodPost, "/v1/accounts", handle, body)
		if got.Status != http.StatusBadRequest {
			t.Fatalf("%v must give 400, got %d", body, got.Status)
		}
	}

	if got := s.transit.AuthenticatorKeys(); got != 4 {
		t.Fatalf("a refused import must leave Vault as it was, got %d secrets", got)
	}

	// Removing an account deletes its secret, and a second removal finds nothing.
	path := fmt.Sprintf("/v1/accounts/%d", list.Accounts[0].AccountXID)
	if a := s.call(http.MethodDelete, path, handle, nil); a.Status != http.StatusNoContent {
		t.Fatalf("remove: %d %+v", a.Status, a.Error)
	}

	s.refuses(s.call(http.MethodDelete, path, handle, nil), http.StatusNotFound, "NOT_FOUND_ACCOUNT")

	if got := s.transit.AuthenticatorKeys(); got != 3 {
		t.Fatalf("the secret must be gone from Vault, got %d secrets", got)
	}

	// Another user cannot remove or see it.
	otherHandle, _, _ := s.freshAuthenticatorUser(t)
	s.refuses(s.call(http.MethodDelete, fmt.Sprintf("/v1/accounts/%d", list.Accounts[1].AccountXID), otherHandle, nil), http.StatusNotFound, "NOT_FOUND_ACCOUNT")
	s.decode(s.call(http.MethodGet, "/v1/accounts", otherHandle, nil), &list)
	if len(list.Accounts) != 0 {
		t.Fatalf("another user must see nothing: %+v", list)
	}
}

// TestAuthenticatorAddNeedsAFreshLogin proves that adding an account needs a login within the fresh window, and that
// viewing the codes does not.
func TestAuthenticatorAddNeedsAFreshLogin(t *testing.T) {
	s := newStand(t)
	handle, _, _ := s.freshAuthenticatorUser(t)
	s.clock.Advance(6 * time.Minute)

	s.refuses(s.call(http.MethodPost, "/v1/accounts", handle, map[string]string{"secret": "JBSWY3DPEHPK3PXP"}), http.StatusUnauthorized, "STALE_AUTHENTICATION")

	if a := s.call(http.MethodGet, "/v1/accounts", handle, nil); a.Status != http.StatusOK {
		t.Fatalf("the list needs no fresh login: %d %+v", a.Status, a.Error)
	}
}

// TestAuthenticatorKeepsVaultAndRowsInStep proves that two imports at the same time that together pass the limit leave
// no secret in Vault without a row: the one that loses deletes its keys again. It also proves that deleting the account
// deletes the secrets.
func TestAuthenticatorKeepsVaultAndRowsInStep(t *testing.T) {
	s := newStand(t)
	handle, email, authenticator := s.freshAuthenticatorUser(t)

	// 26 accounts in one export. The first passes alone, and two of them together pass the limit of 50.
	var payload []byte
	for i := range 26 {
		secret := fmt.Sprintf("secret-number-%04d", i)
		e := append([]byte{0x0a, byte(len(secret))}, secret...)
		e = append(e, 0x30, 2)
		payload = append(payload, 0x0a, byte(len(e)))
		payload = append(payload, e...)
	}
	body := map[string]string{
		"uri": "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload)),
	}

	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.try(http.MethodPost, "/v1/accounts", handle, body)
			if err == nil && got.Status == http.StatusCreated {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()

	var rows int
	if err := s.env.Database.QueryRow("SELECT COUNT(*) FROM accounts a JOIN users u ON u.id = a.user_id WHERE u.email = ?", email).Scan(&rows); err != nil {
		t.Fatal(err)
	}

	if rows > es.MaxAccounts || s.transit.AuthenticatorKeys() != rows {
		t.Fatalf("Vault holds %d secrets for %d rows: %d imports won", s.transit.AuthenticatorKeys(), rows, wins.Load())
	}

	if wins.Load() < 1 {
		t.Fatal("at least one import must succeed")
	}

	// Deleting the account deletes every secret in Vault.
	var started api.BeginDeleteUserHandlerResult
	s.decode(s.call(http.MethodPost, "/v1/user/deletion", handle, nil), &started)
	challenge, err := authtest.Challenge(started.Options)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := authenticator.Assert(challenge, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a := s.call(http.MethodPost, "/v1/user/deletion/confirm", handle, map[string]any{"response": json.RawMessage(assertion)}); a.Status != http.StatusNoContent {
		t.Fatalf("delete the account: %d %+v", a.Status, a.Error)
	}

	if s.transit.AuthenticatorKeys() != 0 {
		t.Fatalf("no secret may stay in Vault after the account is deleted, got %d", s.transit.AuthenticatorKeys())
	}
}
