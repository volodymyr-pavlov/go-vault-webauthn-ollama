//go:build integration

package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// TestIdleSessionEnds proves that a session ends when its device stays silent for longer than the idle limit, and that
// a device that keeps making requests stays logged in.
func TestIdleSessionEnds(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("hana-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)

	// Requests inside the idle limit keep the session alive, even when they add up to more than the limit.
	for range 3 {
		s.clock.Advance(api.DefaultIdleTimeout - time.Hour)
		var current api.RetrieveSessionHandlerResult
		s.decode(s.call(http.MethodGet, "/v1/session", session.Handle, nil), &current)
	}

	s.clock.Advance(api.DefaultIdleTimeout + time.Hour)
	s.refuses(s.call(http.MethodGet, "/v1/session", session.Handle, nil), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
}

// TestDevicesList proves that the owner can see the logged-in sessions of the account, can end another one, and cannot
// touch the session of another account.
func TestDevicesList(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("ivan-%d@example.com", time.Now().UnixNano())
	authenticator := s.authenticator()
	laptop := s.open()
	s.register(laptop.Handle, email)
	if _, a := s.enrollPasskey(laptop.Handle, authenticator, "key"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	var login api.AuthorizeResult
	s.decode(s.loginPasskey(laptop.Handle, email, authenticator), &login)

	phone := s.open()
	s.decode(s.loginPasskey(phone.Handle, email, authenticator), &login)

	var list api.ListSessionsHandlerResult
	s.decode(s.call(http.MethodGet, "/v1/sessions", laptop.Handle, nil), &list)
	if len(list.Sessions) != 2 {
		t.Fatalf("the account has two logged-in sessions: %+v", list.Sessions)
	}
	var current int
	for _, device := range list.Sessions {
		if device.Current {
			current++
			if device.SessionXID != laptop.SessionXID {
				t.Fatalf("the current session is the laptop: %+v", device)
			}
		}
	}
	if current != 1 {
		t.Fatalf("exactly one session is current: %+v", list.Sessions)
	}

	// Another account cannot end the session of this one.
	other := s.open()
	otherEmail := fmt.Sprintf("jane-%d@example.com", time.Now().UnixNano())
	s.register(other.Handle, otherEmail)
	otherKey := s.authenticator()
	if _, a := s.enrollPasskey(other.Handle, otherKey, "key"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	s.decode(s.loginPasskey(other.Handle, otherEmail, otherKey), &login)
	s.refuses(s.call(http.MethodDelete, "/v1/sessions/"+strconv.FormatUint(phone.SessionXID, 10), other.Handle, nil), http.StatusNotFound, "NOT_FOUND_DEVICE")

	// The owner ends the phone. It stops working at once, and the list shows one session.
	if a := s.call(http.MethodDelete, "/v1/sessions/"+strconv.FormatUint(phone.SessionXID, 10), laptop.Handle, nil); a.Status != http.StatusNoContent {
		t.Fatalf("remove: %d %+v", a.Status, a.Error)
	}
	s.refuses(s.call(http.MethodGet, "/v1/session", phone.Handle, nil), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
	s.decode(s.call(http.MethodGet, "/v1/sessions", laptop.Handle, nil), &list)
	if len(list.Sessions) != 1 {
		t.Fatalf("one session is left: %+v", list.Sessions)
	}
	s.refuses(s.call(http.MethodDelete, "/v1/sessions/0", laptop.Handle, nil), http.StatusBadRequest, "NO_PARAM_SESSION_XID")
}

// TestStaleRequestTimeCarriesServerTime proves that a request with a wrong clock gets the time of the server, so that
// the page can fix its clock and send the request again.
func TestStaleRequestTimeCarriesServerTime(t *testing.T) {
	s := newStand(t)
	session := s.open()
	key := s.devices[session.Handle]

	request := s.newRequest(http.MethodGet, "/v1/session", nil)
	s.sign(request, nil, key, s.clock.Now().Add(-time.Hour).Unix(), s.nextNonce(), s.tags[session.Handle])
	response := s.do(request)
	s.refuses(response, http.StatusUnauthorized, "STALE_REQUEST_TIME")
	if got := response.Error.Params["server_time"]; got != float64(s.clock.Now().Unix()) {
		t.Fatalf("server_time = %v, want %d", got, s.clock.Now().Unix())
	}
}

// TestSessionOpenLimit proves that one address cannot open sessions without limit, because each one is a database row.
func TestSessionOpenLimit(t *testing.T) {
	s := newStand(t)
	var refused bool
	for range api.DefaultSessionPerMinute + 5 {
		handle := s.newDevice()
		a := s.openSession(handle)
		if a.Status == http.StatusTooManyRequests {
			refused = true
			if a.Error == nil || a.Error.Code != "TOO_MANY_REQUESTS" {
				t.Fatalf("the refusal must name the reason: %+v", a.Error)
			}
			break
		}
	}
	if !refused {
		t.Fatalf("an address must not open more than %d sessions in a minute", api.DefaultSessionPerMinute)
	}
}

// TestPurgeExpiredSessions proves that the purge deletes the sessions that expired before the cutoff and keeps the others.
func TestPurgeExpiredSessions(t *testing.T) {
	s := newStand(t)
	old := s.open()
	live := s.open()

	// Make the first session old by moving its end into the past.
	if _, err := s.env.SessionWriter.WriteOne(context.Background(), es.Session{
		ID:        mustSessionID(t, s, old.SessionXID),
		ExpiresAt: s.clock.Now().Add(-time.Hour),
	}, es.WriteUpdate); err != nil {
		t.Fatal(err)
	}

	if _, err := s.env.SessionWriter.WriteOne(context.Background(), es.Session{
		ExpiresAt: s.clock.Now().Add(-time.Minute),
	}, es.PurgeExpiredSessions); err != nil {
		t.Fatal(err)
	}
	if _, err := s.env.SessionReader.ReadOne(context.Background(), es.Session{SessionXID: old.SessionXID}, 0); err == nil {
		t.Fatal("an expired session must be deleted")
	}
	if _, err := s.env.SessionReader.ReadOne(context.Background(), es.Session{SessionXID: live.SessionXID}, 0); err != nil {
		t.Fatalf("a live session must stay: %v", err)
	}
}

// mustSessionID returns the internal ID of the session with the external identifier.
func mustSessionID(t *testing.T, s *stand, xid uint64) uint64 {
	t.Helper()
	session, err := s.env.SessionReader.ReadOne(context.Background(), es.Session{SessionXID: xid}, 0)
	if err != nil {
		t.Fatal(err)
	}

	return session.ID
}

// TestSharedAddressSignal proves that the login handlers set the shared-address signal when enough different accounts
// tried the same address within the hour, because that is the pattern of credential stuffing from a small pool of
// addresses. The advisor mock records the summary that the risk engine sends, which carries the signals.
func TestSharedAddressSignal(t *testing.T) {
	s := newStand(t)
	login := func(prefix string) ai.Signals {
		email := fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
		session := s.open()
		s.register(session.Handle, email)
		authenticator := s.authenticator()
		if _, a := s.enrollPasskey(session.Handle, authenticator, "key"); a.Error != nil {
			t.Fatalf("enroll: %+v", a.Error)
		}
		var result api.AuthorizeResult
		s.decode(s.loginPasskey(session.Handle, email, authenticator), &result)

		return s.advisor.Last().Signals
	}

	// Four earlier accounts are not enough. The fifth account sets the signal.
	for i := range ai.SharedAddressAccounts - 1 {
		if signals := login(fmt.Sprintf("shared%d", i)); signals.Has(ai.SignalSharedAddress) {
			t.Fatalf("account %d must not set the signal: %s", i+1, signals.List())
		}
	}
	if signals := login("fifth"); !signals.Has(ai.SignalSharedAddress) {
		t.Fatalf("the fifth account must set the signal: %s", signals.List())
	}
}
