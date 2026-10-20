//go:build integration

package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
)

// TestRequestLogRecordsEveryRequestWithoutItsBody proves that the request log middleware saves one row for each
// request with the status and the error number of the answer, and that the row holds nothing from the body, because the
// bodies of this service carry passwords, codes and tokens.
func TestRequestLogRecordsEveryRequestWithoutItsBody(t *testing.T) {
	s := newStand(t)
	session := s.open()

	const secret = "hunter2-do-not-log-me"
	s.refuses(s.call(http.MethodPost, "/v1/auth/password", session.Handle, map[string]string{
		"email":    "nobody@example.com",
		"password": secret,
	}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")

	var path, method, event string
	var status, errorCode uint16
	var sessionXID uint64
	err := s.env.Database.QueryRow(
		"SELECT path, method, status_code, error_code, session_xid, event FROM http_requests WHERE path = ? ORDER BY id DESC LIMIT 1",
		"/v1/auth/password",
	).Scan(&path, &method, &status, &errorCode, &sessionXID, &event)
	if err != nil {
		t.Fatalf("the refused request must leave a row: %v", err)
	}

	if method != http.MethodPost || status != http.StatusUnauthorized || errorCode == 0 || sessionXID != session.SessionXID {
		t.Fatalf("the row must describe the answer: %s %d %d %d", method, status, errorCode, sessionXID)
	}

	if event != "password_refused" {
		t.Fatalf("the row must name the event of the refusal, got %q", event)
	}

	// No column of any row may hold the password that the client sent.
	var found int
	err = s.env.Database.QueryRow(
		"SELECT COUNT(*) FROM http_requests WHERE CONCAT_WS(' ', path, request_id, host, user_agent, build_version, event, event_attrs, error_text) LIKE ?",
		"%"+secret+"%",
	).Scan(&found)
	if err != nil {
		t.Fatal(err)
	}

	if found != 0 {
		t.Fatalf("a row holds the password of the body")
	}
}

// TestRequestLogNamesTheSecurityEvents proves that the log names the events of a registration, an enrollment and a
// passkey login, with the factor of the login and without any secret.
func TestRequestLogNamesTheSecurityEvents(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("events-%d@example.com", time.Now().UnixNano())
	authenticator := s.authenticator()
	session := s.open()
	s.register(session.Handle, email)
	if _, a := s.enrollPasskey(session.Handle, authenticator, "key"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}
	var login api.AuthorizeResult
	s.decode(s.loginPasskey(session.Handle, email, authenticator), &login)

	want := map[string]string{
		"registration_begun":    "",
		"registration_verified": "",
		"passkey_enrolled":      "passkey_xid=",
		"login":                 "factor=passkey",
	}
	for event, attrs := range want {
		var found string
		err := s.env.Database.QueryRow(
			"SELECT event_attrs FROM http_requests WHERE event = ? AND session_xid = ? ORDER BY id DESC LIMIT 1",
			event, session.SessionXID,
		).Scan(&found)
		if err != nil {
			t.Fatalf("the log must hold the event %q: %v", event, err)
		}

		if !strings.Contains(found, attrs) {
			t.Fatalf("the event %q has the attributes %q, want %q in them", event, found, attrs)
		}
	}
}
