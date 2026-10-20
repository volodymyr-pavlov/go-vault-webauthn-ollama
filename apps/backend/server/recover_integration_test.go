//go:build integration

package server

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// approve approves the open recovery request of the address the way the operator command does. It returns an error if
// there is no open request or the delay has not ended.
func (s *stand) approve(email string) error {
	s.t.Helper()
	user, err := s.env.UserReader.ReadOne(context.Background(), es.User{Email: email}, 0)
	if err != nil {
		s.t.Fatal(err)
	}
	request, err := s.env.RecoveryRequestReader.ReadOne(context.Background(), es.RecoveryRequest{UserID: user.ID}, 0)
	if err != nil {
		return err
	}
	_, err = s.env.RecoveryRequestWriter.WriteOne(context.Background(), es.RecoveryRequest{
		RecoveryRequestXID: request.RecoveryRequestXID,
		Flags:              es.RecoveryRequestFlagApproved,
	}, es.WriteUpdate|es.AppendFlag|es.ApproveRecoveryRequest)
	return err
}

// TestRecoveryOfLostFactors proves that a user who lost every factor and every recovery code gets back in only through
// the delay, the approval of an operator and a single-use grant, and that the old sessions end.
func TestRecoveryOfLostFactors(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("dave-%d@example.com", time.Now().UnixNano())
	old := s.open()
	s.register(old.Handle, email)
	if _, a := s.enrollPasskey(old.Handle, s.authenticator(), "lost phone"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}

	// The owner has lost everything and asks for the recovery from a new device.
	device := s.open()
	var status api.RecoveryStatusResult
	s.decode(s.call(http.MethodPost, "/v1/recover/request", device.Handle, map[string]string{"email": email}), &status)
	cancelToken, ok := s.messages.lastToken(email, es.SendRecoveryRequested)
	if !ok || status.Flags&es.SessionFlagStarted == 0 {
		t.Fatalf("the owner must get a notice with a cancel token: %+v %v", status, ok)
	}

	// A second request, and a request for an unknown address, answer the same and send nothing new.
	s.decode(s.call(http.MethodPost, "/v1/recover/request", device.Handle, map[string]string{"email": email}), &status)
	s.decode(s.call(http.MethodPost, "/v1/recover/request", device.Handle, map[string]string{"email": "nobody-" + email}), &status)
	if n := s.messages.count(email, es.SendRecoveryRequested); n != 1 {
		t.Fatalf("one open request must send one notice, got %d", n)
	}

	// Nothing works before the delay ends and an operator approves.
	if err := s.approve(email); err == nil {
		t.Fatal("a request must not be approved before its delay ends")
	}
	s.decode(s.call(http.MethodPost, "/v1/recover/claim", device.Handle, map[string]string{"email": email}), &status)
	if _, ok := s.messages.lastToken(email, es.SendRecoveryGrant); ok {
		t.Fatal("an unapproved request must not yield a grant")
	}
	s.refuses(s.call(http.MethodPost, "/v1/recover/grant", device.Handle, map[string]string{"token": cancelToken}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")

	// The owner can cancel with the token, once.
	if a := s.call(http.MethodPost, "/v1/recover/cancel", device.Handle, map[string]string{"token": cancelToken}); a.Status != http.StatusNoContent {
		t.Fatalf("cancel: %d %+v", a.Status, a.Error)
	}
	s.refuses(s.call(http.MethodPost, "/v1/recover/cancel", device.Handle, map[string]string{"token": cancelToken}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")

	// A new request goes through the delay and the approval.
	s.decode(s.call(http.MethodPost, "/v1/recover/request", device.Handle, map[string]string{"email": email}), &status)
	if n := s.messages.count(email, es.SendRecoveryRequested); n != 2 {
		t.Fatalf("a request after a cancel must send a notice, got %d", n)
	}
	s.clock.Advance(time.Hour + time.Minute)
	if err := s.approve(email); err != nil {
		t.Fatalf("approve after the delay: %v", err)
	}

	s.decode(s.call(http.MethodPost, "/v1/recover/claim", device.Handle, map[string]string{"email": email}), &status)
	grant, ok := s.messages.lastToken(email, es.SendRecoveryGrant)
	if !ok {
		t.Fatal("an approved request must yield a grant")
	}

	// The grant works once, on one session. A wrong token is refused.
	other := s.open()
	s.refuses(s.call(http.MethodPost, "/v1/recover/grant", other.Handle, map[string]string{"token": cancelToken}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
	var result api.AuthorizeRecoveryHandlerResult
	s.decode(s.call(http.MethodPost, "/v1/recover/grant", device.Handle, map[string]string{"token": grant}), &result)
	if result.Flags&es.SessionFlagRecoveryApproved == 0 {
		t.Fatalf("grant: %+v", result)
	}
	s.refuses(s.call(http.MethodPost, "/v1/recover/grant", other.Handle, map[string]string{"token": grant}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")

	// The old session ends, and the new one may enroll a factor and do nothing else.
	s.refuses(s.call(http.MethodGet, "/v1/session", old.Handle, nil), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
	if _, a := s.enrollPasskey(device.Handle, s.authenticator(), "new phone"); a.Error != nil {
		t.Fatalf("enroll after the recovery: %+v", a.Error)
	}
	s.refuses(s.call(http.MethodGet, "/v1/passkeys", device.Handle, nil), http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
}

// TestRecoveryGrantExpires proves that a grant stops working after its lifetime.
func TestRecoveryGrantExpires(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("erin-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	device := s.open()
	var status api.RecoveryStatusResult
	s.decode(s.call(http.MethodPost, "/v1/recover/request", device.Handle, map[string]string{"email": email}), &status)
	s.clock.Advance(time.Hour + time.Minute)
	if err := s.approve(email); err != nil {
		t.Fatal(err)
	}
	s.decode(s.call(http.MethodPost, "/v1/recover/claim", device.Handle, map[string]string{"email": email}), &status)
	grant, _ := s.messages.lastToken(email, es.SendRecoveryGrant)

	s.clock.Advance(api.RecoveryGrantTTL + time.Minute)
	s.refuses(s.call(http.MethodPost, "/v1/recover/grant", device.Handle, map[string]string{"token": grant}), http.StatusUnauthorized, "AUTHENTICATION_FAILED")
}

// TestLoginCancelsRecovery proves that a login with a factor ends an open recovery request, because the owner is still
// in control of the user.
func TestLoginCancelsRecovery(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("frank-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	authenticator := s.authenticator()
	if _, a := s.enrollPasskey(session.Handle, authenticator, "phone"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}

	attacker := s.open()
	var status api.RecoveryStatusResult
	s.decode(s.call(http.MethodPost, "/v1/recover/request", attacker.Handle, map[string]string{"email": email}), &status)

	var login api.AuthorizeResult
	s.decode(s.loginPasskey(s.open().Handle, email, authenticator), &login)

	s.clock.Advance(time.Hour + time.Minute)
	if err := s.approve(email); err == nil {
		t.Fatal("a login must cancel the open recovery request")
	}
}
