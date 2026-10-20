//go:build integration

package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
)

// scrape returns the body that the metrics handler of the stand serves.
func (s *stand) scrape() string {
	s.t.Helper()
	recorder := httptest.NewRecorder()
	s.srv.Metrics().Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		s.t.Fatalf("scrape: status %d", recorder.Code)
	}

	return recorder.Body.String()
}

// TestMetrics proves that a login, a refused login, a rate-limited call and a recovery request leave the expected
// series, and that no label carries an email or an identifier.
func TestMetrics(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("erin-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)

	authenticator := s.authenticator()
	if _, a := s.enrollPasskey(session.Handle, authenticator, "phone"); a.Error != nil {
		t.Fatalf("enroll: %+v", a.Error)
	}

	login := s.open()
	if a := s.loginPasskey(login.Handle, email, authenticator); a.Error != nil {
		t.Fatalf("login: %+v", a.Error)
	}

	refused := s.open()
	s.refuses(s.loginPassword(refused.Handle, email, "wrong password"), http.StatusUnauthorized, "AUTHENTICATION_FAILED")

	device := s.open()
	if a := s.call(http.MethodPost, "/v1/recover/request", device.Handle, map[string]string{"email": email}); a.Error != nil {
		t.Fatalf("recover request: %+v", a.Error)
	}

	for range api.DefaultSessionPerMinute + 5 {
		if s.openSession(s.newDevice()).Status == http.StatusTooManyRequests {
			break
		}
	}

	body := s.scrape()
	for _, want := range []string{
		`login_http_requests_total{resource="complete_authorize_passkey",status="200"} 1`,
		`login_http_requests_total{resource="authorize_password",status="401"} 1`,
		`login_http_requests_total{resource="begin_session",status="429"}`,
		`login_http_request_duration_seconds_count{resource="authorize_password"} 1`,
		`login_rate_limited_total{scope="session_open"}`,
		`login_login_decisions_total{decision="allow"} 1`,
		`login_advisor_outcomes_total{outcome="advice"} 1`,
		`login_recovery_events_total{event="requested"} 1`,
		`login_session_events_total{event="opened"}`,
		`login_auth_failures_total{factor="password"} 1`,
		"go_goroutines",
		"process_open_fds",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the scrape lacks %q", want)
		}
	}

	families, err := s.srv.Metrics().Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "login_") {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				value := label.GetValue()
				if strings.Contains(value, "@") || strings.Contains(value, email) || len(value) > 40 {
					t.Errorf("%s: the label %s holds %q", family.GetName(), label.GetName(), value)
				}
			}
		}
	}
}

// TestMetricsNotOnAPIPort proves that the API port does not serve the metrics.
func TestMetricsNotOnAPIPort(t *testing.T) {
	s := newStand(t)
	request, err := http.NewRequest(http.MethodGet, "http://stand/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}

	response, err := s.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.StatusCode)
	}
}
