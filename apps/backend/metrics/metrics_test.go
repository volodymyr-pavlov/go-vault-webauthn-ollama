package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

func TestCountersIncrement(t *testing.T) {
	m := New()
	m.Request("authorize_password", 401, time.Second)
	m.Request("authorize_password", 401, time.Second)
	m.RateLimited(ScopeAddress)
	m.Decision("deny")
	m.Advisor(OutcomeTimeout)
	m.Recovery(RecoveryGranted)
	m.Session(SessionExpiredPurged, 3)
	m.AuthFailure(es.FactorTOTP)

	checks := []struct {
		name string
		got  float64
		want float64
	}{
		{"requests", testutil.ToFloat64(m.requests.WithLabelValues("authorize_password", "401")), 2},
		{"rate limited", testutil.ToFloat64(m.rateLimited.WithLabelValues(ScopeAddress)), 1},
		{"decision", testutil.ToFloat64(m.decisions.WithLabelValues("deny")), 1},
		{"advisor", testutil.ToFloat64(m.advisor.WithLabelValues(OutcomeTimeout)), 1},
		{"recovery", testutil.ToFloat64(m.recovery.WithLabelValues(RecoveryGranted)), 1},
		{"session", testutil.ToFloat64(m.sessionEvents.WithLabelValues(SessionExpiredPurged)), 3},
		{"failure", testutil.ToFloat64(m.authFailures.WithLabelValues(es.FactorTOTP.String())), 1},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %v, want %v", check.name, check.got, check.want)
		}
	}
}

func TestLabelsAreBounded(t *testing.T) {
	m := New()
	for i := range 100 {
		value := fmt.Sprintf("user-%d@example.com", i)
		m.RateLimited(value)
		m.Decision(value)
		m.Advisor(value)
		m.Recovery(value)
		m.Session(value, 1)
		m.AuthFailure(es.Factors(i + 16))
		m.Request("x", 1000+i, 0)
	}

	for name, vec := range map[string]int{
		"rate limited": testutil.CollectAndCount(m.rateLimited),
		"decisions":    testutil.CollectAndCount(m.decisions),
		"advisor":      testutil.CollectAndCount(m.advisor),
		"recovery":     testutil.CollectAndCount(m.recovery),
		"session":      testutil.CollectAndCount(m.sessionEvents),
		"failures":     testutil.CollectAndCount(m.authFailures),
		"requests":     testutil.CollectAndCount(m.requests),
	} {
		if vec != 1 {
			t.Errorf("%s: %d series, want 1", name, vec)
		}
	}
}

func TestNilMetricsIsSafe(t *testing.T) {
	var m *Metrics
	m.Request("x", 200, 0)
	m.RateLimited(ScopeGlobal)
	m.Decision("allow")
	m.Advisor(OutcomeAdvice)
	m.Recovery(RecoveryRequested)
	m.Session(SessionOpened, 1)
	m.AuthFailure(es.FactorPassword)
}

func TestAdvisorOutcomes(t *testing.T) {
	cases := map[string]error{
		OutcomeAdvice:      nil,
		OutcomeRefused:     fmt.Errorf("x: %w", ai.ErrAdvice),
		OutcomeBreakerOpen: ai.ErrBreakerOpen,
		OutcomeTimeout:     context.DeadlineExceeded,
		OutcomeError:       errors.New("boom"),
	}
	for want, err := range cases {
		m := New()
		a := &Advisor{
			Next:    &ai.MockAdvisor{Err: err},
			Metrics: m,
		}
		_, _ = a.ReadOne(context.Background(), ai.Consultation{}, 0)

		if got := testutil.ToFloat64(m.advisor.WithLabelValues(want)); got != 1 {
			t.Errorf("%s = %v", want, got)
		}
	}
}

func TestHandlerServesRegistry(t *testing.T) {
	m := New()
	m.Decision("allow")

	recorder := httptest.NewRecorder()
	m.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := recorder.Body.String()
	for _, want := range []string{`login_login_decisions_total{decision="allow"} 1`, "go_goroutines", "process_open_fds"} {
		if !strings.Contains(body, want) {
			t.Errorf("the body lacks %q", want)
		}
	}
}
