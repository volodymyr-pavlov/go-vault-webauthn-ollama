// Package metrics collects the Prometheus metrics of the service. A [Metrics] owns a dedicated registry, so the
// metrics of the process never mix with a global one. Every label has a closed set of values: no label holds an email,
// an address or an ID.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// Values of the label scope of the metric login_rate_limited_total.
const (
	ScopeAddress     = "address"
	ScopeAccount     = "account"
	ScopeGlobal      = "global"
	ScopeSessionOpen = "session_open"
)

// Values of the label outcome of the metric login_advisor_outcomes_total.
const (
	OutcomeAdvice      = "advice"
	OutcomeRefused     = "refused"
	OutcomeTimeout     = "timeout"
	OutcomeError       = "error"
	OutcomeBreakerOpen = "breaker_open"
)

// Values of the label event of the metric login_recovery_events_total.
const (
	RecoveryRequested = "requested"
	RecoveryCancelled = "cancelled"
	RecoveryClaimed   = "claimed"
	RecoveryGranted   = "granted"
	RecoveryRefused   = "refused"
)

// Values of the label event of the metric login_session_events_total.
const (
	SessionOpened        = "opened"
	SessionRevoked       = "revoked"
	SessionExpiredPurged = "expired_purged"
)

// Unknown is the label value of a resource, a decision or an outcome that the package does not know. It keeps the
// number of series bounded.
const Unknown = "unknown"

// Metrics holds the collectors of the service and the registry that serves them. [New] builds it. A nil *Metrics is
// valid: every method does nothing, so a component works with no metrics set.
type Metrics struct {
	registry *prometheus.Registry

	requests       *prometheus.CounterVec
	duration       *prometheus.HistogramVec
	rateLimited    *prometheus.CounterVec
	decisions      *prometheus.CounterVec
	advisor        *prometheus.CounterVec
	recovery       *prometheus.CounterVec
	sessionEvents  *prometheus.CounterVec
	authFailures   *prometheus.CounterVec
	knownDecisions map[string]struct{}
}

// New returns a [Metrics] with its own registry, the Go collector and the process collector.
func New() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "login_http_requests_total",
			Help: "The HTTP requests by resource and status code.",
		}, []string{
			"resource",
			"status",
		}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "login_http_request_duration_seconds",
			Help:    "The duration of the HTTP requests by resource.",
			Buckets: prometheus.DefBuckets,
		}, []string{"resource"}),
		rateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "login_rate_limited_total",
			Help: "The requests that a rate limit refused, by scope.",
		}, []string{"scope"}),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "login_login_decisions_total",
			Help: "The decisions of the risk engine.",
		}, []string{"decision"}),
		advisor: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "login_advisor_outcomes_total",
			Help: "The results of the questions to the risk advisor.",
		}, []string{"outcome"}),
		recovery: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "login_recovery_events_total",
			Help: "The events of the account recovery flow.",
		}, []string{"event"}),
		sessionEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "login_session_events_total",
			Help: "The session lifecycle events.",
		}, []string{"event"}),
		authFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "login_auth_failures_total",
			Help: "The failed authentications by factor.",
		}, []string{"factor"}),
		knownDecisions: map[string]struct{}{
			"allow":  {},
			"limit":  {},
			"review": {},
			"deny":   {},
		},
	}
	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.requests,
		m.duration,
		m.rateLimited,
		m.decisions,
		m.advisor,
		m.recovery,
		m.sessionEvents,
		m.authFailures,
	)

	return m
}

// Handler returns the HTTP handler that serves the metrics in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Registry returns the registry of m.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// Request counts one finished request of the resource with the status code, and records its duration. The resource is
// the name of the endpoint, never a path.
func (m *Metrics) Request(resource string, status int, took time.Duration) {
	if m == nil {
		return
	}

	m.requests.WithLabelValues(resource, statusLabel(status)).Inc()
	m.duration.WithLabelValues(resource).Observe(took.Seconds())
}

// RateLimited counts one request that the limit of the scope refused. A scope that is not one of the Scope constants
// counts as [Unknown].
func (m *Metrics) RateLimited(scope string) {
	if m == nil {
		return
	}

	switch scope {
	case ScopeAddress, ScopeAccount, ScopeGlobal, ScopeSessionOpen:
	default:
		scope = Unknown
	}

	m.rateLimited.WithLabelValues(scope).Inc()
}

// Decision counts one decision of the risk engine. The name is "allow", "limit", "review" or "deny"; any other name
// counts as [Unknown].
func (m *Metrics) Decision(name string) {
	if m == nil {
		return
	}

	if _, ok := m.knownDecisions[name]; !ok {
		name = Unknown
	}

	m.decisions.WithLabelValues(name).Inc()
}

// Advisor counts one result of a question to the risk advisor. An outcome that is not one of the Outcome constants
// counts as [Unknown].
func (m *Metrics) Advisor(outcome string) {
	if m == nil {
		return
	}

	switch outcome {
	case OutcomeAdvice, OutcomeRefused, OutcomeTimeout, OutcomeError, OutcomeBreakerOpen:
	default:
		outcome = Unknown
	}

	m.advisor.WithLabelValues(outcome).Inc()
}

// Recovery counts one event of the recovery flow. An event that is not one of the Recovery constants counts as
// [Unknown].
func (m *Metrics) Recovery(event string) {
	if m == nil {
		return
	}

	switch event {
	case RecoveryRequested, RecoveryCancelled, RecoveryClaimed, RecoveryGranted, RecoveryRefused:
	default:
		event = Unknown
	}

	m.recovery.WithLabelValues(event).Inc()
}

// Session adds n to the count of the session event. An event that is not one of the Session constants counts as
// [Unknown].
func (m *Metrics) Session(event string, n uint64) {
	if m == nil || n == 0 {
		return
	}

	switch event {
	case SessionOpened, SessionRevoked, SessionExpiredPurged:
	default:
		event = Unknown
	}

	m.sessionEvents.WithLabelValues(event).Add(float64(n))
}

// AuthFailure counts one failed authentication of the factor. A set that does not hold exactly one known factor counts
// as [Unknown].
func (m *Metrics) AuthFailure(factor es.Factors) {
	if m == nil {
		return
	}

	label := Unknown
	if factor.Single() && factor.String() != "" {
		label = factor.String()
	}

	m.authFailures.WithLabelValues(label).Inc()
}

// statusLabel returns the status code as a label value. A code outside 100 to 599 gives [Unknown].
func statusLabel(status int) string {
	if status < 100 || status > 599 {
		return Unknown
	}

	return strconv.Itoa(status)
}
