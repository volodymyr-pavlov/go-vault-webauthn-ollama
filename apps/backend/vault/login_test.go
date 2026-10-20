package vault

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

// newTestLease returns a lease for a fake Vault at address. The fake answers the AppRole login with the status that
// next returns and, for status 200, with a token.
func newTestLease(t *testing.T, next func(call int32) int) (*Lease, *atomic.Int32) {
	t.Helper()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		status := next(calls.Add(1))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)

		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"auth":{"client_token":"token","lease_duration":3600,"renewable":true}}`))
		} else {
			_, _ = w.Write([]byte(`{"errors":["unavailable"]}`))
		}
	}))
	t.Cleanup(server.Close)

	config := api.DefaultConfig()
	config.Address = server.URL
	config.MaxRetries = 0

	client, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}

	return &Lease{
		client:   client,
		mount:    DefaultAppRoleMount,
		roleID:   "role",
		secretID: "secret",
		logger:   nil,
		retryMin: time.Millisecond,
		retryMax: 4 * time.Millisecond,
	}, &calls
}

// TestLoginAgainSurvivesAShortOutage proves that a login which fails twice does not end the lease: the third try
// succeeds and sets the token.
func TestLoginAgainSurvivesAShortOutage(t *testing.T) {
	lease, calls := newTestLease(t, func(call int32) int {
		if call <= 2 {
			return http.StatusServiceUnavailable
		}

		return http.StatusOK
	})
	lease.logger = slog.New(slog.DiscardHandler)

	if err := lease.loginAgain(context.Background()); err != nil {
		t.Fatalf("a short outage must not fail the lease: %v", err)
	}

	if calls.Load() != 3 {
		t.Fatalf("want 3 tries, got %d", calls.Load())
	}

	if lease.client.Token() != "token" {
		t.Fatalf("the new token must be set, got %q", lease.client.Token())
	}
}

// TestLoginAgainStopsWhenTheContextEnds proves that the retry loop ends with the context and does not spin for ever.
func TestLoginAgainStopsWhenTheContextEnds(t *testing.T) {
	lease, _ := newTestLease(t, func(int32) int { return http.StatusServiceUnavailable })
	lease.logger = slog.New(slog.DiscardHandler)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := lease.loginAgain(ctx); err == nil {
		t.Fatal("a lease that cannot log in must end with the context")
	}
}
