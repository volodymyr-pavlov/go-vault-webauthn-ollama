//go:build integration

package mysql

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// TestPurgeHTTPRequestsDeletesOnlyTheOldRows proves on a real database that a purge deletes the rows that are older
// than the cutoff, with their address and user agent, and keeps the newer ones.
func TestPurgeHTTPRequestsDeletesOnlyTheOldRows(t *testing.T) {
	now := time.Date(2026, time.October, 16, 12, 0, 0, 0, time.UTC)
	writer := &HTTPRequestWriter{
		Database: testDB,
		SystemClock: &clock.FixedClock{
			Time: now,
		},
	}

	// The test database is shared, so the marker is a path that only this test writes.
	marker := "/v1/purge-test"

	for _, age := range []time.Duration{40 * 24 * time.Hour, 31 * 24 * time.Hour, 29 * 24 * time.Hour, time.Hour} {
		_, err := writer.WriteOne(context.Background(), es.HTTPRequest{
			Method:    "GET",
			Path:      marker,
			IP:        netip.MustParseAddr("192.0.2.9"),
			UserAgent: "purge-test",
			CreatedAt: now.Add(-age),
		}, es.WriteCreate)
		if err != nil {
			t.Fatal(err)
		}
	}

	if _, err := writer.WriteOne(context.Background(), es.HTTPRequest{
		CreatedAt: now.Add(-30 * 24 * time.Hour),
	}, es.PurgeHTTPRequests); err != nil {
		t.Fatal(err)
	}

	var left int
	if err := testDB.QueryRow("SELECT COUNT(*) FROM http_requests WHERE path = ?", marker).Scan(&left); err != nil {
		t.Fatal(err)
	}

	if left != 2 {
		t.Fatalf("the two rows newer than 30 days must stay, got %d", left)
	}

	var old int
	if err := testDB.QueryRow("SELECT COUNT(*) FROM http_requests WHERE path = ? AND created_at < ?", marker, now.Add(-30*24*time.Hour)).Scan(&old); err != nil {
		t.Fatal(err)
	}

	if old != 0 {
		t.Fatalf("no row older than the cutoff may stay, got %d", old)
	}

	if _, err := testDB.Exec("DELETE FROM http_requests WHERE path = ?", marker); err != nil {
		t.Fatal(err)
	}
}
