package mysql

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql/expr"
)

// TestHTTPRequestWriterSavesTheRow proves that the writer runs the insert once with the fields of the request in the
// order of the columns, cuts the long texts, and sets the ID and the time.
func TestHTTPRequestWriterSavesTheRow(t *testing.T) {
	log := newCallLog()
	writer := &HTTPRequestWriter{
		Database:    newFakeDatabase(log),
		SystemClock: newFakeClock(),
	}

	saved, err := writer.WriteOne(context.Background(), es.HTTPRequest{
		ResourceCode: 7,
		Method:       "POST",
		StatusCode:   401,
		ErrorCode:    10015,
		DurationMs:   12,
		SessionXID:   31,
		UserXID:      32,
		IP:           netip.MustParseAddr("192.0.2.4"),
		Path:         "/v1/auth/totp",
		RequestID:    "request",
		UserAgent:    strings.Repeat("a", 300),
	}, es.WriteCreate)
	if err != nil {
		t.Fatal(err)
	}

	if saved.ID == 0 || saved.CreatedAt.IsZero() {
		t.Fatalf("the row must carry its ID and time, got %+v", saved)
	}

	args := log.argsOf(t, expr.CreateHTTPRequest)
	if len(args) != 17 {
		t.Fatalf("the insert takes 17 values, got %d", len(args))
	}

	if got := args[11].(string); len(got) != 255 {
		t.Fatalf("the user agent must be cut to 255 bytes, got %d", len(got))
	}
}

// TestHTTPRequestWriterRefusesWhatItCannotWrite proves that the log only creates rows.
func TestHTTPRequestWriterRefusesWhatItCannotWrite(t *testing.T) {
	writer := &HTTPRequestWriter{
		Database:    newFakeDatabase(newCallLog()),
		SystemClock: newFakeClock(),
	}

	if _, err := writer.WriteOne(context.Background(), es.HTTPRequest{}, es.WriteUpdate); !errors.Is(err, es.ErrNoMethod) {
		t.Fatalf("an update: %v", err)
	}

	if _, err := writer.WriteOne(context.Background(), es.HTTPRequest{}, 0); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("no option: %v", err)
	}

	if _, err := writer.WriteOne(context.Background(), es.HTTPRequest{}, es.PurgeHTTPRequests); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("a purge without a time: %v", err)
	}
}

// TestHTTPRequestWriterPurgesWithTheCutoff proves that a purge runs the delete once with the time of the argument in
// UTC and does not insert a row.
func TestHTTPRequestWriterPurgesWithTheCutoff(t *testing.T) {
	log := newCallLog()
	writer := &HTTPRequestWriter{
		Database:    newFakeDatabase(log),
		SystemClock: newFakeClock(),
	}

	cutoff := fakeNow.Add(-30 * 24 * time.Hour)

	if _, err := writer.WriteOne(context.Background(), es.HTTPRequest{
		CreatedAt: cutoff,
	}, es.PurgeHTTPRequests); err != nil {
		t.Fatal(err)
	}

	args := log.argsOf(t, expr.DeleteExpiredHTTPRequests)
	if len(args) != 1 || !args[0].(time.Time).Equal(cutoff) {
		t.Fatalf("the delete takes the cutoff, got %v", args)
	}

	for _, call := range log.get() {
		if strings.Contains(call, "INSERT") {
			t.Fatalf("a purge must not insert: %s", call)
		}
	}
}

// TestCutTextKeepsWholeCharacters proves that the cut never leaves half of a multi-byte character.
func TestCutTextKeepsWholeCharacters(t *testing.T) {
	if got := cutText("abc", 8); got != "abc" {
		t.Fatalf("a short text stays: %q", got)
	}

	// "é" takes two bytes, so a cut inside it must drop the whole character.
	if got := cutText("abécd", 3); got != "ab" {
		t.Fatalf("got %q", got)
	}

	// An invalid byte early in the text must not shorten the cut.
	if got := cutText("a\xffbcdef", 5); got != "a\xffbcd" {
		t.Fatalf("a stray invalid byte: got %q", got)
	}
}
