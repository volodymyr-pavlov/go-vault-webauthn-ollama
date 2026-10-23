package mysql

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql/expr"
)

// TestSessionWriterPurgesInBatches proves that a purge runs the delete with the cutoff and the batch size, runs it
// again while a run deletes a full batch, and returns the sum of the deleted rows.
func TestSessionWriterPurgesInBatches(t *testing.T) {
	log := newCallLog()
	log.affectedRuns[expr.DeleteExpiredSessions] = []int64{PurgeBatchSize, PurgeBatchSize, 3}
	writer := &SessionWriter{
		Database:    newFakeDatabase(log),
		SystemClock: newFakeClock(),
	}

	cutoff := fakeNow.Add(-24 * time.Hour)

	purged, err := writer.WriteOne(context.Background(), es.Session{
		ExpiresAt: cutoff,
	}, es.PurgeExpiredSessions)
	if err != nil {
		t.Fatal(err)
	}

	args := log.argsOf(t, expr.DeleteExpiredSessions)
	if len(args) != 2 || !args[0].(time.Time).Equal(cutoff) || args[1].(int64) != PurgeBatchSize {
		t.Fatalf("the delete takes the cutoff and the batch size, got %v", args)
	}

	runs := 0
	for _, run := range log.statements {
		if run.query == expr.DeleteExpiredSessions {
			runs++
		}
	}

	if runs != 3 {
		t.Fatalf("the purge runs the delete until a batch is short, got %d runs", runs)
	}

	if purged.ID != 2*PurgeBatchSize+3 {
		t.Fatalf("the purge returns the sum of the deleted rows, got %d", purged.ID)
	}
}

// TestSessionWriterPurgeNeedsACutoff proves that a purge without a time runs nothing.
func TestSessionWriterPurgeNeedsACutoff(t *testing.T) {
	log := newCallLog()
	writer := &SessionWriter{
		Database:    newFakeDatabase(log),
		SystemClock: newFakeClock(),
	}

	if _, err := writer.WriteOne(context.Background(), es.Session{}, es.PurgeExpiredSessions); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("a purge without a time: %v", err)
	}

	if calls := log.get(); len(calls) != 0 {
		t.Fatalf("a purge without a time runs nothing, got %v", calls)
	}
}
