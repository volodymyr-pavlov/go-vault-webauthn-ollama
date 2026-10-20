package mysql

import (
	"errors"
	"testing"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

func TestPasskeyChallengeOpener(t *testing.T) {
	f := newEnrollFakes()
	writer := &SessionGroupWriter{
		Database:  newFakeDatabase(f.log),
		SessionTx: f.session,
	}

	if _, err := writer.WriteOne(t.Context(), es.SessionGroup{}, es.WriteCreate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("create: %v", err)
	}

	f.checkCalls(t)

	if _, err := writer.WriteOne(t.Context(), es.SessionGroup{}, es.OpenPasskeyEnrollment); err != nil {
		t.Fatal(err)
	}

	f.checkCalls(t, "begin", "session.update", "session.update", "commit")
}

func TestPasskeyChallengeOpenerStopsOnFailure(t *testing.T) {
	f := newEnrollFakes()
	f.failures["session.update"] = errEnrollStep
	writer := &SessionGroupWriter{
		Database:  newFakeDatabase(f.log),
		SessionTx: f.session,
	}

	if _, err := writer.WriteOne(t.Context(), es.SessionGroup{}, es.OpenPasskeyEnrollment); !errors.Is(err, errEnrollStep) {
		t.Fatalf("got %v", err)
	}

	f.checkCalls(t, "begin", "session.update", "rollback")
}

func TestPasskeyEnroller(t *testing.T) {
	f := newEnrollFakes()
	writer := &SessionGroupWriter{
		Database:  newFakeDatabase(f.log),
		SessionTx: f.session,
		PasskeyTx: f.passkey,
	}

	if _, err := writer.WriteOne(t.Context(), es.SessionGroup{}, es.WriteUpdate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("update: %v", err)
	}

	if _, err := writer.WriteOne(t.Context(), es.SessionGroup{}, es.EnrollPasskey); err != nil {
		t.Fatal(err)
	}

	f.checkCalls(t, "begin", "session.update", "passkey.create", "commit")

	if len(f.session.ops) != 1 || f.session.ops[0]&es.ConsumeChallenge == 0 {
		t.Fatalf("the enrollment must use the challenge up, got %b", f.session.ops)
	}
}

func TestPasskeyEnrollerRollsBack(t *testing.T) {
	tests := []struct {
		name  string
		fail  string
		err   error
		calls []string
	}{
		{
			name:  "the challenge is used up",
			fail:  "session.update",
			err:   es.ErrNoUpdatedRows,
			calls: []string{"begin", "session.update", "rollback"},
		},
		{
			name:  "the passkey exists",
			fail:  "passkey.create",
			err:   es.ErrDuplicate,
			calls: []string{"begin", "session.update", "passkey.create", "rollback"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newEnrollFakes()
			f.failures[tc.fail] = tc.err
			writer := &SessionGroupWriter{
				Database:  newFakeDatabase(f.log),
				SessionTx: f.session,
				PasskeyTx: f.passkey,
			}

			if _, err := writer.WriteOne(t.Context(), es.SessionGroup{}, es.EnrollPasskey); !errors.Is(err, tc.err) {
				t.Fatalf("got %v", err)
			}

			f.checkCalls(t, tc.calls...)
		})
	}
}

func TestPasskeyEnrollmentRefuser(t *testing.T) {
	f := newEnrollFakes()
	writer := &SessionGroupWriter{
		Database:  newFakeDatabase(f.log),
		SessionTx: f.session,
	}

	if _, err := writer.WriteOne(t.Context(), es.SessionGroup{}, es.RefusePasskeyEnrollment); err != nil {
		t.Fatal(err)
	}

	f.checkCalls(t, "begin", "session.update", "commit")

	if len(f.session.ops) != 1 || f.session.ops[0]&es.ConsumeChallenge == 0 {
		t.Fatalf("the refusal must use the challenge up, got %b", f.session.ops)
	}

	f = newEnrollFakes()
	f.failures["session.update"] = es.ErrNoUpdatedRows
	writer.Database = newFakeDatabase(f.log)
	writer.SessionTx = f.session

	if _, err := writer.WriteOne(t.Context(), es.SessionGroup{}, es.RefusePasskeyEnrollment); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("got %v", err)
	}

	f.checkCalls(t, "begin", "session.update", "rollback")
}
