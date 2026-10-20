package mysql

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

func newTestRecoveryRequestChanger(fakes loginFakes) *RecoveryGroupWriter {
	return &RecoveryGroupWriter{
		Database:          newFakeDatabase(fakes.log),
		RecoveryRequestTx: fakes.requests,
	}
}

func TestRecoveryRequestChangerCreatesInOneTransaction(t *testing.T) {
	fakes := newLoginFakes("", nil)

	changed, err := newTestRecoveryRequestChanger(fakes).WriteOne(context.Background(), es.RecoveryGroup{
		Request: es.RecoveryRequest{UserID: 3},
	}, es.OpenRecoveryRequest)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"begin", "request.create", "commit"}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}

	if changed.Request.ID != 41 {
		t.Fatalf("the group must carry the stored records, got %+v", changed)
	}
}

func TestRecoveryRequestChangerUpdatesWithTheOptionOfTheCaller(t *testing.T) {
	op := es.WriteUpdate | es.AppendFlag | es.CancelRecoveryRequest
	fakes := newLoginFakes("", nil)

	_, err := newTestRecoveryRequestChanger(fakes).WriteOne(context.Background(), es.RecoveryGroup{
		Request: es.RecoveryRequest{CancelHash: []byte{1}},
	}, es.CancelRecoveryRequest)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"begin", "request.update", "commit"}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}

	if fakes.requests.op != op {
		t.Fatalf("the store must receive the update option of the cancel, got %b", fakes.requests.op)
	}
}

func TestRecoveryRequestChangerRollsBackAndStopsAtTheFailedStep(t *testing.T) {
	tests := []struct {
		name  string
		op    es.Op
		fail  string
		err   error
		calls []string
	}{
		{
			name:  "duplicate request",
			op:    es.OpenRecoveryRequest,
			fail:  "request.create",
			err:   es.ErrDuplicate,
			calls: []string{"begin", "request.create", "rollback"},
		},
		{
			name:  "unknown cancel token",
			op:    es.CancelRecoveryRequest,
			fail:  "request.update",
			err:   es.ErrNoUpdatedRows,
			calls: []string{"begin", "request.update", "rollback"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newLoginFakes(test.fail, test.err)

			_, err := newTestRecoveryRequestChanger(fakes).WriteOne(context.Background(), es.RecoveryGroup{}, test.op)
			if !errors.Is(err, test.err) {
				t.Fatalf("got %v, want %v", err, test.err)
			}

			if got := fakes.log.get(); !slices.Equal(got, test.calls) {
				t.Fatalf("calls %v, want %v", got, test.calls)
			}
		})
	}
}

func TestRecoveryRequestChangerRefusesAnOpWithoutAction(t *testing.T) {
	fakes := newLoginFakes("", nil)

	if _, err := newTestRecoveryRequestChanger(fakes).WriteOne(context.Background(), es.RecoveryGroup{}, 0); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("got %v", err)
	}

	if got := fakes.log.get(); len(got) != 0 {
		t.Fatalf("no call must reach the database, got %v", got)
	}
}

func newTestRecoveryGrantRedeemer(fakes loginFakes) *RecoveryGroupWriter {
	return &RecoveryGroupWriter{
		Database:          newFakeDatabase(fakes.log),
		RecoveryRequestTx: fakes.requests,
		SessionTx:         fakes.session,
	}
}

var redemption = es.RecoveryGroup{
	Request: es.RecoveryRequest{GrantHash: []byte{2}},
	Session: es.Session{
		ID:     9,
		UserID: 3,
		Flags:  es.SessionFlagRecoveryApproved,
	},
}

func TestRecoveryGrantRedeemerRedeemsInOneTransaction(t *testing.T) {
	fakes := newLoginFakes("", nil)

	_, err := newTestRecoveryGrantRedeemer(fakes).WriteOne(context.Background(), redemption, es.RedeemRecoveryGrant)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"begin",
		"session.replace",
		"session.replace",
		"session.update",
		"request.update",
		"commit",
	}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}

	if fakes.requests.op&es.UseUpRecoveryGrant == 0 || fakes.requests.received.Flags != es.RecoveryRequestFlagGranted {
		t.Fatalf("the grant update %+v with %b", fakes.requests.received, fakes.requests.op)
	}
}

func TestRecoveryGrantRedeemerIgnoresAUserWithoutOtherSessions(t *testing.T) {
	// Every replace reports that no session matched. The first one revokes the other sessions and the redeemer ignores
	// it. The second one resets the current session and the redeemer reports it.
	fakes := newLoginFakes("session.replace", es.ErrNoUpdatedRows)

	_, err := newTestRecoveryGrantRedeemer(fakes).WriteOne(context.Background(), redemption, es.RedeemRecoveryGrant)
	if !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("got %v", err)
	}

	want := []string{"begin", "session.replace", "session.replace", "rollback"}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
}

func TestRecoveryGrantRedeemerRollsBackAndStopsAtTheFailedStep(t *testing.T) {
	tests := []struct {
		name  string
		fail  string
		err   error
		calls []string
	}{
		{
			name:  "used grant",
			fail:  "request.update",
			err:   es.ErrNoUpdatedRows,
			calls: []string{"begin", "session.replace", "session.replace", "session.update", "request.update", "rollback"},
		},
		{
			name:  "revoke",
			fail:  "session.replace",
			err:   errGroupStep,
			calls: []string{"begin", "session.replace", "rollback"},
		},
		{
			name:  "bind",
			fail:  "session.update",
			err:   errGroupStep,
			calls: []string{"begin", "session.replace", "session.replace", "session.update", "rollback"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newLoginFakes(test.fail, test.err)

			_, err := newTestRecoveryGrantRedeemer(fakes).WriteOne(context.Background(), redemption, es.RedeemRecoveryGrant)
			if !errors.Is(err, test.err) {
				t.Fatalf("got %v, want %v", err, test.err)
			}

			if got := fakes.log.get(); !slices.Equal(got, test.calls) {
				t.Fatalf("calls %v, want %v", got, test.calls)
			}
		})
	}
}

func TestRecoveryGrantRedeemerRefusesAnOpWithoutUpdate(t *testing.T) {
	fakes := newLoginFakes("", nil)

	if _, err := newTestRecoveryGrantRedeemer(fakes).WriteOne(context.Background(), redemption, es.WriteCreate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("got %v", err)
	}

	if got := fakes.log.get(); len(got) != 0 {
		t.Fatalf("no call must reach the database, got %v", got)
	}
}
