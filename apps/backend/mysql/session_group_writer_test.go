package mysql

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

var errGroupStep = errors.New("the step failed")

// groupStepTx is a fake [es.Tx] that writes the name of each call to the log and fails on the call that failOn names.
type groupStepTx[T any, F es.Integer] struct {
	name   string
	log    *callLog
	failOn string
	err    error

	// created is what CreateOneTx returns.
	created T

	// received holds the argument of the last call.
	received T
	op       es.Op

	// ops holds the option of every update, in the order of the calls.
	ops []es.Op
}

func (s *groupStepTx[T, F]) step(call string, item T) error {
	s.log.add(s.name + "." + call)
	s.received = item

	if s.failOn == call {
		return s.err
	}

	return nil
}

func (s *groupStepTx[T, F]) FindOneTx(_ *sql.Tx, item T) (T, error) {
	return item, s.step("find", item)
}

func (s *groupStepTx[T, F]) LockOneTx(_ *sql.Tx, item T) (T, error) {
	return item, s.step("lock", item)
}

func (s *groupStepTx[T, F]) CreateOneTx(_ *sql.Tx, item T) (T, error) {
	if err := s.step("create", item); err != nil {
		return item, err
	}

	return s.created, nil
}

func (s *groupStepTx[T, F]) UpdateOneTx(_ *sql.Tx, item T, op es.Op) error {
	s.op = op
	s.ops = append(s.ops, op)

	return s.step("update", item)
}

func (s *groupStepTx[T, F]) ReplaceFlagOneTx(_ *sql.Tx, _, _ F, item T) error {
	return s.step("replace", item)
}

type groupFakes struct {
	log     *callLog
	users   *groupStepTx[es.User, es.UserFlag]
	session *groupStepTx[es.Session, es.SessionFlag]
}

func newGroupFakes(failOn string, err error) groupFakes {
	log := newCallLog()
	fakes := groupFakes{
		log: log,
		users: &groupStepTx[es.User, es.UserFlag]{
			name:    "user",
			log:     log,
			created: es.User{ID: 31},
		},
		session: &groupStepTx[es.Session, es.SessionFlag]{
			name: "session",
			log:  log,
		},
	}

	for _, store := range []interface{ fail(string, error) }{fakes.users, fakes.session} {
		store.fail(failOn, err)
	}

	return fakes
}

// fail makes the store fail on call when the call is named "<store>.<call>" for this store.
func (s *groupStepTx[T, F]) fail(failOn string, err error) {
	prefix := s.name + "."
	if len(failOn) > len(prefix) && failOn[:len(prefix)] == prefix {
		s.failOn = failOn[len(prefix):]
		s.err = err
	}
}

func TestRegistryOpenerCreatesTheAccountBindsTheSession(t *testing.T) {
	fakes := newGroupFakes("", nil)
	opener := &SessionGroupWriter{
		Database:  newFakeDatabase(fakes.log),
		UserTx:    fakes.users,
		SessionTx: fakes.session,
	}

	opened, err := opener.WriteOne(context.Background(), es.SessionGroup{
		Session: es.Session{ID: 9},
	}, es.OpenRegistry)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"begin", "user.create", "session.update", "commit"}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}

	if fakes.session.received.UserID != 31 || opened.User.ID != 31 {
		t.Fatalf("the session must bind to the created user, got %+v and %+v", fakes.session.received, opened)
	}

	if fakes.session.op != es.WriteUpdate|es.AppendFlag {
		t.Fatalf("the session update op is %v", fakes.session.op)
	}
}

func TestRegistryOpenerForATakenEmailCreatesNoUser(t *testing.T) {
	fakes := newGroupFakes("", nil)
	opener := &SessionGroupWriter{
		Database:  newFakeDatabase(fakes.log),
		UserTx:    fakes.users,
		SessionTx: fakes.session,
	}

	_, err := opener.WriteOne(context.Background(), es.SessionGroup{
		Session: es.Session{ID: 9},
	}, es.OpenTakenRegistry)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"begin", "session.update", "commit"}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}

	if fakes.session.received.UserID != 0 {
		t.Fatalf("the session must stay unbound, got %+v", fakes.session.received)
	}
}

func TestRegistryOpenerRollsBackAndStopsAtTheFailedStep(t *testing.T) {
	tests := []struct {
		name  string
		fail  string
		err   error
		calls []string
	}{
		{
			name:  "duplicate email",
			fail:  "user.create",
			err:   es.ErrDuplicate,
			calls: []string{"begin", "user.create", "rollback"},
		},
		{
			name:  "missing session",
			fail:  "session.update",
			err:   es.ErrNoUpdatedRows,
			calls: []string{"begin", "user.create", "session.update", "rollback"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newGroupFakes(test.fail, test.err)
			opener := &SessionGroupWriter{
				Database:  newFakeDatabase(fakes.log),
				UserTx:    fakes.users,
				SessionTx: fakes.session,
			}

			_, err := opener.WriteOne(context.Background(), es.SessionGroup{}, es.OpenRegistry)
			if !errors.Is(err, test.err) {
				t.Fatalf("got %v, want %v", err, test.err)
			}

			if got := fakes.log.get(); !slices.Equal(got, test.calls) {
				t.Fatalf("calls %v, want %v", got, test.calls)
			}
		})
	}
}

func TestRegistryOpenerRefusesAnOpWithoutAction(t *testing.T) {
	fakes := newGroupFakes("", nil)
	opener := &SessionGroupWriter{
		Database:  newFakeDatabase(fakes.log),
		UserTx:    fakes.users,
		SessionTx: fakes.session,
	}

	if _, err := opener.WriteOne(context.Background(), es.SessionGroup{}, 0); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("got %v", err)
	}

	if got := fakes.log.get(); len(got) != 0 {
		t.Fatalf("no call must reach the database, got %v", got)
	}
}

func TestRegistryVerifierVerifiesInOneTransaction(t *testing.T) {
	fakes := newGroupFakes("", nil)
	verifier := &SessionGroupWriter{
		Database:  newFakeDatabase(fakes.log),
		UserTx:    fakes.users,
		SessionTx: fakes.session,
	}

	_, err := verifier.WriteOne(context.Background(), es.SessionGroup{
		User:    es.User{ID: 31},
		Session: es.Session{ID: 9},
	}, es.VerifyRegistry)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"begin", "user.update", "session.update", "commit"}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}

	if fakes.session.op != es.WriteUpdate|es.AppendFlag|es.ClearVerifyToken {
		t.Fatalf("the session update must clear the verification token, got %v", fakes.session.op)
	}
}

func TestRegistryVerifierRollsBackAndStopsAtTheFailedStep(t *testing.T) {
	tests := []struct {
		name  string
		fail  string
		calls []string
	}{
		{
			name:  "missing user",
			fail:  "user.update",
			calls: []string{"begin", "user.update", "rollback"},
		},
		{
			name:  "missing session",
			fail:  "session.update",
			calls: []string{"begin", "user.update", "session.update", "rollback"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newGroupFakes(test.fail, es.ErrNoUpdatedRows)
			verifier := &SessionGroupWriter{
				Database:  newFakeDatabase(fakes.log),
				UserTx:    fakes.users,
				SessionTx: fakes.session,
			}

			_, err := verifier.WriteOne(context.Background(), es.SessionGroup{}, es.VerifyRegistry)
			if !errors.Is(err, es.ErrNoUpdatedRows) {
				t.Fatalf("got %v", err)
			}

			if got := fakes.log.get(); !slices.Equal(got, test.calls) {
				t.Fatalf("calls %v, want %v", got, test.calls)
			}
		})
	}

	fakes := newGroupFakes("", nil)
	verifier := &SessionGroupWriter{
		Database:  newFakeDatabase(fakes.log),
		UserTx:    fakes.users,
		SessionTx: fakes.session,
	}

	if _, err := verifier.WriteOne(context.Background(), es.SessionGroup{}, es.WriteCreate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("a create: %v", err)
	}

	if _, err := verifier.WriteOne(context.Background(), es.SessionGroup{}, 0); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("no option: %v", err)
	}
}

func TestSessionRevokerRevokesInOneTransaction(t *testing.T) {
	fakes := newGroupFakes("", nil)
	revoker := &SessionGroupWriter{
		Database:  newFakeDatabase(fakes.log),
		SessionTx: fakes.session,
	}

	_, err := revoker.WriteOne(context.Background(), es.SessionGroup{
		Session: es.Session{ID: 9},
	}, es.RevokeSession)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"begin", "session.replace", "commit"}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
}

func TestSessionRevokerRollsBackAndStopsAtTheFailedStep(t *testing.T) {
	tests := []struct {
		name  string
		fail  string
		calls []string
	}{
		{
			name:  "missing session",
			fail:  "session.replace",
			calls: []string{"begin", "session.replace", "rollback"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newGroupFakes(test.fail, es.ErrNoUpdatedRows)
			revoker := &SessionGroupWriter{
				Database:  newFakeDatabase(fakes.log),
				SessionTx: fakes.session,
			}

			_, err := revoker.WriteOne(context.Background(), es.SessionGroup{}, es.RevokeSession)
			if !errors.Is(err, es.ErrNoUpdatedRows) {
				t.Fatalf("got %v", err)
			}

			if got := fakes.log.get(); !slices.Equal(got, test.calls) {
				t.Fatalf("calls %v, want %v", got, test.calls)
			}
		})
	}

	fakes := newGroupFakes("", nil)
	revoker := &SessionGroupWriter{
		Database:  newFakeDatabase(fakes.log),
		SessionTx: fakes.session,
	}

	if _, err := revoker.WriteOne(context.Background(), es.SessionGroup{}, es.WriteCreate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("a create: %v", err)
	}

	if _, err := revoker.WriteOne(context.Background(), es.SessionGroup{}, 0); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("no option: %v", err)
	}
}
