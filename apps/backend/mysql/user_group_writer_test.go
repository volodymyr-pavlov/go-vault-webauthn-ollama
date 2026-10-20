package mysql

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql/expr"
)

var errEnrollStep = errors.New("the step failed")

// enrollStepTx is a fake [es.Tx] that writes the name of each call to the call log of the fake driver, so a test sees
// the order of the steps between begin and commit. failures maps a call name to the error that the call returns. locked
// is what a lock returns.
type enrollStepTx[T any, F es.Integer] struct {
	name     string
	log      *callLog
	failures map[string]error
	locked   T

	// ops holds the option of every update, in the order of the calls.
	ops []es.Op
}

func (s *enrollStepTx[T, F]) step(call string) error {
	s.log.add(s.name + "." + call)

	return s.failures[s.name+"."+call]
}

func (s *enrollStepTx[T, F]) FindOneTx(_ *sql.Tx, item T) (T, error) {
	return item, s.step("find")
}

func (s *enrollStepTx[T, F]) LockOneTx(_ *sql.Tx, item T) (T, error) {
	if err := s.step("lock"); err != nil {
		return item, err
	}

	return s.locked, nil
}

func (s *enrollStepTx[T, F]) CreateOneTx(_ *sql.Tx, item T) (T, error) {
	return item, s.step("create")
}

func (s *enrollStepTx[T, F]) UpdateOneTx(_ *sql.Tx, _ T, op es.Op) error {
	s.ops = append(s.ops, op)

	return s.step("update")
}

func (s *enrollStepTx[T, F]) ReplaceFlagOneTx(_ *sql.Tx, _, _ F, _ T) error {
	return s.step("replace")
}

// enrollPasskeyReader is a fake [es.BatchReaderTx] of passkeys.
type enrollPasskeyReader struct {
	log      *callLog
	passkeys []es.Passkey
}

func (r *enrollPasskeyReader) ReadAllTx(*sql.Tx, es.Passkey, es.Paginator, es.Op) ([]es.Passkey, error) {
	r.log.add("passkeys.read")

	return r.passkeys, nil
}

// enrollFakes holds the fake stores of one test.
type enrollFakes struct {
	log      *callLog
	failures map[string]error
	session  *enrollStepTx[es.Session, es.SessionFlag]
	passkey  *enrollStepTx[es.Passkey, es.PasskeyFlag]
	user     *enrollStepTx[es.User, es.UserFlag]
	code     *enrollStepTx[es.RecoveryCode, es.RecoveryCodeFlag]
	passkeys *enrollPasskeyReader
}

func newEnrollFakes() *enrollFakes {
	log := newCallLog()
	failures := map[string]error{}

	return &enrollFakes{
		log:      log,
		failures: failures,
		session: &enrollStepTx[es.Session, es.SessionFlag]{
			name:     "session",
			log:      log,
			failures: failures,
		},
		passkey: &enrollStepTx[es.Passkey, es.PasskeyFlag]{
			name:     "passkey",
			log:      log,
			failures: failures,
		},
		user: &enrollStepTx[es.User, es.UserFlag]{
			name:     "user",
			log:      log,
			failures: failures,
		},
		code: &enrollStepTx[es.RecoveryCode, es.RecoveryCodeFlag]{
			name:     "code",
			log:      log,
			failures: failures,
		},
		passkeys: &enrollPasskeyReader{log: log},
	}
}

func (f *enrollFakes) checkCalls(t *testing.T, want ...string) {
	t.Helper()

	if got := f.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
}

func newPasskeyRemover(f *enrollFakes) *UserGroupWriter {
	return &UserGroupWriter{
		Database:       newFakeDatabase(f.log),
		UserTx:         f.user,
		PasskeyTx:      f.passkey,
		PasskeyBatchTx: f.passkeys,
	}
}

func TestPasskeyRemover(t *testing.T) {
	f := newEnrollFakes()
	f.passkeys.passkeys = []es.Passkey{
		{ID: 1},
		{ID: 2},
	}

	group := es.UserGroup{
		Passkey: es.Passkey{ID: 1},
	}

	if _, err := newPasskeyRemover(f).WriteOne(t.Context(), group, es.WriteCreate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("create: %v", err)
	}

	if _, err := newPasskeyRemover(f).WriteOne(t.Context(), group, es.RemovePasskey); err != nil {
		t.Fatal(err)
	}

	f.checkCalls(t, "begin", "user.lock", "passkeys.read", "passkey.update", "commit")
}

func TestPasskeyRemoverKeepsTheLastFactor(t *testing.T) {
	f := newEnrollFakes()
	f.passkeys.passkeys = []es.Passkey{
		{ID: 1},
		{
			ID:    2,
			Flags: es.PasskeyFlagDisabled,
		},
	}

	group := es.UserGroup{
		Passkey: es.Passkey{ID: 1},
	}

	if _, err := newPasskeyRemover(f).WriteOne(t.Context(), group, es.RemovePasskey); !errors.Is(err, es.ErrLastFactor) {
		t.Fatalf("got %v", err)
	}

	f.checkCalls(t, "begin", "user.lock", "passkeys.read", "rollback")

	f = newEnrollFakes()
	f.passkeys.passkeys = []es.Passkey{{ID: 1}}
	f.user.locked = es.User{
		TOTPCiphertext: "vault:v1:x",
		Flags:          es.UserFlagTOTPConfirmed,
	}

	if _, err := newPasskeyRemover(f).WriteOne(t.Context(), group, es.RemovePasskey); err != nil {
		t.Fatalf("with a TOTP factor: %v", err)
	}
}

func TestPasskeyRemoverStopsOnFailure(t *testing.T) {
	f := newEnrollFakes()
	f.passkeys.passkeys = []es.Passkey{
		{ID: 1},
		{ID: 2},
	}
	f.failures["passkey.update"] = errEnrollStep

	if _, err := newPasskeyRemover(f).WriteOne(t.Context(), es.UserGroup{}, es.RemovePasskey); !errors.Is(err, errEnrollStep) {
		t.Fatalf("got %v", err)
	}

	f.checkCalls(t, "begin", "user.lock", "passkeys.read", "passkey.update", "rollback")
}

func TestTOTPEnroller(t *testing.T) {
	f := newEnrollFakes()
	writer := &UserGroupWriter{
		Database: newFakeDatabase(f.log),
		UserTx:   f.user,
	}

	if _, err := writer.WriteOne(t.Context(), es.UserGroup{}, es.WriteCreate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("create: %v", err)
	}

	if _, err := writer.WriteOne(t.Context(), es.UserGroup{}, es.ConfirmTOTP); err != nil {
		t.Fatal(err)
	}

	f.checkCalls(t, "begin", "user.update", "commit")
}

func newTOTPRemover(f *enrollFakes) *UserGroupWriter {
	return &UserGroupWriter{
		Database:       newFakeDatabase(f.log),
		UserTx:         f.user,
		PasskeyBatchTx: f.passkeys,
	}
}

func TestTOTPRemover(t *testing.T) {
	f := newEnrollFakes()
	f.user.locked = es.User{TOTPCiphertext: "vault:v1:x"}
	f.passkeys.passkeys = []es.Passkey{{ID: 1}}

	if _, err := newTOTPRemover(f).WriteOne(t.Context(), es.UserGroup{}, es.WriteCreate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("create: %v", err)
	}

	if _, err := newTOTPRemover(f).WriteOne(t.Context(), es.UserGroup{}, es.RemoveTOTP); err != nil {
		t.Fatal(err)
	}

	f.checkCalls(t, "begin", "user.lock", "passkeys.read", "user.update", "commit")
}

func TestTOTPRemoverRefuses(t *testing.T) {
	f := newEnrollFakes()

	if _, err := newTOTPRemover(f).WriteOne(t.Context(), es.UserGroup{}, es.RemoveTOTP); !errors.Is(err, es.ErrNoTOTPSecret) {
		t.Fatalf("no secret: %v", err)
	}

	f.checkCalls(t, "begin", "user.lock", "rollback")

	f = newEnrollFakes()
	f.user.locked = es.User{TOTPCiphertext: "vault:v1:x"}
	f.passkeys.passkeys = []es.Passkey{{
		ID:    1,
		Flags: es.PasskeyFlagRemoved,
	}}

	if _, err := newTOTPRemover(f).WriteOne(t.Context(), es.UserGroup{}, es.RemoveTOTP); !errors.Is(err, es.ErrLastFactor) {
		t.Fatalf("last factor: %v", err)
	}

	f.checkCalls(t, "begin", "user.lock", "passkeys.read", "rollback")
}

// TestDeleteUserRunsEveryDeleteInOrder proves that the deletion locks the user first, deletes the children before the
// user, erases the request log by the external ID, and fails as a whole if a delete fails.
func TestDeleteUserRunsEveryDeleteInOrder(t *testing.T) {
	f := newEnrollFakes()
	f.user.locked = es.User{
		ID:      4,
		UserXID: 99,
	}
	writer := &UserGroupWriter{
		Database: newFakeDatabase(f.log),
		UserTx:   f.user,
	}

	group, err := writer.WriteOne(context.Background(), es.UserGroup{
		User: es.User{
			ID: 4,
		},
	}, es.DeleteUser)
	if err != nil {
		t.Fatal(err)
	}

	if group.User.UserXID != 99 {
		t.Fatalf("the group must carry the locked user, got %+v", group.User)
	}

	for query, key := range map[string]int64{
		expr.DeleteUserRecoveryRequests: 4,
		expr.DeleteUserRecoveryCodes:    4,
		expr.DeleteUserPasskeys:         4,
		expr.DeleteUserSessions:         4,
		expr.EraseUserHTTPRequests:      99,
		expr.DeleteUser:                 4,
	} {
		args := f.log.argsOf(t, query)
		if len(args) != 1 || args[0] != key {
			t.Fatalf("the statement %q takes the key %d, got %v", query, key, args)
		}
	}

	calls := f.log.get()
	if len(calls) < 2 || calls[1] != "user.lock" {
		t.Fatalf("the user is locked first, got %v", calls)
	}
}
