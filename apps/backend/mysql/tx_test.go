package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Masterminds/squirrel"
	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql/expr"
)

// fakeRows is the answer of the fake driver to a query.
type fakeRows struct {
	columns []string
	data    [][]driver.Value
}

// fakeStatement is a statement that the fake driver received, with its arguments.
type fakeStatement struct {
	query string
	args  []driver.Value
}

// callLog records the steps of one test in order: the transaction steps and the full text of each statement. The fake
// driver fills it, and the test reads it.
type callLog struct {
	mu         sync.Mutex
	calls      []string
	statements []fakeStatement

	// answers holds the rows that a query returns. A query that is not here returns no rows.
	answers map[string]fakeRows

	// execErrs holds the error that a statement returns. affected holds the number of rows that it changes. A
	// statement that is not in affected changes one row. affectedRuns holds one count for each run of a statement, in
	// order, and takes priority over affected while it has counts left.
	execErrs     map[string]error
	affected     map[string]int64
	affectedRuns map[string][]int64

	// lastID is the key that every insert reports.
	lastID int64
}

func newCallLog() *callLog {
	return &callLog{
		answers:      map[string]fakeRows{},
		execErrs:     map[string]error{},
		affected:     map[string]int64{},
		affectedRuns: map[string][]int64{},
		lastID:       7,
	}
}

func (l *callLog) add(call string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls = append(l.calls, call)
}

func (l *callLog) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return slices.Clone(l.calls)
}

// argsOf returns the arguments of the first statement with the text query.
func (l *callLog) argsOf(t *testing.T, query string) []driver.Value {
	t.Helper()

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, run := range l.statements {
		if run.query == query {
			return run.args
		}
	}

	t.Fatalf("the statement was not run: %s", query)

	return nil
}

// fakeConnector hands a connection that records its statements to every request of the pool.
type fakeConnector struct {
	log *callLog
}

func (c *fakeConnector) Connect(context.Context) (driver.Conn, error) {
	return &fakeConn{log: c.log}, nil
}

func (c *fakeConnector) Driver() driver.Driver {
	return &fakeDriver{log: c.log}
}

type fakeDriver struct {
	log *callLog
}

func (d *fakeDriver) Open(string) (driver.Conn, error) {
	return &fakeConn{log: d.log}, nil
}

var _ driver.ExecerContext = &fakeConn{}
var _ driver.QueryerContext = &fakeConn{}

type fakeConn struct {
	log *callLog
}

func (c *fakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("the fake driver runs no prepared statements")
}

func (c *fakeConn) Close() error {
	return nil
}

func (c *fakeConn) Begin() (driver.Tx, error) {
	c.log.add("begin")

	return &fakeTx{log: c.log}, nil
}

func (c *fakeConn) record(query string, named []driver.NamedValue) {
	args := make([]driver.Value, len(named))
	for i, arg := range named {
		args[i] = arg.Value
	}

	c.log.mu.Lock()
	defer c.log.mu.Unlock()

	c.log.calls = append(c.log.calls, query)
	c.log.statements = append(c.log.statements, fakeStatement{
		query: query,
		args:  args,
	})
}

func (c *fakeConn) ExecContext(_ context.Context, query string, named []driver.NamedValue) (driver.Result, error) {
	c.record(query, named)

	if err := c.log.execErrs[query]; err != nil {
		return nil, err
	}

	affected, ok := c.log.affected[query]
	if !ok {
		affected = 1
	}

	if runs := c.log.affectedRuns[query]; len(runs) > 0 {
		affected = runs[0]
		c.log.affectedRuns[query] = runs[1:]
	}

	return fakeResult{
		lastID:   c.log.lastID,
		affected: affected,
	}, nil
}

func (c *fakeConn) QueryContext(_ context.Context, query string, named []driver.NamedValue) (driver.Rows, error) {
	c.record(query, named)

	answer := c.log.answers[query]

	return &fakeRowsReader{
		answer: answer,
	}, nil
}

type fakeRowsReader struct {
	answer fakeRows
	next   int
}

func (r *fakeRowsReader) Columns() []string {
	return r.answer.columns
}

func (r *fakeRowsReader) Close() error {
	return nil
}

func (r *fakeRowsReader) Next(dest []driver.Value) error {
	if r.next >= len(r.answer.data) {
		return io.EOF
	}

	copy(dest, r.answer.data[r.next])
	r.next++

	return nil
}

type fakeTx struct {
	log *callLog
}

func (t *fakeTx) Commit() error {
	t.log.add("commit")

	return nil
}

func (t *fakeTx) Rollback() error {
	t.log.add("rollback")

	return nil
}

// fakeResult reports the key and the number of rows that the log holds for a statement.
type fakeResult struct {
	lastID   int64
	affected int64
}

func (r fakeResult) LastInsertId() (int64, error) {
	return r.lastID, nil
}

func (r fakeResult) RowsAffected() (int64, error) {
	return r.affected, nil
}

// newFakeDatabase returns a database whose connections run on log.
func newFakeDatabase(log *callLog) *sql.DB {
	return sql.OpenDB(&fakeConnector{log: log})
}

// beginFake begins a transaction on a new fake database.
func beginFake(t *testing.T) (*sql.Tx, *callLog) {
	t.Helper()

	log := newCallLog()

	tx, err := newFakeDatabase(log).Begin()
	if err != nil {
		t.Fatal(err)
	}

	return tx, log
}

var fakeNow = time.Date(2026, time.October, 16, 12, 0, 0, 123456789, time.UTC)

func newFakeClock() *clock.FixedClock {
	return &clock.FixedClock{
		Time: fakeNow,
	}
}

// updatesTable reports whether the statement is an update of the table that a squirrel builder wrote.
func updatesTable(log *callLog, table string) bool {
	log.mu.Lock()
	defer log.mu.Unlock()

	for _, run := range log.statements {
		if strings.HasPrefix(run.query, "UPDATE "+table+" SET ") {
			return true
		}
	}

	return false
}

func TestSessionTxCreateLockReplaceUpdate(t *testing.T) {
	tx, log := beginFake(t)
	store := &SessionTx{
		SystemClock: newFakeClock(),
		UpdateSessionBuilder: &UpdateSessionBuilder{
			QueryBuilder: squirrel.StatementBuilder,
		},
	}

	created, err := store.CreateOneTx(tx, es.Session{
		SessionXID: 11,
		ExpiresAt:  fakeNow.Add(time.Hour),
	})
	if err != nil || created.ID != 7 || !created.CreatedAt.Equal(fakeNow) {
		t.Fatalf("create: %+v, %v", created, err)
	}

	if got := len(log.argsOf(t, expr.CreateSession)); got != 20 {
		t.Fatalf("the insert has %d arguments, want 20", got)
	}

	if _, err := store.LockOneTx(tx, es.Session{}); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("lock without arguments: %v", err)
	}

	if _, err := store.LockOneTx(tx, es.Session{ID: 7}); !errors.Is(err, es.ErrNotFound) {
		t.Fatalf("lock of a missing session: %v", err)
	}

	if _, err := store.LockOneTx(tx, es.Session{SessionXID: 11}); !errors.Is(err, es.ErrNotFound) {
		t.Fatalf("lock by the external ID: %v", err)
	}

	if _, err := store.FindOneTx(tx, es.Session{ID: 7}); !errors.Is(err, es.ErrNotFound) {
		t.Fatalf("find of a missing session: %v", err)
	}

	if err := store.ReplaceFlagOneTx(tx, es.SessionFlagAuthorized, es.SessionFlagRevoked, es.Session{ID: 7}); err != nil {
		t.Fatalf("replace one: %v", err)
	}

	if err := store.ReplaceFlagOneTx(tx, es.SessionFlagAuthorized, es.SessionFlagRevoked, es.Session{UserID: 3}); err != nil {
		t.Fatalf("replace all of a user: %v", err)
	}

	if err := store.ReplaceFlagOneTx(tx, 0, 0, es.Session{}); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("replace without arguments: %v", err)
	}

	log.affected[expr.ReplaceSessionFlags] = 0

	if err := store.ReplaceFlagOneTx(tx, 0, 0, es.Session{ID: 9}); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("replace of a missing session: %v", err)
	}

	if err := store.UpdateOneTx(tx, es.Session{
		ID:       7,
		Failures: 2,
	}, es.WriteUpdate); err != nil {
		t.Fatalf("update: %v", err)
	}

	if !updatesTable(log, "sessions") {
		t.Fatal("the update builder statement was not run")
	}

	want := []string{
		"begin",
		expr.CreateSession,
		expr.SessionByIDForUpdate,
		expr.SessionBySessionXIDForUpdate,
		expr.SessionByID,
		expr.ReplaceSessionFlags,
		expr.ReplaceSessionFlagsByUser,
		expr.ReplaceSessionFlags,
	}

	if got := log.get(); !slices.Equal(got[:len(want)], want) {
		t.Fatalf("calls %v, want the start %v", got, want)
	}
}

func TestSessionTxCreateReportsDuplicate(t *testing.T) {
	tx, log := beginFake(t)
	log.execErrs[expr.CreateSession] = &mysqldriver.MySQLError{Number: 1062}

	store := &SessionTx{
		SystemClock: newFakeClock(),
	}

	if _, err := store.CreateOneTx(tx, es.Session{}); !errors.Is(err, es.ErrDuplicate) {
		t.Fatalf("got %v", err)
	}
}

func TestPasskeyTxCreateLockReplaceUpdate(t *testing.T) {
	tx, log := beginFake(t)
	store := &PasskeyTx{
		SystemClock: newFakeClock(),
		UpdatePasskeyBuilder: &UpdatePasskeyBuilder{
			QueryBuilder: squirrel.StatementBuilder,
		},
	}

	created, err := store.CreateOneTx(tx, es.Passkey{
		PasskeyXID:   21,
		UserID:       3,
		CredentialID: []byte{1},
	})
	if err != nil || created.ID != 7 || !created.CreatedAt.Equal(fakeNow) || len(created.AAGUID) != 0 {
		t.Fatalf("create: %+v, %v", created, err)
	}

	args := log.argsOf(t, expr.CreatePasskey)
	if len(args) != 12 {
		t.Fatalf("the insert has %d arguments, want 12", len(args))
	}

	// The returned passkey keeps its empty AAGUID, and the database gets the default blob so that no column is NULL.
	if aaguid, ok := args[8].([]byte); !ok || len(aaguid) != 1 {
		t.Fatalf("the insert must receive the default blob for the AAGUID, got %#v", args[8])
	}

	for _, args := range []es.Passkey{
		{ID: 1},
		{PasskeyXID: 2},
		{CredentialID: []byte{3}},
	} {
		if _, err := store.LockOneTx(tx, args); !errors.Is(err, es.ErrNotFound) {
			t.Fatalf("lock of %+v: %v", args, err)
		}
	}

	if _, err := store.FindOneTx(tx, es.Passkey{}); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("find without arguments: %v", err)
	}

	if err := store.ReplaceFlagOneTx(tx, 0, es.PasskeyFlagDisabled, es.Passkey{ID: 4}); err != nil {
		t.Fatalf("replace: %v", err)
	}

	if err := store.ReplaceFlagOneTx(tx, 0, 0, es.Passkey{}); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("replace without arguments: %v", err)
	}

	if err := store.UpdateOneTx(tx, es.Passkey{
		ID:        4,
		SignCount: 9,
	}, es.WriteUpdate); err != nil {
		t.Fatalf("update: %v", err)
	}

	if !updatesTable(log, "passkeys") {
		t.Fatal("the update builder statement was not run")
	}

	want := []string{
		"begin",
		expr.CreatePasskey,
		expr.PasskeyByIDForUpdate,
		expr.PasskeyByPasskeyXIDForUpdate,
		expr.PasskeyByCredentialIDForUpdate,
		expr.ReplacePasskeyFlags,
	}

	if got := log.get(); !slices.Equal(got[:len(want)], want) {
		t.Fatalf("calls %v, want the start %v", got, want)
	}
}

func TestRecoveryCodeTx(t *testing.T) {
	tx, log := beginFake(t)
	store := &RecoveryCodeTx{
		SystemClock: newFakeClock(),
	}

	created, err := store.CreateOneTx(tx, es.RecoveryCode{
		RecoveryCodeXID: 31,
		UserID:          3,
		MAC:             "mac",
	})
	if err != nil || created.ID != 7 || !created.CreatedAt.Equal(fakeNow) {
		t.Fatalf("create: %+v, %v", created, err)
	}

	code := es.RecoveryCode{
		Flags:  es.RecoveryCodeFlagUsed,
		UserID: 3,
		MAC:    "mac",
	}

	if err := store.UpdateOneTx(tx, code, es.WriteUpdate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("update without the option: %v", err)
	}

	if err := store.UpdateOneTx(tx, code, es.WriteUpdate|es.UseUpRecoveryCode); err != nil {
		t.Fatalf("use up: %v", err)
	}

	log.affected[expr.UseRecoveryCode] = 0

	if err := store.UpdateOneTx(tx, code, es.WriteUpdate|es.UseUpRecoveryCode); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("use up of a used code: %v", err)
	}

	if err := store.ReplaceFlagOneTx(tx, 0, es.RecoveryCodeFlagUsed, es.RecoveryCode{UserID: 3}); err != nil {
		t.Fatalf("replace: %v", err)
	}

	if err := store.ReplaceFlagOneTx(tx, 0, 0, es.RecoveryCode{}); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("replace without a user: %v", err)
	}

	if _, err := store.FindOneTx(tx, code); !errors.Is(err, es.ErrNoMethod) {
		t.Fatalf("find: %v", err)
	}

	if _, err := store.LockOneTx(tx, code); !errors.Is(err, es.ErrNoMethod) {
		t.Fatalf("lock: %v", err)
	}

	want := []string{
		"begin",
		expr.CreateRecoveryCode,
		expr.UseRecoveryCode,
		expr.UseRecoveryCode,
		expr.ReplaceRecoveryCodeFlagsByUser,
	}

	if got := log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
}

func TestRecoveryRequestTx(t *testing.T) {
	tx, log := beginFake(t)
	store := &RecoveryRequestTx{
		SystemClock: newFakeClock(),
	}

	created, err := store.CreateOneTx(tx, es.RecoveryRequest{
		RecoveryRequestXID: 41,
		UserID:             3,
		CancelHash:         []byte{1},
		ReadyAt:            fakeNow.Add(time.Hour),
	})
	if err != nil || created.ID != 7 || !created.CreatedAt.Equal(fakeNow) {
		t.Fatalf("create: %+v, %v", created, err)
	}

	updates := []struct {
		name  string
		item  es.RecoveryRequest
		op    es.Op
		query string
	}{
		{
			name: "cancel",
			item: es.RecoveryRequest{
				Flags:      es.RecoveryRequestFlagCancelled,
				CancelHash: []byte{1},
			},
			op:    es.WriteUpdate | es.CancelRecoveryRequest,
			query: expr.CancelRecoveryRequest,
		},
		{
			name: "approve",
			item: es.RecoveryRequest{
				Flags:              es.RecoveryRequestFlagApproved,
				RecoveryRequestXID: 41,
			},
			op:    es.WriteUpdate | es.ApproveRecoveryRequest,
			query: expr.ApproveRecoveryRequest,
		},
		{
			name: "issue",
			item: es.RecoveryRequest{
				ID:             7,
				GrantHash:      []byte{2},
				GrantExpiresAt: fakeNow.Add(time.Hour),
			},
			op:    es.WriteUpdate | es.IssueRecoveryGrant,
			query: expr.IssueRecoveryGrant,
		},
		{
			name: "use up",
			item: es.RecoveryRequest{
				Flags:     es.RecoveryRequestFlagGranted,
				GrantHash: []byte{2},
			},
			op:    es.WriteUpdate | es.UseUpRecoveryGrant,
			query: expr.UseUpRecoveryGrant,
		},
	}

	want := make([]string, 0, 12)
	want = append(want, "begin", expr.CreateRecoveryRequest)
	for _, update := range updates {
		if err := store.UpdateOneTx(tx, update.item, update.op); err != nil {
			t.Fatalf("%s: %v", update.name, err)
		}

		want = append(want, update.query)
	}

	if err := store.UpdateOneTx(tx, es.RecoveryRequest{}, es.WriteUpdate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("update without an option: %v", err)
	}

	log.affected[expr.UseUpRecoveryGrant] = 0

	if err := store.UpdateOneTx(tx, updates[3].item, updates[3].op); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("use up of a used grant: %v", err)
	}

	want = append(want, expr.UseUpRecoveryGrant)

	if _, err := store.LockOneTx(tx, es.RecoveryRequest{UserID: 3}); !errors.Is(err, es.ErrNotFound) {
		t.Fatalf("lock by the user: %v", err)
	}

	if _, err := store.LockOneTx(tx, es.RecoveryRequest{GrantHash: []byte{2}}); !errors.Is(err, es.ErrNotFound) {
		t.Fatalf("lock by the grant: %v", err)
	}

	if _, err := store.FindOneTx(tx, es.RecoveryRequest{}); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("find without arguments: %v", err)
	}

	want = append(want, expr.RecoveryRequestByUserForUpdate, expr.RecoveryRequestByGrantHashForUpdate)

	if err := store.ReplaceFlagOneTx(tx, 0, es.RecoveryRequestFlagCancelled, es.RecoveryRequest{UserID: 3}); err != nil {
		t.Fatalf("replace: %v", err)
	}

	if err := store.ReplaceFlagOneTx(tx, 0, 0, es.RecoveryRequest{}); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("replace without a user: %v", err)
	}

	want = append(want, expr.CancelRecoveryRequestsByUser)

	if got := log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
}

func TestUserTx(t *testing.T) {
	tx, log := beginFake(t)
	store := &UserTx{
		SystemClock: newFakeClock(),
		UpdateUserBuilder: &UpdateUserBuilder{
			QueryBuilder: squirrel.StatementBuilder,
		},
	}

	created, err := store.CreateOneTx(tx, es.User{
		UserXID: 51,
		Email:   "a@example.com",
		Handle:  []byte{1},
	})
	if err != nil || created.ID != 7 || !created.CreatedAt.Equal(fakeNow) {
		t.Fatalf("create: %+v, %v", created, err)
	}

	if got := len(log.argsOf(t, expr.CreateUser)); got != 9 {
		t.Fatalf("the insert has %d arguments, want 9", got)
	}

	for _, args := range []es.User{
		{ID: 1},
		{UserXID: 2},
		{Handle: []byte{3}},
		{Email: "b@example.com"},
	} {
		if _, err := store.FindOneTx(tx, args); !errors.Is(err, es.ErrNotFound) {
			t.Fatalf("find of %+v: %v", args, err)
		}
	}

	if _, err := store.FindOneTx(tx, es.User{}); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("find without arguments: %v", err)
	}

	if _, err := store.LockOneTx(tx, es.User{}); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("lock without arguments: %v", err)
	}

	if _, err := store.LockOneTx(tx, es.User{ID: 7}); !errors.Is(err, es.ErrNotFound) {
		t.Fatalf("lock of a missing user: %v", err)
	}

	if err := store.ReplaceFlagOneTx(tx, 0, es.UserFlagVerified, es.User{ID: 7}); err != nil {
		t.Fatalf("replace: %v", err)
	}

	if err := store.ReplaceFlagOneTx(tx, 0, 0, es.User{}); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("replace without arguments: %v", err)
	}

	if err := store.UpdateOneTx(tx, es.User{
		ID:           7,
		PasswordHash: "x",
	}, es.WriteUpdate); err != nil {
		t.Fatalf("update: %v", err)
	}

	if !updatesTable(log, "users") {
		t.Fatal("the update builder statement was not run")
	}

	want := []string{
		"begin",
		expr.CreateUser,
		expr.UserByID,
		expr.UserByUserXID,
		expr.UserByHandle,
		expr.UserByEmail,
		expr.UserByIDForUpdate,
		expr.ReplaceUserFlags,
	}

	if got := log.get(); !slices.Equal(got[:len(want)], want) {
		t.Fatalf("calls %v, want the start %v", got, want)
	}
}
