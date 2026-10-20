// Package mysql implements the store interfaces of the [es] package on MySQL. It has one file for each table. Each
// file holds the readers, writers, replacers and update builders of the table. The package reads and writes rows and
// contains no business rules.
//
// [Open] connects to the database and applies the migrations, so a new database is ready after one call.
package mysql

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

//go:embed migrations/*.sql
var migrations embed.FS

// MigrationTable is the name of the table where goose records the applied migrations.
const MigrationTable = "schema_version"

// OpenOptions holds the settings of the database connection.
type OpenOptions struct {
	// DSN is the data source name, in the form user:password@tcp(host:port)/database. [Open] adds the parseTime
	// option, the UTC location, the multi-statement mode for the migrations and the found-rows mode.
	DSN string

	// MaxOpenConns and MaxIdleConns limit the connection pool. Zero selects 8 and 4.
	MaxOpenConns int
	MaxIdleConns int

	// ConnMaxLifetime is how long the pool reuses a connection. Zero selects 30 minutes.
	ConnMaxLifetime time.Duration
}

// Open connects to the database that opts describes, checks the connection and applies the missing migrations. The
// caller closes the returned database.
//
// It returns [ErrNoDSN] if the data source name is empty.
func Open(ctx context.Context, opts OpenOptions) (*sql.DB, error) {
	if opts.DSN == "" {
		return nil, ErrNoDSN
	}

	config, err := mysql.ParseDSN(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse the DSN: %w", err)
	}

	config.ParseTime = true
	config.Loc = time.UTC
	config.MultiStatements = true
	// With this option an update reports the rows that it matched, not the rows that it changed. So an update that
	// writes the same value again is not mistaken for an update that found no row.
	config.ClientFoundRows = true

	connector, err := mysql.NewConnector(config)
	if err != nil {
		return nil, fmt.Errorf("make the connector: %w", err)
	}

	db := sql.OpenDB(connector)

	if opts.MaxOpenConns == 0 {
		opts.MaxOpenConns = 8
	}

	if opts.MaxIdleConns == 0 {
		opts.MaxIdleConns = 4
	}

	if opts.ConnMaxLifetime == 0 {
		opts.ConnMaxLifetime = 30 * time.Minute
	}

	db.SetMaxOpenConns(opts.MaxOpenConns)
	db.SetMaxIdleConns(opts.MaxIdleConns)
	db.SetConnMaxLifetime(opts.ConnMaxLifetime)

	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("ping the database: %w", err), db.Close())
	}

	if err := Migrate(ctx, db); err != nil {
		return nil, errors.Join(err, db.Close())
	}

	return db, nil
}

// migrationLock is the name of the MySQL lock that serializes the migrations of several instances that start together.
const migrationLock = "login_migrations"

// migrationLockWait is how many seconds an instance waits for the migration lock.
const migrationLockWait = 120

// Migrate applies the migrations that db does not have. It holds a MySQL lock while it works, so several instances that
// start at the same time apply each migration once: the first one migrates, and the others wait and find nothing to do.
//
// It returns an error if it cannot get the lock in two minutes.
func Migrate(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("take a connection for the migration lock: %w", err)
	}
	defer conn.Close()

	var got sql.NullInt64

	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", migrationLock, migrationLockWait).Scan(&got); err != nil {
		return fmt.Errorf("get the migration lock: %w", err)
	}

	if !got.Valid || got.Int64 != 1 {
		return fmt.Errorf("get the migration lock: %w", ErrMigrationLock)
	}
	defer func() {
		// The lock also ends with the connection, so a failure here changes nothing.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT RELEASE_LOCK(?)", migrationLock)
	}()

	files, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("open the migrations: %w", err)
	}

	provider, err := goose.NewProvider(goose.DialectMySQL, db, files,
		goose.WithTableName(MigrationTable),
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return fmt.Errorf("build the migration provider: %w", err)
	}

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply the migrations: %w", err)
	}

	return nil
}

// NewQueryBuilder returns the statement builder that the stores use. It runs its statements on db.
func NewQueryBuilder(db *sql.DB) squirrel.StatementBuilderType {
	return squirrel.StatementBuilder.RunWith(db)
}

// IsDuplicate reports whether err is the MySQL error for a duplicate entry.
func IsDuplicate(err error) bool {
	var sqlErr *mysql.MySQLError
	return errors.As(err, &sqlErr) && sqlErr.Number == 1062
}

// rowScanner is the part of [sql.Row] and [sql.Rows] that reads the columns of one row. The functions that scan a record
// take it, so the same code reads a single row and each row of a page.
type rowScanner interface {
	Scan(dest ...any) error
}

// checkUpdated returns err if it is set. Otherwise it returns [es.ErrNoUpdatedRows] if result reports that the
// statement matched no row.
func checkUpdated(result sql.Result, err error) error {
	if err != nil {
		return err
	}

	if MustRowsAffected(result) == 0 {
		return es.ErrNoUpdatedRows
	}

	return nil
}

// ipBytes returns the binary form of ip for a binary address column, or nil, which the database stores as NULL, for the
// zero address.
func ipBytes(ip netip.Addr) []byte {
	if !ip.IsValid() {
		return nil
	}

	return ip.AsSlice()
}

// ipScan is an [sql.Scanner] that reads a binary address column into ip. A NULL value gives the zero address.
type ipScan struct {
	ip *netip.Addr
}

// Scan implements [sql.Scanner]. It returns [ErrScan] if the value is not NULL or a valid address.
func (s ipScan) Scan(value any) error {
	switch v := value.(type) {
	case nil:
		*s.ip = netip.Addr{}
		return nil
	case []byte:
		ip, ok := netip.AddrFromSlice(v)
		if !ok {
			return fmt.Errorf("scan an address of %d bytes: %w", len(v), ErrScan)
		}

		*s.ip = ip
		return nil
	}

	return fmt.Errorf("scan an address from %T: %w", value, ErrScan)
}

// MustLastID returns the auto-increment key that res reports. It panics if the driver cannot report it. The MySQL
// driver always reports it after an insert.
func MustLastID[T es.Integer](res sql.Result) T {
	v, err := res.LastInsertId()
	if err != nil {
		panic(fmt.Errorf("unable to get LastInsertId(): %w", err))
	}

	return T(v)
}

// MustRowsAffected returns the number of rows that res reports. It panics if the driver cannot report it. The MySQL
// driver always reports it.
func MustRowsAffected(res sql.Result) int64 {
	rowsCount, err := res.RowsAffected()
	if err != nil {
		panic(fmt.Errorf("unable to get RowsAffected(): %w", err))
	}

	return rowsCount
}

// NewNullInt returns n as a nullable value. It is NULL if n is zero.
func NewNullInt[T es.Integer](n T) sql.Null[T] {
	if n == 0 {
		return sql.Null[T]{}
	}

	return sql.Null[T]{
		V:     n,
		Valid: true,
	}
}

// emptyBlobByte is the only byte of the blob that stands for an empty value.
const emptyBlobByte byte = 0

// NewDefaultBlob returns b, or a blob of one zero byte if b is empty, so that an empty value is never stored as NULL.
func NewDefaultBlob(b []byte) []byte {
	if len(b) == 0 {
		return []byte{emptyBlobByte}
	}

	return b
}

// FromDefaultBlob reverses [NewDefaultBlob]. It returns nil if b is the blob of one zero byte, and b otherwise.
func FromDefaultBlob(b []byte) []byte {
	if len(b) == 1 && b[0] == emptyBlobByte {
		return nil
	}

	return b
}

// inTx runs apply in one database transaction and returns the group that apply returns. It commits if apply succeeds. If
// apply or the commit fails, it rolls the transaction back and returns the group as given, so the caller never sees a
// half-written group. A failure of the rollback is joined to the error.
//
// The function apply must not call a service outside the database. The transaction is open until apply returns.
func inTx[G any](ctx context.Context, db *sql.DB, group G, apply func(*sql.Tx, G) (G, error)) (_ G, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return group, fmt.Errorf("begin the transaction: %w", err)
	}

	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, rollbackErr)
		}
	}()

	written, err := apply(tx, group)
	if err != nil {
		return group, err
	}

	err = tx.Commit()
	if err != nil {
		return group, fmt.Errorf("commit: %w", err)
	}

	return written, nil
}
