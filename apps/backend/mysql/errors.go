package mysql

import "errors"

// ErrNoDSN reports that the data source name is empty. [Open] returns it.
var ErrNoDSN = errors.New("the database DSN is required")

// ErrScan reports that a column has a type that the scanner does not expect. The scanner returns it wrapped.
var ErrScan = errors.New("unexpected column type")

// ErrMigrationLock reports that the migration lock was not free within the waiting time. [Migrate] returns it wrapped.
var ErrMigrationLock = errors.New("the migration lock is held by another instance")
