package es

import (
	"context"
	"database/sql"

	"github.com/Masterminds/squirrel"
)

// Integer is the constraint of a flag type. A flag type is a named unsigned integer type.
type Integer interface {
	~uint8 | ~uint16 | ~uint32 | ~uint64
}

// Tx is a store of one kind of record that runs inside a database transaction. The caller begins the transaction and
// decides to commit or roll it back, so several stores can change their records together.
//
// T is the record type and F is its flag type. A store that does not offer a
// method returns [ErrNoMethod].
type Tx[T any, F Integer] interface {
	// FindOneTx returns the record that the identifying fields of the argument name, without locking it.
	//
	// It returns [ErrNoArguments] if the argument has no usable identifier and [ErrNotFound] if there is no such
	// record.
	FindOneTx(*sql.Tx, T) (T, error)

	// LockOneTx returns the matching record and locks it until the transaction ends, so no other transaction can
	// change it. It waits if another transaction holds the lock.
	//
	// It returns [ErrNoArguments] if the argument has no usable identifier and [ErrNotFound] if there is no such
	// record.
	LockOneTx(*sql.Tx, T) (T, error)

	// CreateOneTx saves a new record and returns it with its ID and creation time set.
	//
	// It returns [ErrDuplicate] if the record must be unique and already exists.
	CreateOneTx(*sql.Tx, T) (T, error)

	// UpdateOneTx changes the record that its identifying fields name. It writes only the fields that are set. The
	// [Op] says if the flag bits are added to the stored bits, overwrite them or are removed from them.
	//
	// It returns [ErrNoUpdatedRows] if no record matched.
	UpdateOneTx(*sql.Tx, T, Op) error

	// ReplaceFlagOneTx clears the bits of oldest and sets the bits of newest in one statement. The record is the one
	// that the ID of args names. If the ID is zero, a store that supports it changes every record of the UserID of
	// args.
	//
	// It returns [ErrNoArguments] if args has no usable identifier and [ErrNoUpdatedRows] if no record matched.
	ReplaceFlagOneTx(tx *sql.Tx, oldest, newest F, args T) error
}

// Reader reads one record of one kind, outside a transaction.
//
// T is the record type.
type Reader[T any] interface {
	// ReadOne returns the record that matches the identifying fields of its argument. The [Op] can select a special
	// search if the store has several.
	//
	// It returns [ErrNotFound] if there is no such record and [ErrNoArguments] if the argument has no usable
	// identifier.
	ReadOne(context.Context, T, Op) (T, error)
}

// Writer creates or updates one record of one kind, outside a transaction. To swap flag bits, use [Replacer].
//
// T is the record type.
type Writer[T any] interface {
	// WriteOne creates or updates a record and returns it. The [Op] must set exactly one of [WriteCreate] and
	// [WriteUpdate]. With neither or both, WriteOne returns [ErrNoArguments].
	//
	// With [WriteCreate], WriteOne saves a new record and returns it with its ID and creation time set. It returns
	// [ErrDuplicate] if the record must be unique and already exists, and [ErrNoCreatedRows] if the database adds no
	// row.
	//
	// With [WriteUpdate], WriteOne changes the record that its identifying fields name. It writes only the fields that
	// are set and returns the record as given, without reading it back. The other options say if the flag bits are
	// added to the stored bits, overwrite them or are removed from them.
	//
	// An update returns [ErrNoUpdatedRows] if no record matched.
	WriteOne(context.Context, T, Op) (T, error)
}

// Replacer swaps flag bits of one record of one kind, or of every record of one owner, outside a transaction.
//
// T is the record type and F is its flag type.
type Replacer[T any, F Integer] interface {
	// ReplaceOne clears the bits of oldest and sets the bits of newest in one statement. With [AllOfUser] it changes
	// every record of the owner in item, not only one record.
	//
	// It returns [ErrNoArguments] if item has no usable identifier and [ErrNoUpdatedRows] if no record matched.
	ReplaceOne(ctx context.Context, oldest, newest F, item T, op Op) error
}

// BatchReader reads many records of one kind at once.
//
// T is the record type as in [Reader].
type BatchReader[T any] interface {
	// ReadAll returns one page of the records that match the fields that are set in its argument. The [Op] can select
	// a special search.
	//
	// It returns [ErrNoArguments] if the argument sets no filter.
	ReadAll(context.Context, T, Paginator, Op) ([]T, error)
}

// BatchReaderTx reads many records of one kind at once inside a database transaction. The caller begins the transaction,
// so the records come from the same snapshot and under the same locks as its other steps.
//
// T is the record type as in [BatchReader].
type BatchReaderTx[T any] interface {
	// ReadAllTx returns one page of the records that match the fields that are set in its argument. The [Op] can
	// select a special search.
	//
	// It returns [ErrNoArguments] if the argument sets no filter.
	ReadAllTx(*sql.Tx, T, Paginator, Op) ([]T, error)
}

// BatchWriter writes many records of one kind at once.
//
// T is the record type and F is its flag type.
type BatchWriter[T any, F Integer] interface {
	// WriteAll saves items in one call. A store that updates existing items clears the bits of oldest and sets the
	// bits of newest. A store that only creates items ignores both. The [Op] can select a special write.
	WriteAll(ctx context.Context, oldest, newest F, items []T, op Op) error
}

// UpdateBuilder builds the SQL update statement for one kind of record. It only prepares the statement. The [Tx] and
// [Writer] stores of the same kind run it.
//
// T is the record type.
type UpdateBuilder[T any] interface {
	// UpdateOneBuilder returns a statement that changes the fields that are set on the record. The [Op] says how the
	// flag bits change.
	UpdateOneBuilder(T, Op) squirrel.UpdateBuilder
}
