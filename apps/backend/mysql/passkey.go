package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Masterminds/squirrel"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql/expr"
)

var _ es.Reader[es.Passkey] = &PasskeyReader{}
var _ es.Writer[es.Passkey] = &PasskeyWriter{}
var _ es.BatchReader[es.Passkey] = &PasskeyBatchReader{}
var _ es.UpdateBuilder[es.Passkey] = &UpdatePasskeyBuilder{}
var _ es.BatchReaderTx[es.Passkey] = &PasskeyBatchTx{}
var _ es.Tx[es.Passkey, es.PasskeyFlag] = &PasskeyTx{}

// scanPasskey reads the columns of the select statements of passkeys from row. It returns the error of the scan as it
// is, so the caller can tell a missing row.
func scanPasskey(row rowScanner) (es.Passkey, error) {
	var passkey es.Passkey

	err := row.Scan(
		&passkey.ID,
		&passkey.PasskeyXID,
		&passkey.Flags,
		&passkey.UserID,
		&passkey.CredentialID,
		&passkey.PublicKey,
		&passkey.AttestationType,
		&passkey.AttestationFormat,
		&passkey.Transports,
		&passkey.AAGUID,
		&passkey.SignCount,
		&passkey.Name,
		&passkey.CreatedAt,
	)
	if err != nil {
		return es.Passkey{}, err
	}

	passkey.AAGUID = FromDefaultBlob(passkey.AAGUID)

	return passkey, nil
}

// PasskeyReader implements [es.Reader] for passkeys.
type PasskeyReader struct {
	Database *sql.DB
}

// ReadOne returns the passkey that the first set field of the argument identifies. The fields are ID, PasskeyXID and
// CredentialID, in that order.
//
// It returns [es.ErrNoArguments] if none of them is set and [es.ErrNotFound] if there is no such passkey.
func (s *PasskeyReader) ReadOne(ctx context.Context, args es.Passkey, _ es.Op) (es.Passkey, error) {
	var row *sql.Row
	switch {
	case args.ID != 0:
		row = s.Database.QueryRowContext(ctx, expr.PasskeyByID, args.ID)
	case args.PasskeyXID != 0:
		row = s.Database.QueryRowContext(ctx, expr.PasskeyByPasskeyXID, args.PasskeyXID)
	case len(args.CredentialID) != 0:
		row = s.Database.QueryRowContext(ctx, expr.PasskeyByCredentialID, args.CredentialID)
	default:
		return es.Passkey{}, es.ErrNoArguments
	}

	passkey, err := scanPasskey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return es.Passkey{}, es.ErrNotFound
	} else if err != nil {
		return es.Passkey{}, err
	}

	return passkey, nil
}

// PasskeyWriter implements [es.Writer] for passkeys.
type PasskeyWriter struct {
	Database             *sql.DB
	SystemClock          clock.Clock
	UpdatePasskeyBuilder es.UpdateBuilder[es.Passkey]
}

// WriteOne creates or updates a passkey, as [es.Writer] describes. An update identifies the passkey by ID.
//
// It returns [es.ErrDuplicate] if a create finds the passkey already stored, [es.ErrNoCreatedRows] if a create adds no
// row, and [es.ErrNoUpdatedRows] if an update matches no passkey.
func (s *PasskeyWriter) WriteOne(ctx context.Context, item es.Passkey, op es.Op) (es.Passkey, error) {
	switch {
	case es.IsCreate(op):
		return s.createOne(ctx, item)
	case es.IsUpdate(op):
		return item, s.updateOne(ctx, item, op)
	}

	return item, es.ErrNoArguments
}

func (s *PasskeyWriter) createOne(ctx context.Context, passkey es.Passkey) (es.Passkey, error) {
	passkey.CreatedAt = s.SystemClock.Now()

	result, err := s.Database.ExecContext(ctx, expr.CreatePasskey,
		passkey.PasskeyXID,
		passkey.Flags,
		passkey.UserID,
		passkey.CredentialID,
		passkey.PublicKey,
		passkey.AttestationType,
		passkey.AttestationFormat,
		passkey.Transports,
		NewDefaultBlob(passkey.AAGUID),
		passkey.SignCount,
		passkey.Name,
		passkey.CreatedAt,
	)
	if IsDuplicate(err) {
		return passkey, es.ErrDuplicate
	} else if err != nil {
		return passkey, fmt.Errorf("create a passkey: %w", err)
	}

	passkey.ID = MustLastID[uint64](result)

	if passkey.ID == 0 {
		return passkey, es.ErrNoCreatedRows
	}

	return passkey, nil
}

func (s *PasskeyWriter) updateOne(ctx context.Context, passkey es.Passkey, op es.Op) error {
	result, err := s.UpdatePasskeyBuilder.UpdateOneBuilder(passkey, op).RunWith(s.Database).ExecContext(ctx)
	return checkUpdated(result, err)
}

// PasskeyBatchReader implements [es.BatchReader] for passkeys. It lists the passkeys of a user, oldest first.
type PasskeyBatchReader struct {
	Database *sql.DB
}

// ReadAll returns one page of the passkeys of the UserID of the argument.
//
// It returns [es.ErrNoArguments] if the argument has no UserID.
func (s *PasskeyBatchReader) ReadAll(ctx context.Context, args es.Passkey, paging es.Paginator, _ es.Op) ([]es.Passkey, error) {
	if args.UserID == 0 {
		return nil, es.ErrNoArguments
	}

	rows, err := s.Database.QueryContext(ctx, expr.PasskeysByUser, args.UserID, paging.Limit(), paging.Offset())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPasskeys(rows)
}

// scanPasskeys reads every passkey of rows.
func scanPasskeys(rows *sql.Rows) ([]es.Passkey, error) {
	var passkeys []es.Passkey
	for rows.Next() {
		passkey, err := scanPasskey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan a passkey: %w", err)
		}

		passkeys = append(passkeys, passkey)
	}

	return passkeys, rows.Err()
}

// PasskeyBatchTx implements [es.BatchReaderTx] for passkeys. It lists the passkeys of a user inside the transaction of
// the caller, oldest first.
type PasskeyBatchTx struct{}

// ReadAllTx returns one page of the passkeys of the UserID of the argument, as the transaction sees them.
//
// It returns [es.ErrNoArguments] if the argument has no UserID.
func (s *PasskeyBatchTx) ReadAllTx(tx *sql.Tx, args es.Passkey, paging es.Paginator, _ es.Op) ([]es.Passkey, error) {
	if args.UserID == 0 {
		return nil, es.ErrNoArguments
	}

	rows, err := tx.Query(expr.PasskeysByUser, args.UserID, paging.Limit(), paging.Offset())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPasskeys(rows)
}

// PasskeyTx implements [es.Tx] for passkeys. It identifies a passkey by ID, PasskeyXID or CredentialID, in that order.
type PasskeyTx struct {
	SystemClock          clock.Clock
	UpdatePasskeyBuilder es.UpdateBuilder[es.Passkey]
}

// FindOneTx returns the passkey that the first set field of the argument identifies, without locking it.
//
// It returns [es.ErrNoArguments] if none of the fields is set and [es.ErrNotFound] if there is no such passkey.
func (s *PasskeyTx) FindOneTx(tx *sql.Tx, args es.Passkey) (es.Passkey, error) {
	return selectPasskeyTx(tx, args, expr.PasskeyByID, expr.PasskeyByPasskeyXID, expr.PasskeyByCredentialID)
}

// LockOneTx locks the passkey that the first set field of the argument identifies and returns it. It waits for the row
// lock.
//
// It returns [es.ErrNoArguments] if none of the fields is set and [es.ErrNotFound] if there is no such passkey.
func (s *PasskeyTx) LockOneTx(tx *sql.Tx, args es.Passkey) (es.Passkey, error) {
	return selectPasskeyTx(tx, args, expr.PasskeyByIDForUpdate, expr.PasskeyByPasskeyXIDForUpdate, expr.PasskeyByCredentialIDForUpdate)
}

// selectPasskeyTx runs byID, byXID or byCredentialID, whichever the first set field of args selects, and scans the
// passkey.
func selectPasskeyTx(tx *sql.Tx, args es.Passkey, byID, byXID, byCredentialID string) (es.Passkey, error) {
	var row *sql.Row
	switch {
	case args.ID != 0:
		row = tx.QueryRow(byID, args.ID)
	case args.PasskeyXID != 0:
		row = tx.QueryRow(byXID, args.PasskeyXID)
	case len(args.CredentialID) != 0:
		row = tx.QueryRow(byCredentialID, args.CredentialID)
	default:
		return es.Passkey{}, es.ErrNoArguments
	}

	passkey, err := scanPasskey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return es.Passkey{}, es.ErrNotFound
	} else if err != nil {
		return es.Passkey{}, err
	}

	return passkey, nil
}

// CreateOneTx stores the passkey at the time of the clock and returns it with its ID set.
//
// It returns [es.ErrDuplicate] if the passkey or its credential ID is already stored and [es.ErrNoCreatedRows] if the
// database adds no row.
func (s *PasskeyTx) CreateOneTx(tx *sql.Tx, item es.Passkey) (es.Passkey, error) {
	item.CreatedAt = s.SystemClock.Now()

	result, err := tx.Exec(expr.CreatePasskey,
		item.PasskeyXID,
		item.Flags,
		item.UserID,
		item.CredentialID,
		item.PublicKey,
		item.AttestationType,
		item.AttestationFormat,
		item.Transports,
		NewDefaultBlob(item.AAGUID),
		item.SignCount,
		item.Name,
		item.CreatedAt,
	)
	if IsDuplicate(err) {
		return item, es.ErrDuplicate
	} else if err != nil {
		return item, fmt.Errorf("create a passkey: %w", err)
	}

	item.ID = MustLastID[uint64](result)

	if item.ID == 0 {
		return item, es.ErrNoCreatedRows
	}

	return item, nil
}

// UpdateOneTx updates the passkey that the ID of the item names, as [UpdatePasskeyBuilder] describes.
//
// It returns [es.ErrNoUpdatedRows] if no passkey matches.
func (s *PasskeyTx) UpdateOneTx(tx *sql.Tx, item es.Passkey, op es.Op) error {
	result, err := s.UpdatePasskeyBuilder.UpdateOneBuilder(item, op).RunWith(tx).Exec()

	return checkUpdated(result, err)
}

// ReplaceFlagOneTx clears the oldest bits and sets the newest bits of the passkey with the ID of args.
//
// It returns [es.ErrNoArguments] if args has no ID and [es.ErrNoUpdatedRows] if no passkey matched.
func (s *PasskeyTx) ReplaceFlagOneTx(tx *sql.Tx, oldest, newest es.PasskeyFlag, args es.Passkey) error {
	if args.ID == 0 {
		return es.ErrNoArguments
	}

	return checkUpdated(tx.Exec(expr.ReplacePasskeyFlags, oldest, newest, args.ID))
}

// UpdatePasskeyBuilder implements [es.UpdateBuilder] for passkeys. The update writes only the fields that are set.
type UpdatePasskeyBuilder struct {
	QueryBuilder squirrel.StatementBuilderType
}

// UpdateOneBuilder returns the update of the passkey that the ID names.
func (b *UpdatePasskeyBuilder) UpdateOneBuilder(passkey es.Passkey, op es.Op) squirrel.UpdateBuilder {
	sb := b.QueryBuilder.Update("passkeys")
	switch {
	case op&es.ClearFlag != 0:
		sb = sb.Set("flags", squirrel.Expr("flags & ~?", passkey.Flags))
	case op&es.AppendFlag != 0:
		sb = sb.Set("flags", squirrel.Expr("flags | ?", passkey.Flags))
	case op&es.RewriteFlag != 0:
		sb = sb.Set("flags", passkey.Flags)
	}

	if passkey.SignCount != 0 {
		sb = sb.Set("sign_count", passkey.SignCount)
	}

	if passkey.Name != "" {
		sb = sb.Set("name", passkey.Name)
	}

	return sb.Where(squirrel.Eq{"id": passkey.ID})
}
