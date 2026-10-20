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

var _ es.Reader[es.User] = &UserReader{}
var _ es.Writer[es.User] = &UserWriter{}
var _ es.BatchReader[es.User] = &UserBatchReader{}
var _ es.Tx[es.User, es.UserFlag] = &UserTx{}
var _ es.UpdateBuilder[es.User] = &UpdateUserBuilder{}

// scanUser reads the columns of the select statements of users from row. It returns the error of the scan as it is, so
// the caller can tell a missing row.
func scanUser(row rowScanner) (es.User, error) {
	var user es.User

	err := row.Scan(
		&user.ID,
		&user.UserXID,
		&user.Flags,
		&user.Email,
		&user.Handle,
		&user.PasswordHash,
		&user.TOTPCiphertext,
		&user.TOTPLastStep,
		&user.TOTPFailures,
		&user.CreatedAt,
	)
	if err != nil {
		return es.User{}, err
	}

	return user, nil
}

// UserReader implements [es.Reader] for users.
type UserReader struct {
	Database *sql.DB
}

// ReadOne returns the user that the first set field of the argument identifies. The fields are ID, UserXID, Handle and
// Email, in that order.
//
// It returns [es.ErrNoArguments] if none of them is set and [es.ErrNotFound] if there is no such user.
func (s *UserReader) ReadOne(ctx context.Context, args es.User, _ es.Op) (es.User, error) {
	var row *sql.Row
	switch {
	case args.ID != 0:
		row = s.Database.QueryRowContext(ctx, expr.UserByID, args.ID)
	case args.UserXID != 0:
		row = s.Database.QueryRowContext(ctx, expr.UserByUserXID, args.UserXID)
	case len(args.Handle) != 0:
		row = s.Database.QueryRowContext(ctx, expr.UserByHandle, args.Handle)
	case args.Email != "":
		row = s.Database.QueryRowContext(ctx, expr.UserByEmail, args.Email)
	default:
		return es.User{}, es.ErrNoArguments
	}

	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return es.User{}, es.ErrNotFound
	} else if err != nil {
		return es.User{}, err
	}

	return user, nil
}

// UserWriter implements [es.Writer] for users.
type UserWriter struct {
	Database          *sql.DB
	SystemClock       clock.Clock
	UpdateUserBuilder es.UpdateBuilder[es.User]
}

// WriteOne creates or updates a user, as [es.Writer] describes. An update identifies the user by ID.
//
// It returns [es.ErrDuplicate] if the email or the handle is already taken, [es.ErrNoCreatedRows] if a create adds no
// row, and [es.ErrNoUpdatedRows] if an update matches no user.
func (s *UserWriter) WriteOne(ctx context.Context, item es.User, op es.Op) (es.User, error) {
	switch {
	case es.IsCreate(op):
		return s.createOne(ctx, item)
	case es.IsUpdate(op):
		return item, s.updateOne(ctx, item, op)
	}

	return item, es.ErrNoArguments
}

func (s *UserWriter) createOne(ctx context.Context, user es.User) (es.User, error) {
	user.CreatedAt = s.SystemClock.Now()

	result, err := s.Database.ExecContext(ctx, expr.CreateUser,
		user.UserXID,
		user.Flags,
		user.Email,
		user.Handle,
		user.PasswordHash,
		user.TOTPCiphertext,
		user.TOTPLastStep,
		user.TOTPFailures,
		user.CreatedAt,
	)
	if IsDuplicate(err) {
		return user, es.ErrDuplicate
	} else if err != nil {
		return user, fmt.Errorf("create a user: %w", err)
	}

	user.ID = MustLastID[uint64](result)

	if user.ID == 0 {
		return user, es.ErrNoCreatedRows
	}

	return user, nil
}

func (s *UserWriter) updateOne(ctx context.Context, user es.User, op es.Op) error {
	result, err := s.UpdateUserBuilder.UpdateOneBuilder(user, op).RunWith(s.Database).ExecContext(ctx)
	if IsDuplicate(err) {
		return es.ErrDuplicate
	}

	return checkUpdated(result, err)
}

// UserBatchReader implements [es.BatchReader] for users. It lists only the users that have a TOTP secret, oldest
// first.
type UserBatchReader struct {
	Database *sql.DB
}

// ReadAll returns one page of users. It ignores the user argument.
//
// It returns [es.ErrNoArguments] unless the [es.Op] has [es.HoldingTOTPSecret].
func (s *UserBatchReader) ReadAll(ctx context.Context, _ es.User, paging es.Paginator, op es.Op) ([]es.User, error) {
	if op&es.HoldingTOTPSecret == 0 {
		return nil, es.ErrNoArguments
	}

	rows, err := s.Database.QueryContext(ctx, expr.UsersWithTOTP, paging.Limit(), paging.Offset())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []es.User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan a user: %w", err)
		}

		users = append(users, user)
	}
	return users, rows.Err()
}

// UserTx implements [es.Tx] for users. It finds a user by ID, UserXID, Handle or Email, in that order, and locks and
// updates a user by ID.
type UserTx struct {
	SystemClock       clock.Clock
	UpdateUserBuilder es.UpdateBuilder[es.User]
}

// FindOneTx returns the user that the first set field of the argument identifies, without locking it. The fields are
// ID, UserXID, Handle and Email, in that order.
//
// It returns [es.ErrNoArguments] if none of them is set and [es.ErrNotFound] if there is no such user.
func (s *UserTx) FindOneTx(tx *sql.Tx, args es.User) (es.User, error) {
	var row *sql.Row
	switch {
	case args.ID != 0:
		row = tx.QueryRow(expr.UserByID, args.ID)
	case args.UserXID != 0:
		row = tx.QueryRow(expr.UserByUserXID, args.UserXID)
	case len(args.Handle) != 0:
		row = tx.QueryRow(expr.UserByHandle, args.Handle)
	case args.Email != "":
		row = tx.QueryRow(expr.UserByEmail, args.Email)
	default:
		return es.User{}, es.ErrNoArguments
	}

	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return es.User{}, es.ErrNotFound
	} else if err != nil {
		return es.User{}, err
	}

	return user, nil
}

// LockOneTx locks the user that the ID of the argument names and returns it. It waits for the row lock.
//
// It returns [es.ErrNoArguments] if the ID is zero and [es.ErrNotFound] if there is no such user.
func (s *UserTx) LockOneTx(tx *sql.Tx, args es.User) (es.User, error) {
	if args.ID == 0 {
		return es.User{}, es.ErrNoArguments
	}

	user, err := scanUser(tx.QueryRow(expr.UserByIDForUpdate, args.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return es.User{}, es.ErrNotFound
	} else if err != nil {
		return es.User{}, err
	}

	return user, nil
}

// CreateOneTx stores the user at the time of the clock and returns it with its ID set.
//
// It returns [es.ErrDuplicate] if the email or the handle is already taken and [es.ErrNoCreatedRows] if the database
// adds no row.
func (s *UserTx) CreateOneTx(tx *sql.Tx, item es.User) (es.User, error) {
	item.CreatedAt = s.SystemClock.Now()

	result, err := tx.Exec(expr.CreateUser,
		item.UserXID,
		item.Flags,
		item.Email,
		item.Handle,
		item.PasswordHash,
		item.TOTPCiphertext,
		item.TOTPLastStep,
		item.TOTPFailures,
		item.CreatedAt,
	)
	if IsDuplicate(err) {
		return item, es.ErrDuplicate
	} else if err != nil {
		return item, fmt.Errorf("create a user: %w", err)
	}

	item.ID = MustLastID[uint64](result)

	if item.ID == 0 {
		return item, es.ErrNoCreatedRows
	}

	return item, nil
}

// UpdateOneTx updates the user that the ID of the item names.
//
// It returns [es.ErrDuplicate] if the new email is already taken and [es.ErrNoUpdatedRows] if no user matches.
func (s *UserTx) UpdateOneTx(tx *sql.Tx, item es.User, op es.Op) error {
	result, err := s.UpdateUserBuilder.UpdateOneBuilder(item, op).RunWith(tx).Exec()
	if IsDuplicate(err) {
		return es.ErrDuplicate
	}

	return checkUpdated(result, err)
}

// ReplaceFlagOneTx clears the oldest bits and sets the newest bits of the user with the ID of args.
//
// It returns [es.ErrNoArguments] if args has no ID and [es.ErrNoUpdatedRows] if no user matched.
func (s *UserTx) ReplaceFlagOneTx(tx *sql.Tx, oldest, newest es.UserFlag, args es.User) error {
	if args.ID == 0 {
		return es.ErrNoArguments
	}

	return checkUpdated(tx.Exec(expr.ReplaceUserFlags, oldest, newest, args.ID))
}

// UpdateUserBuilder implements [es.UpdateBuilder] for users. The update writes only the fields that are set.
type UpdateUserBuilder struct {
	QueryBuilder squirrel.StatementBuilderType
}

// UpdateOneBuilder returns the update of the user that the ID names. [es.ResetTOTP] makes it write the TOTP fields even
// if they are zero. [es.AdvanceTOTPStep] and [es.CountTOTPFailure] build an update of the TOTP counters only.
func (b *UpdateUserBuilder) UpdateOneBuilder(user es.User, op es.Op) squirrel.UpdateBuilder {
	sb := b.QueryBuilder.Update("users")
	switch {
	case op&es.AdvanceTOTPStep != 0:
		return sb.Set("totp_last_step", user.TOTPLastStep).
			Set("totp_failures", 0).
			Where(squirrel.Eq{"id": user.ID}).
			Where(squirrel.Lt{"totp_last_step": user.TOTPLastStep})
	case op&es.CountTOTPFailure != 0:
		return sb.Set("totp_failures", squirrel.Expr("totp_failures + 1")).
			Where(squirrel.Eq{"id": user.ID})
	}

	switch {
	case op&es.ClearFlag != 0:
		sb = sb.Set("flags", squirrel.Expr("flags & ~?", user.Flags))
	case op&es.AppendFlag != 0:
		sb = sb.Set("flags", squirrel.Expr("flags | ?", user.Flags))
	case op&es.RewriteFlag != 0:
		sb = sb.Set("flags", user.Flags)
	}

	if user.Email != "" {
		sb = sb.Set("email", user.Email)
	}

	if user.PasswordHash != "" {
		sb = sb.Set("password_hash", user.PasswordHash)
	}

	if user.TOTPCiphertext != "" || op&es.ResetTOTP != 0 {
		sb = sb.Set("totp_ciphertext", user.TOTPCiphertext)
	}

	if user.TOTPLastStep != 0 || op&es.ResetTOTP != 0 {
		sb = sb.Set("totp_last_step", user.TOTPLastStep)
	}

	if user.TOTPFailures != 0 || op&es.ResetTOTP != 0 {
		sb = sb.Set("totp_failures", user.TOTPFailures)
	}

	return sb.Where(squirrel.Eq{"id": user.ID})
}
