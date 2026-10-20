package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql/expr"
)

var _ es.Writer[es.RecoveryCode] = &RecoveryCodeWriter{}
var _ es.BatchWriter[es.RecoveryCode, es.RecoveryCodeFlag] = &RecoveryCodeBatchWriter{}
var _ es.Replacer[es.RecoveryCode, es.RecoveryCodeFlag] = &RecoveryCodeReplacer{}
var _ es.Tx[es.RecoveryCode, es.RecoveryCodeFlag] = &RecoveryCodeTx{}

// RecoveryCodeWriter implements [es.Writer] for recovery codes. It only uses up a code. [RecoveryCodeBatchWriter]
// creates codes.
type RecoveryCodeWriter struct {
	Database *sql.DB
}

// WriteOne sets the flag bits of the item on the unused code with the UserID and the MAC of the item. It accepts
// only an update with [es.UseUpRecoveryCode].
//
// It returns [es.ErrNoArguments] for any other call and [es.ErrNoUpdatedRows] if there is no such unused code.
func (s *RecoveryCodeWriter) WriteOne(ctx context.Context, item es.RecoveryCode, op es.Op) (es.RecoveryCode, error) {
	if !es.IsUpdate(op) || op&es.UseUpRecoveryCode == 0 || item.UserID == 0 || item.MAC == "" {
		return item, es.ErrNoArguments
	}

	result, err := s.Database.ExecContext(ctx, expr.UseRecoveryCode,
		item.Flags,
		item.UserID,
		item.MAC,
		es.RecoveryCodeFlagUsed,
	)
	if err != nil {
		return item, err
	}

	if MustRowsAffected(result) == 0 {
		return item, es.ErrNoUpdatedRows
	}

	return item, nil
}

// RecoveryCodeBatchWriter implements [es.BatchWriter] for recovery codes. It creates a set of codes.
type RecoveryCodeBatchWriter struct {
	Database    *sql.DB
	SystemClock clock.Clock
}

// WriteAll creates every item in one transaction, so the database stores the whole set or nothing. It ignores the
// oldest and newest flag bits, because a new code starts with the flags of its item.
//
// It returns [es.ErrDuplicate] if a code already exists.
func (s *RecoveryCodeBatchWriter) WriteAll(ctx context.Context, _, _ es.RecoveryCodeFlag, items []es.RecoveryCode, _ es.Op) error {
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin the transaction: %w", err)
	}

	createdAt := s.SystemClock.Now()
	for _, item := range items {
		_, err := tx.ExecContext(ctx, expr.CreateRecoveryCode,
			item.RecoveryCodeXID,
			item.Flags,
			item.UserID,
			item.MAC,
			createdAt,
		)
		if IsDuplicate(err) {
			return errors.Join(es.ErrDuplicate, tx.Rollback())
		} else if err != nil {
			return errors.Join(fmt.Errorf("create a recovery code: %w", err), tx.Rollback())
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit the recovery codes: %w", err)
	}

	return nil
}

// RecoveryCodeReplacer implements [es.Replacer] for recovery codes. It swaps the flags of every code of a user.
type RecoveryCodeReplacer struct {
	Database *sql.DB
}

// ReplaceOne clears the oldest bits and sets the newest bits on every code of the UserID of the item. It accepts only
// a call with [es.AllOfUser].
//
// It returns [es.ErrNoArguments] for any other call and [es.ErrNoUpdatedRows] if no code matched.
func (s *RecoveryCodeReplacer) ReplaceOne(ctx context.Context, oldest, newest es.RecoveryCodeFlag, item es.RecoveryCode, op es.Op) error {
	if op&es.AllOfUser == 0 || item.UserID == 0 {
		return es.ErrNoArguments
	}

	result, err := s.Database.ExecContext(ctx, expr.ReplaceRecoveryCodeFlagsByUser, oldest, newest, item.UserID)
	if err != nil {
		return err
	}

	if MustRowsAffected(result) == 0 {
		return es.ErrNoUpdatedRows
	}

	return nil
}

// RecoveryCodeTx implements [es.Tx] for recovery codes. The service never reads a code by key, so the store offers
// the creation of a code, the use of a code and the retirement of the codes of a user.
type RecoveryCodeTx struct {
	SystemClock clock.Clock
}

// FindOneTx always returns [es.ErrNoMethod]. The service looks a code up only by using it up.
func (s *RecoveryCodeTx) FindOneTx(_ *sql.Tx, item es.RecoveryCode) (es.RecoveryCode, error) {
	return item, es.ErrNoMethod
}

// LockOneTx always returns [es.ErrNoMethod]. [RecoveryCodeTx.UpdateOneTx] uses a code up in one statement, so no lock
// is needed.
func (s *RecoveryCodeTx) LockOneTx(_ *sql.Tx, item es.RecoveryCode) (es.RecoveryCode, error) {
	return item, es.ErrNoMethod
}

// CreateOneTx stores the code at the time of the clock and returns it with its ID set.
//
// It returns [es.ErrDuplicate] if the code already exists and [es.ErrNoCreatedRows] if the database adds no row.
func (s *RecoveryCodeTx) CreateOneTx(tx *sql.Tx, item es.RecoveryCode) (es.RecoveryCode, error) {
	item.CreatedAt = s.SystemClock.Now()

	result, err := tx.Exec(expr.CreateRecoveryCode,
		item.RecoveryCodeXID,
		item.Flags,
		item.UserID,
		item.MAC,
		item.CreatedAt,
	)
	if IsDuplicate(err) {
		return item, es.ErrDuplicate
	} else if err != nil {
		return item, fmt.Errorf("create a recovery code: %w", err)
	}

	item.ID = MustLastID[uint64](result)

	if item.ID == 0 {
		return item, es.ErrNoCreatedRows
	}

	return item, nil
}

// UpdateOneTx sets the flag bits of the item on the unused code with the UserID and the MAC of the item. It accepts only
// the option [es.UseUpRecoveryCode].
//
// It returns [es.ErrNoArguments] for any other call and [es.ErrNoUpdatedRows] if there is no such unused code.
func (s *RecoveryCodeTx) UpdateOneTx(tx *sql.Tx, item es.RecoveryCode, op es.Op) error {
	if op&es.UseUpRecoveryCode == 0 || item.UserID == 0 || item.MAC == "" {
		return es.ErrNoArguments
	}

	return checkUpdated(tx.Exec(expr.UseRecoveryCode,
		item.Flags,
		item.UserID,
		item.MAC,
		es.RecoveryCodeFlagUsed,
	))
}

// ReplaceFlagOneTx clears the oldest bits and sets the newest bits on every code of the UserID of args.
//
// It returns [es.ErrNoArguments] if args has no UserID and [es.ErrNoUpdatedRows] if the user has no code.
func (s *RecoveryCodeTx) ReplaceFlagOneTx(tx *sql.Tx, oldest, newest es.RecoveryCodeFlag, args es.RecoveryCode) error {
	if args.UserID == 0 {
		return es.ErrNoArguments
	}

	return checkUpdated(tx.Exec(expr.ReplaceRecoveryCodeFlagsByUser, oldest, newest, args.UserID))
}
