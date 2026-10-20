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

var _ es.Reader[es.Account] = &AccountReader{}
var _ es.BatchReader[es.Account] = &AccountBatchReader{}
var _ es.Writer[es.AccountGroup] = &AccountGroupWriter{}

// scanAccount reads the columns of the select statements of authenticator accounts from row.
func scanAccount(row rowScanner) (es.Account, error) {
	var account es.Account

	err := row.Scan(
		&account.ID,
		&account.AccountXID,
		&account.Flags,
		&account.UserID,
		&account.VaultKey,
		&account.Issuer,
		&account.Label,
		&account.Algorithm,
		&account.Digits,
		&account.Period,
		&account.CreatedAt,
	)
	if err != nil {
		return es.Account{}, err
	}

	return account, nil
}

// AccountReader implements [es.Reader] for authenticator accounts.
type AccountReader struct {
	Database *sql.DB
}

// ReadOne returns the account with the AccountXID of the argument that belongs to its UserID.
//
// It returns [es.ErrNoArguments] if either is zero and [es.ErrNotFound] if the user has no such account.
func (s *AccountReader) ReadOne(ctx context.Context, args es.Account, _ es.Op) (es.Account, error) {
	if args.AccountXID == 0 || args.UserID == 0 {
		return es.Account{}, es.ErrNoArguments
	}

	account, err := scanAccount(s.Database.QueryRowContext(ctx, expr.AccountByXID, args.AccountXID, args.UserID))
	if errors.Is(err, sql.ErrNoRows) {
		return es.Account{}, es.ErrNotFound
	} else if err != nil {
		return es.Account{}, err
	}

	return account, nil
}

// AccountBatchReader implements [es.BatchReader] for authenticator accounts. It lists the accounts of a user,
// oldest first.
type AccountBatchReader struct {
	Database *sql.DB
}

// ReadAll returns one page of the accounts of the UserID of the argument.
//
// It returns [es.ErrNoArguments] if the argument has no UserID.
func (s *AccountBatchReader) ReadAll(ctx context.Context, args es.Account, paging es.Paginator, _ es.Op) ([]es.Account, error) {
	if args.UserID == 0 {
		return nil, es.ErrNoArguments
	}

	rows, err := s.Database.QueryContext(ctx, expr.AccountsByUser, args.UserID, paging.Limit(), paging.Offset())
	if err != nil {
		return nil, fmt.Errorf("read the authenticator accounts: %w", err)
	}
	defer rows.Close()

	var accounts []es.Account
	for rows.Next() {
		account, err := scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan an authenticator account: %w", err)
		}

		accounts = append(accounts, account)
	}

	return accounts, rows.Err()
}

// AccountGroupWriter implements [es.Writer] for [es.AccountGroup]. Every intent runs in one database
// transaction and locks the user first, so two additions cannot both pass the limit.
type AccountGroupWriter struct {
	Database    *sql.DB
	SystemClock clock.Clock
	UserTx      es.Tx[es.User, es.UserFlag]
}

// WriteOne runs the intent that op sets, as [es.AccountIntents] lists them, and returns the group with the stored
// rows.
//
// It returns [es.ErrNoArguments] if op sets no intent or more than one, or if the group has no user or no account.
func (s *AccountGroupWriter) WriteOne(ctx context.Context, group es.AccountGroup, op es.Op) (es.AccountGroup, error) {
	switch op & es.AccountIntents {
	case es.AddAccounts:
		return inTx(ctx, s.Database, group, s.addAuthenticators)
	case es.RemoveAccount:
		return inTx(ctx, s.Database, group, s.removeAuthenticator)
	default:
		return group, es.ErrNoArguments
	}
}

// addAuthenticators stores the accounts of group.Items for group.User. It locks the user first and counts the stored
// accounts after the lock, in the same transaction.
//
// It returns [es.ErrTooManyAccounts] if the user would have more than [es.MaxAccounts], and then it writes
// nothing.
func (s *AccountGroupWriter) addAuthenticators(tx *sql.Tx, group es.AccountGroup) (es.AccountGroup, error) {
	if group.User.ID == 0 || len(group.Items) == 0 {
		return group, es.ErrNoArguments
	}

	locked, err := s.UserTx.LockOneTx(tx, es.User{
		ID: group.User.ID,
	})
	if err != nil {
		return group, fmt.Errorf("lock the user: %w", err)
	}

	var stored int

	if err := tx.QueryRow(expr.CountAccountsByUser, locked.ID).Scan(&stored); err != nil {
		return group, fmt.Errorf("count the authenticator accounts: %w", err)
	}

	if stored+len(group.Items) > es.MaxAccounts {
		return group, es.ErrTooManyAccounts
	}

	now := s.SystemClock.Now().UTC()
	items := make([]es.Account, 0, len(group.Items))

	for _, item := range group.Items {
		result, err := tx.Exec(expr.CreateAccount,
			item.AccountXID,
			item.Flags,
			locked.ID,
			item.VaultKey,
			item.Issuer,
			item.Label,
			item.Algorithm,
			item.Digits,
			item.Period,
			now,
		)
		if err != nil {
			return group, fmt.Errorf("store an authenticator account: %w", err)
		}

		item.ID = MustLastID[uint64](result)
		item.UserID = locked.ID
		item.CreatedAt = now
		items = append(items, item)
	}

	group.User = locked
	group.Items = items

	return group, nil
}

// removeAuthenticator deletes the account named by the first item of group.Items for group.User.
//
// It returns [es.ErrNotFound] if the user has no such account.
func (s *AccountGroupWriter) removeAuthenticator(tx *sql.Tx, group es.AccountGroup) (es.AccountGroup, error) {
	if group.User.ID == 0 || len(group.Items) == 0 || group.Items[0].AccountXID == 0 {
		return group, es.ErrNoArguments
	}

	locked, err := s.UserTx.LockOneTx(tx, es.User{
		ID: group.User.ID,
	})
	if err != nil {
		return group, fmt.Errorf("lock the user: %w", err)
	}

	result, err := tx.Exec(expr.DeleteAccount, group.Items[0].AccountXID, locked.ID)
	if err != nil {
		return group, fmt.Errorf("delete the authenticator account: %w", err)
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return group, fmt.Errorf("count the deleted rows: %w", err)
	}

	if deleted == 0 {
		return group, es.ErrNotFound
	}

	return group, nil
}
