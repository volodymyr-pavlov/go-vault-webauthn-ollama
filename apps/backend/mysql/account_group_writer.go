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

var _ es.Writer[es.AccountGroup] = &AccountGroupWriter{}

// AccountGroupWriter implements [es.Writer] for [es.AccountGroup]. Every intent runs in one database transaction and
// locks the user first, so two changes of the factors of one account run one after the other.
//
// The lock order is the user, then the passkey and the recovery rows. No intent calls a service outside the database while the transaction is open.
type AccountGroupWriter struct {
	Database       *sql.DB
	SystemClock    clock.Clock
	UserTx         es.Tx[es.User, es.UserFlag]
	SessionTx      es.Tx[es.Session, es.SessionFlag]
	PasskeyTx      es.Tx[es.Passkey, es.PasskeyFlag]
	PasskeyBatchTx es.BatchReaderTx[es.Passkey]
	RecoveryCodeTx es.Tx[es.RecoveryCode, es.RecoveryCodeFlag]
}

// WriteOne runs the intent that op sets and returns the group with the records that the stores returned.
//
// The intents are listed in [es.AccountIntents]. A failed step rolls back all the steps of the intent, and a step after
// it does not run.
//
// It returns [es.ErrNoArguments] if op sets no intent or more than one. Each private method documents the other errors
// of its intent.
func (s *AccountGroupWriter) WriteOne(ctx context.Context, group es.AccountGroup, op es.Op) (es.AccountGroup, error) {
	switch op & es.AccountIntents {
	case es.RemovePasskey:
		return inTx(ctx, s.Database, group, func(tx *sql.Tx, group es.AccountGroup) (es.AccountGroup, error) {
			return s.removePasskey(tx, group, op)
		})
	case es.ConfirmTOTP:
		return inTx(ctx, s.Database, group, s.confirmTOTP)
	case es.RemoveTOTP:
		return inTx(ctx, s.Database, group, s.removeTOTP)
	case es.ReissueRecoveryCodes:
		return inTx(ctx, s.Database, group, s.reissueRecoveryCodes)
	case es.DeleteAccount:
		return inTx(ctx, s.Database, group, s.deleteAccount)
	default:
		return group, es.ErrNoArguments
	}
}

// removePasskey marks group.Passkey as removed. With [es.ConsumeChallenge] it also uses up the confirmation challenge of
// group.Session in the same transaction, so a confirmation works once. It locks the user first and reads the
// passkeys of the user after the lock, in the same transaction, so two removals cannot both pass the check.
//
// The lock order is the user, the passkey. It returns [es.ErrLastFactor] if no other usable passkey
// and no TOTP factor stays, and then it writes nothing.
func (s *AccountGroupWriter) removePasskey(tx *sql.Tx, group es.AccountGroup, op es.Op) (es.AccountGroup, error) {
	locked, err := s.UserTx.LockOneTx(tx, es.User{
		ID: group.User.ID,
	})
	if err != nil {
		return group, fmt.Errorf("lock the user: %w", err)
	}

	others, err := s.countUsablePasskeys(tx, group.User.ID, group.Passkey.ID)
	if err != nil {
		return group, err
	}

	if others == 0 && !locked.HasTOTP() {
		return group, es.ErrLastFactor
	}

	if op&es.ConsumeChallenge != 0 {
		err = s.SessionTx.UpdateOneTx(tx, es.Session{
			ID:    group.Session.ID,
			Flags: es.SessionFlagChallenge,
		}, es.WriteUpdate|es.ClearFlag|es.ConsumeChallenge)
		if err != nil {
			return group, fmt.Errorf("consume the challenge: %w", err)
		}
	}

	err = s.PasskeyTx.UpdateOneTx(tx, es.Passkey{
		ID:    group.Passkey.ID,
		Flags: es.PasskeyFlagRemoved,
	}, es.WriteUpdate|es.AppendFlag)
	if err != nil {
		return group, fmt.Errorf("remove the passkey: %w", err)
	}

	return group, nil
}

// passkeyPageSize is the number of passkeys that [AccountGroupWriter.countUsablePasskeys] reads at a time.
const passkeyPageSize = 1000

// countUsablePasskeys returns the number of usable passkeys of the user, not counting the passkey with the ID except.
// It reads every page, so the count does not depend on how many passkeys the user has. A zero except skips nothing.
func (s *AccountGroupWriter) countUsablePasskeys(tx *sql.Tx, userID, except uint64) (int, error) {
	usable := 0

	for page := uint64(1); ; page++ {
		passkeys, err := s.PasskeyBatchTx.ReadAllTx(tx, es.Passkey{
			UserID: userID,
		}, es.PageNumberPagination{
			Page:     page,
			PageSize: passkeyPageSize,
		}, 0)
		if err != nil {
			return 0, fmt.Errorf("read the passkeys: %w", err)
		}

		for _, passkey := range passkeys {
			if passkey.ID != except && passkey.Usable() {
				usable++
			}
		}

		if len(passkeys) < passkeyPageSize {
			return usable, nil
		}
	}
}

// confirmTOTP marks the TOTP secret of group.User as confirmed, stores the step of the accepted code.
// It locks the user by the update of the first step.
//
// The lock order is the user. It returns [es.ErrNoUpdatedRows] if the user is missing.
func (s *AccountGroupWriter) confirmTOTP(tx *sql.Tx, group es.AccountGroup) (es.AccountGroup, error) {
	err := s.UserTx.UpdateOneTx(tx, es.User{
		ID:             group.User.ID,
		Flags:          es.UserFlagTOTPConfirmed,
		TOTPCiphertext: group.User.TOTPCiphertext,
		TOTPLastStep:   group.User.TOTPLastStep,
	}, es.WriteUpdate|es.AppendFlag|es.ResetTOTP)
	if err != nil {
		return group, fmt.Errorf("confirm the secret: %w", err)
	}

	return group, nil
}

// removeTOTP deletes the TOTP secret of the user. It locks the user first and reads the
// passkeys after the lock, in the same transaction, so the check and the removal see the same state.
//
// The lock order is the user. It returns [es.ErrNoTOTPSecret] if the user has no secret and
// [es.ErrLastFactor] if the user has no usable passkey, and then it writes nothing.
func (s *AccountGroupWriter) removeTOTP(tx *sql.Tx, group es.AccountGroup) (es.AccountGroup, error) {
	locked, err := s.UserTx.LockOneTx(tx, es.User{
		ID: group.User.ID,
	})
	if err != nil {
		return group, fmt.Errorf("lock the user: %w", err)
	}

	if locked.TOTPCiphertext == "" {
		return group, es.ErrNoTOTPSecret
	}

	usable, err := s.countUsablePasskeys(tx, group.User.ID, 0)
	if err != nil {
		return group, err
	}

	if usable == 0 {
		return group, es.ErrLastFactor
	}

	err = s.UserTx.UpdateOneTx(tx, es.User{
		ID:    group.User.ID,
		Flags: es.UserFlagTOTPConfirmed,
	}, es.WriteUpdate|es.ClearFlag|es.ResetTOTP)
	if err != nil {
		return group, fmt.Errorf("remove the secret: %w", err)
	}

	return group, nil
}

// reissueRecoveryCodes retires the earlier codes of the user, stores group.Codes. It locks the
// user first, so two reissues run one after the other. A user without an earlier code is not an error.
//
// The lock order is the user, the recovery codes. It returns [es.ErrDuplicate] if a code exists
// already, and then it writes nothing. The group carries the stored codes.
func (s *AccountGroupWriter) reissueRecoveryCodes(tx *sql.Tx, group es.AccountGroup) (es.AccountGroup, error) {
	_, err := s.UserTx.LockOneTx(tx, es.User{
		ID: group.User.ID,
	})
	if err != nil {
		return group, fmt.Errorf("lock the user: %w", err)
	}

	err = s.RecoveryCodeTx.ReplaceFlagOneTx(tx, 0, es.RecoveryCodeFlagUsed, es.RecoveryCode{
		UserID: group.User.ID,
	})
	if err != nil && !errors.Is(err, es.ErrNoUpdatedRows) {
		return group, fmt.Errorf("retire the earlier recovery codes: %w", err)
	}

	stored := make([]es.RecoveryCode, 0, len(group.Codes))

	for _, code := range group.Codes {
		created, err := s.RecoveryCodeTx.CreateOneTx(tx, code)
		if err != nil {
			return group, fmt.Errorf("store a recovery code: %w", err)
		}

		stored = append(stored, created)
	}

	group.Codes = stored

	return group, nil
}

// deleteAccount deletes the user of group.User, with its passkeys, recovery codes, recovery requests and sessions, and
// removes the user, the address, the user agent and the texts from the rows of the request log of the user. The rows
// stay as counts of requests without a person. It locks the user first, so a change of a factor cannot run at the same
// time.
//
// It returns [es.ErrNotFound] if the user does not exist.
func (s *AccountGroupWriter) deleteAccount(tx *sql.Tx, group es.AccountGroup) (es.AccountGroup, error) {
	locked, err := s.UserTx.LockOneTx(tx, es.User{
		ID: group.User.ID,
	})
	if err != nil {
		return group, fmt.Errorf("lock the user: %w", err)
	}

	steps := []struct {
		name  string
		query string
		key   uint64
	}{
		{
			"delete the recovery requests",
			expr.DeleteUserRecoveryRequests,
			locked.ID,
		},
		{
			"delete the recovery codes",
			expr.DeleteUserRecoveryCodes,
			locked.ID,
		},
		{
			"delete the passkeys",
			expr.DeleteUserPasskeys,
			locked.ID,
		},
		{
			"delete the sessions",
			expr.DeleteUserSessions,
			locked.ID,
		},
		{
			"erase the request log",
			expr.EraseUserHTTPRequests,
			locked.UserXID,
		},
		{
			"delete the user",
			expr.DeleteUser,
			locked.ID,
		},
	}

	for _, statement := range steps {
		if _, err := tx.Exec(statement.query, statement.key); err != nil {
			return group, fmt.Errorf("%s: %w", statement.name, err)
		}
	}

	group.User = locked

	return group, nil
}
