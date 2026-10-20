package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

var _ es.Writer[es.SessionGroup] = &SessionGroupWriter{}

// SessionGroupWriter implements [es.Writer] for [es.SessionGroup]. Every intent runs in one database transaction.
//
// All the writers of the package take their locks in one order: the user, then the session, then the passkey and the
// recovery rows. No intent calls a service outside the database while the transaction is open.
type SessionGroupWriter struct {
	Database          *sql.DB
	SystemClock       clock.Clock
	SessionTx         es.Tx[es.Session, es.SessionFlag]
	UserTx            es.Tx[es.User, es.UserFlag]
	PasskeyTx         es.Tx[es.Passkey, es.PasskeyFlag]
	RecoveryCodeTx    es.Tx[es.RecoveryCode, es.RecoveryCodeFlag]
	RecoveryRequestTx es.Tx[es.RecoveryRequest, es.RecoveryRequestFlag]
}

// WriteOne runs the intent that op sets and returns the group with the records that the stores returned.
//
// The intents are listed in [es.SessionIntents]. A failed step rolls back all the steps of the intent, and a step after
// it does not run.
//
// It returns [es.ErrNoArguments] if op sets no intent or more than one. Each private method documents the other errors
// of its intent.
func (s *SessionGroupWriter) WriteOne(ctx context.Context, group es.SessionGroup, op es.Op) (es.SessionGroup, error) {
	switch op & es.SessionIntents {
	case es.OpenRegistry:
		return inTx(ctx, s.Database, group, s.openRegistry)
	case es.OpenTakenRegistry:
		return inTx(ctx, s.Database, group, s.openTakenRegistry)
	case es.VerifyRegistry:
		return inTx(ctx, s.Database, group, s.verifyRegistry)
	case es.RevokeSession:
		return inTx(ctx, s.Database, group, s.revokeSession)
	case es.OpenPasskeyEnrollment, es.OpenConfirmation:
		return inTx(ctx, s.Database, group, s.saveChallenge)
	case es.EnrollPasskey:
		return inTx(ctx, s.Database, group, s.enrollPasskey)
	case es.RefusePasskeyEnrollment:
		return inTx(ctx, s.Database, group, s.refusePasskeyEnrollment)
	case es.OpenPasskeyLogin:
		return inTx(ctx, s.Database, group, s.openPasskeyLogin)
	case es.RefuseLogin:
		return inTx(ctx, s.Database, group, func(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
			return s.refuseLogin(tx, group, op)
		})
	case es.AuthorizeLogin:
		return inTx(ctx, s.Database, group, func(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
			return s.authorizeLogin(tx, group, op)
		})
	case es.DenyLogin:
		return inTx(ctx, s.Database, group, func(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
			return s.denyLogin(tx, group, op)
		})
	case es.ApprovePassword:
		return inTx(ctx, s.Database, group, s.approvePassword)
	case es.ApproveRecoveryCode:
		return inTx(ctx, s.Database, group, s.approveRecoveryCode)
	default:
		return group, es.ErrNoArguments
	}
}

// openRegistry creates group.User, binds group.Session to it. The session update adds the
// flags of group.Session.
//
// The lock order is the new user, the session. It returns [es.ErrDuplicate] if the email of the user
// is taken, and [es.ErrNoUpdatedRows] if the session is missing.
func (s *SessionGroupWriter) openRegistry(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
	user, err := s.UserTx.CreateOneTx(tx, group.User)
	if err != nil {
		return group, fmt.Errorf("create the user: %w", err)
	}

	group.User = user
	group.Session.UserID = user.ID

	err = s.SessionTx.UpdateOneTx(tx, group.Session, es.WriteUpdate|es.AppendFlag)
	if err != nil {
		return group, fmt.Errorf("bind the session: %w", err)
	}

	return group, nil
}

// openTakenRegistry adds the flags and the verification token of group.Session to the stored session.
// It creates no user, so the response of the registration does not show that the email is taken.
//
// The lock order is the session. It returns [es.ErrNoUpdatedRows] if the session is missing.
func (s *SessionGroupWriter) openTakenRegistry(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
	err := s.SessionTx.UpdateOneTx(tx, group.Session, es.WriteUpdate|es.AppendFlag)
	if err != nil {
		return group, fmt.Errorf("mark the session: %w", err)
	}

	return group, nil
}

// verifyRegistry marks group.User as verified, marks group.Session as verified with its verification token cleared,
// .
//
// The lock order is the user, the session. It returns [es.ErrNoUpdatedRows] if the user or the
// session is missing.
func (s *SessionGroupWriter) verifyRegistry(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
	err := s.UserTx.UpdateOneTx(tx, group.User, es.WriteUpdate|es.AppendFlag)
	if err != nil {
		return group, fmt.Errorf("verify the user: %w", err)
	}

	err = s.SessionTx.UpdateOneTx(tx, group.Session, es.WriteUpdate|es.AppendFlag|es.ClearVerifyToken)
	if err != nil {
		return group, fmt.Errorf("verify the session: %w", err)
	}

	return group, nil
}

// revokeSession replaces [es.SessionFlagAuthorized] with [es.SessionFlagRevoked] on the session with the ID of
// group.Session.
//
// The lock order is the session. It returns [es.ErrNoUpdatedRows] if the session is missing.
func (s *SessionGroupWriter) revokeSession(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
	err := s.SessionTx.ReplaceFlagOneTx(tx, es.SessionFlagAuthorized, es.SessionFlagRevoked, group.Session)
	if err != nil {
		return group, fmt.Errorf("revoke the session: %w", err)
	}

	return group, nil
}

// saveChallenge saves the challenge of group.Session and marks the ceremony. A passkey registration and the
// confirmation of an action use it. It clears every earlier challenge
// bit first, so a stale bit of an earlier ceremony, such as the discoverable bit of a login, does not stay.
//
// The lock order is the session. It returns [es.ErrNoUpdatedRows] if the session is missing.
func (s *SessionGroupWriter) saveChallenge(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
	err := s.SessionTx.UpdateOneTx(tx, es.Session{
		ID:                 group.Session.ID,
		Flags:              es.SessionFlagChallenge,
		Challenge:          group.Session.Challenge,
		ChallengeExpiresAt: group.Session.ChallengeExpiresAt,
	}, es.WriteUpdate|es.ClearFlag)
	if err != nil {
		return group, fmt.Errorf("keep the challenge: %w", err)
	}

	err = s.SessionTx.UpdateOneTx(tx, es.Session{
		ID:    group.Session.ID,
		Flags: group.Session.Flags,
	}, es.WriteUpdate|es.AppendFlag)
	if err != nil {
		return group, fmt.Errorf("mark the ceremony: %w", err)
	}

	return group, nil
}

// enrollPasskey uses up the challenge of the session, stores group.Passkey.
//
// The lock order is the session, the passkey. It returns [es.ErrNoUpdatedRows] if the session holds
// no challenge, so a challenge works once, and [es.ErrDuplicate] if the passkey exists already. In both cases it
// writes nothing.
func (s *SessionGroupWriter) enrollPasskey(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
	err := s.consumeChallenge(tx, group.Session)
	if err != nil {
		return group, err
	}

	passkey, err := s.PasskeyTx.CreateOneTx(tx, group.Passkey)
	if err != nil {
		return group, fmt.Errorf("store the passkey: %w", err)
	}

	group.Passkey = passkey

	return group, nil
}

// refusePasskeyEnrollment uses up the challenge of the session after a registration that did not verify and appends
//
// The lock order is the session. It returns [es.ErrNoUpdatedRows] if the session holds no
// challenge, and then it changes nothing.
func (s *SessionGroupWriter) refusePasskeyEnrollment(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
	err := s.consumeChallenge(tx, group.Session)
	if err != nil {
		return group, err
	}

	return group, nil
}

// openPasskeyLogin starts a new login attempt on the session of the group and saves its challenge. A new attempt starts
// clean: it clears the bits of the earlier factors, the earlier outcome and the earlier challenge, sets the bits of
// group.Session, and replaces the account of the earlier attempt by the account of this one, if there is one.
//
// The lock order is the session. It returns [es.ErrNoUpdatedRows] if the session is missing.
func (s *SessionGroupWriter) openPasskeyLogin(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
	err := s.SessionTx.ReplaceFlagOneTx(tx, es.SessionFlagLoginAttempt|es.SessionFlagChallenge, group.Session.Flags, es.Session{
		ID: group.Session.ID,
	})
	if err != nil {
		return group, fmt.Errorf("reset the session: %w", err)
	}

	err = s.SessionTx.UpdateOneTx(tx, es.Session{
		ID:                 group.Session.ID,
		UserID:             group.Session.UserID,
		Challenge:          group.Session.Challenge,
		ChallengeExpiresAt: group.Session.ChallengeExpiresAt,
	}, es.WriteUpdate)
	if err != nil {
		return group, fmt.Errorf("keep the challenge: %w", err)
	}

	return group, nil
}

// refuseLogin records a refused attempt of a factor. It stores the TOTP counters of the user, the failure count of the
// session, the flag bits of the passkey, in this order, and it skips the record whose ID is zero.
// With [es.ConsumeChallenge] the session step uses up the challenge too.
//
// The transaction commits when the steps succeed, so the failure counters of a refused login persist. The lock order is the user, the session, the passkey. It returns [es.ErrNoUpdatedRows]
// if a record is missing or if [es.ConsumeChallenge] finds no challenge, and then it writes nothing.
func (s *SessionGroupWriter) refuseLogin(tx *sql.Tx, group es.SessionGroup, op es.Op) (es.SessionGroup, error) {
	if group.User.ID != 0 {
		userOp := es.WriteUpdate | es.ResetTOTP
		if group.User.TOTPFailures != 0 {
			userOp = es.WriteUpdate | es.CountTOTPFailure
		}

		err := s.UserTx.UpdateOneTx(tx, group.User, userOp)
		if err != nil {
			return group, fmt.Errorf("count the code failure: %w", err)
		}
	}

	switch {
	case op&es.ConsumeChallenge != 0:
		err := s.SessionTx.UpdateOneTx(tx, es.Session{
			ID:       group.Session.ID,
			Flags:    es.SessionFlagChallenge,
			Failures: group.Session.Failures,
		}, es.WriteUpdate|es.ClearFlag|es.ConsumeChallenge)
		if err != nil {
			return group, fmt.Errorf("consume the challenge: %w", err)
		}
	case group.Session.ID != 0:
		err := s.SessionTx.UpdateOneTx(tx, es.Session{
			ID:       group.Session.ID,
			Failures: group.Session.Failures,
		}, es.WriteUpdate)
		if err != nil {
			return group, fmt.Errorf("count the failure: %w", err)
		}
	}

	if group.Passkey.ID != 0 {
		err := s.PasskeyTx.UpdateOneTx(tx, es.Passkey{
			ID:    group.Passkey.ID,
			Flags: group.Passkey.Flags,
		}, es.WriteUpdate|es.AppendFlag)
		if err != nil {
			return group, fmt.Errorf("mark the passkey: %w", err)
		}
	}

	return group, nil
}

// authorizeLogin records a login that a factor accepted and the risk engine allowed. In this order it stores the TOTP
// step of the user, uses up the challenge (with [es.ConsumeChallenge]), stores the counter of the passkey, authorizes
// the session, ends the open recovery requests of the user. It skips the user and the
// passkey whose ID is zero.
//
// The session update adds the flags of group.Session, binds the account, and stores the time of the factor, the risk
// score and a zero failure count. A login with a factor shows that the owner is in control, so the recovery requests of
// the UserID of the session end. A user without an open request is not an error.
//
// The lock order is the user, the session, the passkey, the recovery requests. It returns
// [es.ErrNoUpdatedRows] if a record is missing or if [es.ConsumeChallenge] finds no challenge.
func (s *SessionGroupWriter) authorizeLogin(tx *sql.Tx, group es.SessionGroup, op es.Op) (es.SessionGroup, error) {
	err := s.storeFactor(tx, group, op)
	if err != nil {
		return group, err
	}

	err = s.SessionTx.UpdateOneTx(tx, es.Session{
		ID:        group.Session.ID,
		UserID:    group.Session.UserID,
		Flags:     group.Session.Flags,
		AuthTime:  group.Session.AuthTime,
		RiskScore: group.Session.RiskScore,
	}, es.WriteUpdate|es.AppendFlag|es.StoreRiskOutcome)
	if err != nil {
		return group, fmt.Errorf("authorize the session: %w", err)
	}

	err = s.endOpenRecoveries(tx, group.Session.UserID)
	if err != nil {
		return group, err
	}

	return group, nil
}

// denyLogin records a login that a factor accepted and the risk engine refused. In this order it stores the TOTP step
// of the user, uses up the challenge (with [es.ConsumeChallenge]), stores the counter of the passkey, clears the factor
// bits of the session and stores its risk score. It skips the user and the passkey whose
// ID is zero. The open recovery requests of the user stay.
//
// The transaction commits when the steps succeed, so the refusal persists. The lock order is the user, the session,
// the passkey. It returns [es.ErrNoUpdatedRows] if a record is missing or if [es.ConsumeChallenge]
// finds no challenge.
func (s *SessionGroupWriter) denyLogin(tx *sql.Tx, group es.SessionGroup, op es.Op) (es.SessionGroup, error) {
	err := s.storeFactor(tx, group, op)
	if err != nil {
		return group, err
	}

	err = s.SessionTx.UpdateOneTx(tx, es.Session{
		ID:        group.Session.ID,
		Flags:     es.SessionFlagFactors,
		RiskScore: group.Session.RiskScore,
	}, es.WriteUpdate|es.ClearFlag)
	if err != nil {
		return group, fmt.Errorf("refuse the session: %w", err)
	}

	return group, nil
}

// approvePassword replaces the factor and authorization bits of the session by the bits of group.Session, stores its
// UserID. The password path uses no recovery code and leaves the recovery requests as they are.
//
// The lock order is the session. It returns [es.ErrNoUpdatedRows] if the session is missing.
func (s *SessionGroupWriter) approvePassword(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
	err := bindSession(tx, s.SessionTx, group.Session)
	if err != nil {
		return group, err
	}

	return group, nil
}

// approveRecoveryCode binds the session to the account after an accepted recovery code. In this order it replaces the
// factor and authorization bits of the session by the bits of group.Session, stores its UserID, uses up the code
// group.RecoveryCode, ends the open recovery requests of the user. A recovery code shows that
// the owner is in control, so the requests end.
//
// The lock order is the session, the recovery code, the recovery requests. It returns
// [es.ErrNoUpdatedRows] if the code is unknown or used, or the session is missing, and [es.ErrNoArguments] if the MAC
// of the code is empty.
func (s *SessionGroupWriter) approveRecoveryCode(tx *sql.Tx, group es.SessionGroup) (es.SessionGroup, error) {
	err := bindSession(tx, s.SessionTx, group.Session)
	if err != nil {
		return group, err
	}

	err = s.RecoveryCodeTx.UpdateOneTx(tx, es.RecoveryCode{
		UserID: group.Session.UserID,
		MAC:    group.RecoveryCode.MAC,
		Flags:  es.RecoveryCodeFlagUsed,
	}, es.WriteUpdate|es.AppendFlag|es.UseUpRecoveryCode)
	if err != nil {
		return group, fmt.Errorf("use the code up: %w", err)
	}

	err = s.endOpenRecoveries(tx, group.Session.UserID)
	if err != nil {
		return group, err
	}

	return group, nil
}

// storeFactor stores the state of the accepted factor: the TOTP step of the user, the used challenge and the counter of
// the passkey. It skips the user and the passkey whose ID is zero.
func (s *SessionGroupWriter) storeFactor(tx *sql.Tx, group es.SessionGroup, op es.Op) error {
	if group.User.ID != 0 {
		userOp := es.WriteUpdate | es.ResetTOTP
		if group.User.TOTPLastStep != 0 {
			userOp = es.WriteUpdate | es.AdvanceTOTPStep
		}

		err := s.UserTx.UpdateOneTx(tx, group.User, userOp)
		if err != nil {
			return fmt.Errorf("store the step: %w", err)
		}
	}

	if op&es.ConsumeChallenge != 0 {
		err := s.consumeChallenge(tx, group.Session)
		if err != nil {
			return err
		}
	}

	if group.Passkey.ID != 0 {
		err := s.PasskeyTx.UpdateOneTx(tx, group.Passkey, es.WriteUpdate|es.RewriteFlag)
		if err != nil {
			return fmt.Errorf("store the counter: %w", err)
		}
	}

	return nil
}

// consumeChallenge clears the challenge and its bits on the session. It returns [es.ErrNoUpdatedRows] if the session
// holds no challenge.
func (s *SessionGroupWriter) consumeChallenge(tx *sql.Tx, session es.Session) error {
	err := s.SessionTx.UpdateOneTx(tx, es.Session{
		ID:    session.ID,
		Flags: es.SessionFlagChallenge,
	}, es.WriteUpdate|es.ClearFlag|es.ConsumeChallenge)
	if err != nil {
		return fmt.Errorf("consume the challenge: %w", err)
	}

	return nil
}

// endOpenRecoveries cancels every open recovery request of the user. A user without an open request is not an error.
func (s *SessionGroupWriter) endOpenRecoveries(tx *sql.Tx, userID uint64) error {
	err := s.RecoveryRequestTx.ReplaceFlagOneTx(tx, 0, es.RecoveryRequestFlagCancelled, es.RecoveryRequest{
		UserID: userID,
	})
	if err != nil && !errors.Is(err, es.ErrNoUpdatedRows) {
		return fmt.Errorf("cancel the recovery requests: %w", err)
	}

	return nil
}

// bindSession replaces the factor and authorization bits of the session by its Flags and stores its UserID. The session
// writer and the recovery writer share it.
func bindSession(tx *sql.Tx, store es.Tx[es.Session, es.SessionFlag], session es.Session) error {
	err := store.ReplaceFlagOneTx(tx, es.SessionFlagLoginAttempt, session.Flags, es.Session{
		ID: session.ID,
	})
	if err != nil {
		return fmt.Errorf("reset the session: %w", err)
	}

	err = store.UpdateOneTx(tx, es.Session{
		ID:     session.ID,
		UserID: session.UserID,
	}, es.WriteUpdate)
	if err != nil {
		return fmt.Errorf("bind the session: %w", err)
	}

	return nil
}
