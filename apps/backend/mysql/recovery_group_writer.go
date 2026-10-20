package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

var _ es.Writer[es.RecoveryGroup] = &RecoveryGroupWriter{}

// RecoveryGroupWriter implements [es.Writer] for [es.RecoveryGroup]. Every intent runs in one database transaction.
//
// The lock order is the session rows, then the recovery request. No intent calls a service outside the database while the transaction is open.
type RecoveryGroupWriter struct {
	Database          *sql.DB
	SystemClock       clock.Clock
	SessionTx         es.Tx[es.Session, es.SessionFlag]
	RecoveryRequestTx es.Tx[es.RecoveryRequest, es.RecoveryRequestFlag]
}

// WriteOne runs the intent that op sets and returns the group with the records that the stores returned.
//
// The intents are listed in [es.RecoveryIntents]. A failed step rolls back all the steps of the intent, and a step
// after it does not run.
//
// It returns [es.ErrNoArguments] if op sets no intent or more than one. Each private method documents the other errors
// of its intent.
func (s *RecoveryGroupWriter) WriteOne(ctx context.Context, group es.RecoveryGroup, op es.Op) (es.RecoveryGroup, error) {
	switch op & es.RecoveryIntents {
	case es.OpenRecoveryRequest:
		return inTx(ctx, s.Database, group, s.openRequest)
	case es.CancelRecoveryRequest:
		return inTx(ctx, s.Database, group, s.cancelRequest)
	case es.IssueRecoveryGrant:
		return inTx(ctx, s.Database, group, s.issueGrant)
	case es.RedeemRecoveryGrant:
		return inTx(ctx, s.Database, group, s.redeemGrant)
	default:
		return group, es.ErrNoArguments
	}
}

// openRequest stores group.Request as a new request. The group carries the request with its ID
// set.
//
// The lock order is the new request. It returns [es.ErrDuplicate] if the request exists already.
func (s *RecoveryGroupWriter) openRequest(tx *sql.Tx, group es.RecoveryGroup) (es.RecoveryGroup, error) {
	request, err := s.RecoveryRequestTx.CreateOneTx(tx, group.Request)
	if err != nil {
		return group, fmt.Errorf("create the recovery request: %w", err)
	}

	group.Request = request

	return group, nil
}

// cancelRequest adds [es.RecoveryRequestFlagCancelled] to the open request that the CancelHash of group.Request names
// . The cancel token works once.
//
// The lock order is the recovery request. It returns [es.ErrNoUpdatedRows] if no open request
// matches, and then it changes nothing.
func (s *RecoveryGroupWriter) cancelRequest(tx *sql.Tx, group es.RecoveryGroup) (es.RecoveryGroup, error) {
	err := s.RecoveryRequestTx.UpdateOneTx(tx, group.Request, es.WriteUpdate|es.AppendFlag|es.CancelRecoveryRequest)
	if err != nil {
		return group, fmt.Errorf("cancel the recovery request: %w", err)
	}

	return group, nil
}

// issueGrant writes the GrantHash and the GrantExpiresAt of group.Request on the approved, open request and appends
//
// The lock order is the recovery request. It returns [es.ErrNoUpdatedRows] if no approved, open
// request matches, and then it changes nothing.
func (s *RecoveryGroupWriter) issueGrant(tx *sql.Tx, group es.RecoveryGroup) (es.RecoveryGroup, error) {
	err := s.RecoveryRequestTx.UpdateOneTx(tx, group.Request, es.WriteUpdate|es.IssueRecoveryGrant)
	if err != nil {
		return group, fmt.Errorf("issue the grant: %w", err)
	}

	return group, nil
}

// redeemGrant redeems the grant of group.Request. In this order it revokes every other session of the user, binds the
// current session to the account, uses the grant up. The current session is not among the
// revoked sessions, because it has no account yet. A user without another session is not an error.
//
// The lock order is the sessions of the user, the recovery request. It returns
// [es.ErrNoUpdatedRows] if the grant is unknown, used, expired or not approved, and then it changes nothing.
func (s *RecoveryGroupWriter) redeemGrant(tx *sql.Tx, group es.RecoveryGroup) (es.RecoveryGroup, error) {
	err := s.SessionTx.ReplaceFlagOneTx(tx, es.SessionFlagAuthorized, es.SessionFlagRevoked, es.Session{
		UserID: group.Session.UserID,
	})
	if err != nil && !errors.Is(err, es.ErrNoUpdatedRows) {
		return group, fmt.Errorf("revoke the sessions: %w", err)
	}

	err = bindSession(tx, s.SessionTx, group.Session)
	if err != nil {
		return group, err
	}

	err = s.RecoveryRequestTx.UpdateOneTx(tx, es.RecoveryRequest{
		GrantHash: group.Request.GrantHash,
		Flags:     es.RecoveryRequestFlagGranted,
	}, es.WriteUpdate|es.AppendFlag|es.UseUpRecoveryGrant)
	if err != nil {
		return group, fmt.Errorf("use the grant up: %w", err)
	}

	return group, nil
}
