package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql/expr"
)

var _ es.Reader[es.RecoveryRequest] = &RecoveryRequestReader{}
var _ es.Writer[es.RecoveryRequest] = &RecoveryRequestWriter{}
var _ es.Replacer[es.RecoveryRequest, es.RecoveryRequestFlag] = &RecoveryRequestReplacer{}
var _ es.BatchReader[es.RecoveryRequest] = &RecoveryRequestBatchReader{}
var _ es.Tx[es.RecoveryRequest, es.RecoveryRequestFlag] = &RecoveryRequestTx{}

// scanRecoveryRequest reads the columns that the select statements of recovery requests return from row. It returns
// the error of the scan as it is, so the caller can tell a missing row.
func scanRecoveryRequest(row rowScanner) (es.RecoveryRequest, error) {
	var request es.RecoveryRequest
	var grantExpires sql.NullTime

	err := row.Scan(
		&request.ID,
		&request.RecoveryRequestXID,
		&request.Flags,
		&request.UserID,
		&request.CancelHash,
		&request.GrantHash,
		&grantExpires,
		&request.ReadyAt,
		&request.CreatedAt,
	)
	if err != nil {
		return es.RecoveryRequest{}, err
	}

	request.GrantExpiresAt = grantExpires.Time
	request.GrantHash = FromDefaultBlob(request.GrantHash)

	return request, nil
}

// recoveryRequestUpdate returns the statement and the arguments that the option of op selects for the request in item.
// It reports false if op has no option of a recovery request or item lacks the fields that the option needs. now is the
// time that the statements of an approval and of a grant compare with.
func recoveryRequestUpdate(item es.RecoveryRequest, op es.Op, now time.Time) (string, []any, bool) {
	switch {
	case op&es.CancelRecoveryRequest != 0 && len(item.CancelHash) != 0:
		return expr.CancelRecoveryRequest, []any{
			item.Flags,
			item.CancelHash,
			es.RecoveryRequestClosed,
		}, true
	case op&es.ApproveRecoveryRequest != 0 && item.RecoveryRequestXID != 0:
		return expr.ApproveRecoveryRequest, []any{
			item.Flags,
			item.RecoveryRequestXID,
			es.RecoveryRequestClosed,
			now,
		}, true
	case op&es.IssueRecoveryGrant != 0 && item.ID != 0 && len(item.GrantHash) != 0:
		return expr.IssueRecoveryGrant, []any{
			item.GrantHash,
			item.GrantExpiresAt,
			item.ID,
			es.RecoveryRequestFlagApproved,
			es.RecoveryRequestFlagApproved,
			es.RecoveryRequestClosed,
		}, true
	case op&es.UseUpRecoveryGrant != 0 && len(item.GrantHash) != 0:
		return expr.UseUpRecoveryGrant, []any{
			item.Flags,
			item.GrantHash,
			es.RecoveryRequestFlagApproved,
			es.RecoveryRequestFlagApproved,
			es.RecoveryRequestClosed,
			now,
		}, true
	}

	return "", nil, false
}

// RecoveryRequestReader implements [es.Reader] for recovery requests.
type RecoveryRequestReader struct {
	Database *sql.DB
}

// ReadOne returns the request that the first set field of the argument identifies. With a GrantHash it returns the
// request with that grant, whatever its state. With a UserID it returns the newest open request of the user.
//
// It returns [es.ErrNoArguments] if neither is set and [es.ErrNotFound] if there is no such request.
func (s *RecoveryRequestReader) ReadOne(ctx context.Context, args es.RecoveryRequest, _ es.Op) (es.RecoveryRequest, error) {
	var row *sql.Row
	switch {
	case len(args.GrantHash) != 0:
		row = s.Database.QueryRowContext(ctx, expr.RecoveryRequestByGrantHash, args.GrantHash)
	case args.UserID != 0:
		row = s.Database.QueryRowContext(ctx, expr.RecoveryRequestByUser, args.UserID, es.RecoveryRequestClosed)
	default:
		return es.RecoveryRequest{}, es.ErrNoArguments
	}

	request, err := scanRecoveryRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return es.RecoveryRequest{}, es.ErrNotFound
	} else if err != nil {
		return es.RecoveryRequest{}, err
	}

	return request, nil
}

// RecoveryRequestWriter implements [es.Writer] for recovery requests.
type RecoveryRequestWriter struct {
	Database    *sql.DB
	SystemClock clock.Clock
}

// WriteOne creates a request, or updates one with the option of the call.
//
// A create stores the item with ReadyAt as the end of its delay. An update with [es.CancelRecoveryRequest],
// [es.ApproveRecoveryRequest], [es.IssueRecoveryGrant] or [es.UseUpRecoveryGrant] changes the one open request that
// the argument names, as the option describes.
//
// It returns [es.ErrNoArguments] for any other call and [es.ErrNoUpdatedRows] if an update matches no request.
func (s *RecoveryRequestWriter) WriteOne(ctx context.Context, item es.RecoveryRequest, op es.Op) (es.RecoveryRequest, error) {
	switch {
	case es.IsCreate(op):
		return s.createOne(ctx, item)
	case !es.IsUpdate(op):
		return item, es.ErrNoArguments
	}

	query, args, ok := recoveryRequestUpdate(item, op, s.SystemClock.Now())
	if !ok {
		return item, es.ErrNoArguments
	}

	result, err := s.Database.ExecContext(ctx, query, args...)
	if err != nil {
		return item, fmt.Errorf("update a recovery request: %w", err)
	}

	if MustRowsAffected(result) == 0 {
		return item, es.ErrNoUpdatedRows
	}

	return item, nil
}

func (s *RecoveryRequestWriter) createOne(ctx context.Context, request es.RecoveryRequest) (es.RecoveryRequest, error) {
	request.CreatedAt = s.SystemClock.Now()

	result, err := s.Database.ExecContext(ctx, expr.CreateRecoveryRequest,
		request.RecoveryRequestXID,
		request.Flags,
		request.UserID,
		request.CancelHash,
		request.ReadyAt,
		request.CreatedAt,
	)
	if IsDuplicate(err) {
		return request, es.ErrDuplicate
	} else if err != nil {
		return request, fmt.Errorf("create a recovery request: %w", err)
	}

	request.ID = MustLastID[uint64](result)

	if request.ID == 0 {
		return request, es.ErrNoCreatedRows
	}

	return request, nil
}

// RecoveryRequestReplacer implements [es.Replacer] for recovery requests. It cancels the open requests of a user.
type RecoveryRequestReplacer struct {
	Database *sql.DB
}

// ReplaceOne adds the newest bits to every open request of the UserID of the item. It accepts only a call with
// [es.AllOfUser]. It ignores the oldest bits.
//
// It returns [es.ErrNoArguments] for any other call and [es.ErrNoUpdatedRows] if the user has no open request.
func (s *RecoveryRequestReplacer) ReplaceOne(ctx context.Context, _, newest es.RecoveryRequestFlag, item es.RecoveryRequest, op es.Op) error {
	if op&es.AllOfUser == 0 || item.UserID == 0 {
		return es.ErrNoArguments
	}

	result, err := s.Database.ExecContext(ctx, expr.CancelRecoveryRequestsByUser, newest, item.UserID, es.RecoveryRequestClosed)
	if err != nil {
		return err
	}

	if MustRowsAffected(result) == 0 {
		return es.ErrNoUpdatedRows
	}

	return nil
}

// RecoveryRequestBatchReader implements [es.BatchReader] for recovery requests.
type RecoveryRequestBatchReader struct {
	Database *sql.DB
}

// ReadAll returns a page of the open requests, oldest first. It ignores the fields of the argument.
func (s *RecoveryRequestBatchReader) ReadAll(ctx context.Context, _ es.RecoveryRequest, paging es.Paginator, _ es.Op) ([]es.RecoveryRequest, error) {
	rows, err := s.Database.QueryContext(ctx, expr.RecoveryRequestsOpen, es.RecoveryRequestClosed, paging.Limit(), paging.Offset())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []es.RecoveryRequest
	for rows.Next() {
		request, err := scanRecoveryRequest(rows)
		if err != nil {
			return nil, err
		}

		requests = append(requests, request)
	}

	return requests, rows.Err()
}

// RecoveryRequestTx implements [es.Tx] for recovery requests. It finds and locks a request by GrantHash or by UserID,
// the same way [RecoveryRequestReader] does.
type RecoveryRequestTx struct {
	SystemClock clock.Clock
}

// FindOneTx returns the request that the first set field of the argument identifies, without locking it. With a
// GrantHash it returns the request with that grant, whatever its state. With a UserID it returns the newest open
// request of the user.
//
// It returns [es.ErrNoArguments] if neither is set and [es.ErrNotFound] if there is no such request.
func (s *RecoveryRequestTx) FindOneTx(tx *sql.Tx, args es.RecoveryRequest) (es.RecoveryRequest, error) {
	return selectRecoveryRequestTx(tx, args, expr.RecoveryRequestByGrantHash, expr.RecoveryRequestByUser)
}

// LockOneTx locks the request that [RecoveryRequestTx.FindOneTx] would return and returns it. It waits for the row
// lock.
//
// It returns [es.ErrNoArguments] if neither GrantHash nor UserID is set and [es.ErrNotFound] if there is no such
// request.
func (s *RecoveryRequestTx) LockOneTx(tx *sql.Tx, args es.RecoveryRequest) (es.RecoveryRequest, error) {
	return selectRecoveryRequestTx(tx, args, expr.RecoveryRequestByGrantHashForUpdate, expr.RecoveryRequestByUserForUpdate)
}

// selectRecoveryRequestTx runs byGrantHash or byUser, whichever the first set field of args selects, and scans the
// request.
func selectRecoveryRequestTx(tx *sql.Tx, args es.RecoveryRequest, byGrantHash, byUser string) (es.RecoveryRequest, error) {
	var row *sql.Row
	switch {
	case len(args.GrantHash) != 0:
		row = tx.QueryRow(byGrantHash, args.GrantHash)
	case args.UserID != 0:
		row = tx.QueryRow(byUser, args.UserID, es.RecoveryRequestClosed)
	default:
		return es.RecoveryRequest{}, es.ErrNoArguments
	}

	request, err := scanRecoveryRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return es.RecoveryRequest{}, es.ErrNotFound
	} else if err != nil {
		return es.RecoveryRequest{}, err
	}

	return request, nil
}

// CreateOneTx stores the request at the time of the clock, with ReadyAt as the end of its delay, and returns it with
// its ID set.
//
// It returns [es.ErrDuplicate] if the request already exists and [es.ErrNoCreatedRows] if the database adds no row.
func (s *RecoveryRequestTx) CreateOneTx(tx *sql.Tx, item es.RecoveryRequest) (es.RecoveryRequest, error) {
	item.CreatedAt = s.SystemClock.Now()

	result, err := tx.Exec(expr.CreateRecoveryRequest,
		item.RecoveryRequestXID,
		item.Flags,
		item.UserID,
		item.CancelHash,
		item.ReadyAt,
		item.CreatedAt,
	)
	if IsDuplicate(err) {
		return item, es.ErrDuplicate
	} else if err != nil {
		return item, fmt.Errorf("create a recovery request: %w", err)
	}

	item.ID = MustLastID[uint64](result)

	if item.ID == 0 {
		return item, es.ErrNoCreatedRows
	}

	return item, nil
}

// UpdateOneTx changes the one open request that the argument names, as the option of the call describes. The options
// are [es.CancelRecoveryRequest], [es.ApproveRecoveryRequest], [es.IssueRecoveryGrant] and [es.UseUpRecoveryGrant].
//
// It returns [es.ErrNoArguments] if op has none of them or the item lacks the fields that the option needs, and
// [es.ErrNoUpdatedRows] if no request matches.
func (s *RecoveryRequestTx) UpdateOneTx(tx *sql.Tx, item es.RecoveryRequest, op es.Op) error {
	query, args, ok := recoveryRequestUpdate(item, op, s.SystemClock.Now())
	if !ok {
		return es.ErrNoArguments
	}

	return checkUpdated(tx.Exec(query, args...))
}

// ReplaceFlagOneTx adds the newest bits to every open request of the UserID of args. It ignores the oldest bits and the
// ID of args, because a request only ever gains the bits that close it.
//
// It returns [es.ErrNoArguments] if args has no UserID and [es.ErrNoUpdatedRows] if the user has no open request.
func (s *RecoveryRequestTx) ReplaceFlagOneTx(tx *sql.Tx, _, newest es.RecoveryRequestFlag, args es.RecoveryRequest) error {
	if args.UserID == 0 {
		return es.ErrNoArguments
	}

	return checkUpdated(tx.Exec(expr.CancelRecoveryRequestsByUser, newest, args.UserID, es.RecoveryRequestClosed))
}
