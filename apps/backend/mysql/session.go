package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql/expr"
)

var _ es.Reader[es.Session] = &SessionReader{}
var _ es.Writer[es.Session] = &SessionWriter{}
var _ es.BatchReader[es.Session] = &SessionBatchReader{}
var _ es.Replacer[es.Session, es.SessionFlag] = &SessionReplacer{}
var _ es.Tx[es.Session, es.SessionFlag] = &SessionTx{}
var _ es.UpdateBuilder[es.Session] = &UpdateSessionBuilder{}

// scanSession reads the columns of the select statements of sessions from row. It returns the error of the scan as it
// is, so the caller can tell a missing row.
func scanSession(row rowScanner) (es.Session, error) {
	var session es.Session
	var authTime, verifyExpires, challengeExpires sql.NullTime

	err := row.Scan(
		&session.ID,
		&session.SessionXID,
		&session.Flags,
		&session.UserID,
		&authTime,
		&session.RiskScore,
		&session.Failures,
		&session.DeviceIDHash,
		&session.DeviceKey,
		&session.KeyID,
		ipScan{&session.IP},
		&session.Country,
		&session.Latitude,
		&session.Longitude,
		&session.VerifyHash,
		&verifyExpires,
		&session.Challenge,
		&challengeExpires,
		&session.CreatedAt,
		&session.LastSeenAt,
		&session.ExpiresAt,
	)
	if err != nil {
		return es.Session{}, err
	}

	session.DeviceIDHash = FromDefaultBlob(session.DeviceIDHash)
	session.DeviceKey = FromDefaultBlob(session.DeviceKey)
	session.KeyID = FromDefaultBlob(session.KeyID)
	session.VerifyHash = FromDefaultBlob(session.VerifyHash)
	session.Challenge = FromDefaultBlob(session.Challenge)
	session.AuthTime = authTime.Time
	session.VerifyExpiresAt = verifyExpires.Time
	session.ChallengeExpiresAt = challengeExpires.Time

	return session, nil
}

// SessionReader implements [es.Reader] for sessions.
type SessionReader struct {
	Database *sql.DB
}

// ReadOne returns the session that the first set field of the argument identifies. The fields are ID and SessionXID, in
// that order.
//
// It returns [es.ErrNoArguments] if none of them is set and [es.ErrNotFound] if there is no such session.
func (s *SessionReader) ReadOne(ctx context.Context, args es.Session, _ es.Op) (es.Session, error) {
	var row *sql.Row
	switch {
	case args.ID != 0:
		row = s.Database.QueryRowContext(ctx, expr.SessionByID, args.ID)
	case args.SessionXID != 0:
		row = s.Database.QueryRowContext(ctx, expr.SessionBySessionXID, args.SessionXID)
	default:
		return es.Session{}, es.ErrNoArguments
	}

	session, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return es.Session{}, es.ErrNotFound
	} else if err != nil {
		return es.Session{}, err
	}

	return session, nil
}

// SessionWriter implements [es.Writer] for sessions.
type SessionWriter struct {
	Database             *sql.DB
	SystemClock          clock.Clock
	UpdateSessionBuilder es.UpdateBuilder[es.Session]
}

// WriteOne creates or updates a session, as [es.Writer] describes. An update identifies the session by ID. With
// [es.PurgeExpiredSessions] it deletes the sessions that expired before ExpiresAt and returns the number of deleted
// sessions in ID.
//
// It returns [es.ErrNoUpdatedRows] if an update matches no session.
func (s *SessionWriter) WriteOne(ctx context.Context, item es.Session, op es.Op) (es.Session, error) {
	switch {
	case op&es.PurgeExpiredSessions != 0:
		deleted, err := s.purge(ctx, item.ExpiresAt)
		item.ID = deleted

		return item, err
	case es.IsCreate(op):
		return s.createOne(ctx, item)
	case es.IsUpdate(op):
		return item, s.updateOne(ctx, item, op)
	}

	return item, es.ErrNoArguments
}

// purge deletes the sessions that expired before cutoff and returns how many it deleted.
func (s *SessionWriter) purge(ctx context.Context, cutoff time.Time) (uint64, error) {
	if cutoff.IsZero() {
		return 0, es.ErrNoArguments
	}

	result, err := s.Database.ExecContext(ctx, expr.DeleteExpiredSessions, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete the expired sessions: %w", err)
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count the deleted sessions: %w", err)
	}

	if deleted < 0 {
		return 0, fmt.Errorf("count the deleted sessions: negative count %d", deleted)
	}

	return uint64(deleted), nil
}

func (s *SessionWriter) createOne(ctx context.Context, session es.Session) (es.Session, error) {
	session.CreatedAt = s.SystemClock.Now()

	ip := ipBytes(session.IP)

	result, err := s.Database.ExecContext(ctx, expr.CreateSession,
		session.SessionXID,
		session.Flags,
		NewNullInt(session.UserID),
		sql.NullTime{
			Time:  session.AuthTime,
			Valid: !session.AuthTime.IsZero(),
		},
		session.RiskScore,
		session.Failures,
		NewDefaultBlob(session.DeviceIDHash),
		NewDefaultBlob(session.DeviceKey),
		NewDefaultBlob(session.KeyID),
		ip,
		session.Country,
		session.Latitude,
		session.Longitude,
		NewDefaultBlob(session.VerifyHash),
		sql.NullTime{
			Time:  session.VerifyExpiresAt,
			Valid: !session.VerifyExpiresAt.IsZero(),
		},
		NewDefaultBlob(session.Challenge),
		sql.NullTime{
			Time:  session.ChallengeExpiresAt,
			Valid: !session.ChallengeExpiresAt.IsZero(),
		},
		session.CreatedAt,
		session.CreatedAt,
		session.ExpiresAt,
	)
	if IsDuplicate(err) {
		return session, es.ErrDuplicate
	} else if err != nil {
		return session, fmt.Errorf("create a session: %w", err)
	}

	session.ID = MustLastID[uint64](result)

	if session.ID == 0 {
		return session, es.ErrNoCreatedRows
	}

	return session, nil
}

func (s *SessionWriter) updateOne(ctx context.Context, session es.Session, op es.Op) error {
	result, err := s.UpdateSessionBuilder.UpdateOneBuilder(session, op).RunWith(s.Database).ExecContext(ctx)
	return checkUpdated(result, err)
}

// SessionBatchReader implements [es.BatchReader] for sessions. It lists the sessions of a user, or of an address if
// the argument has no user, newest first. With [es.LoginsSince] it lists only the sessions created at or after the
// CreatedAt of the argument.
type SessionBatchReader struct {
	Database *sql.DB
}

// ReadAll returns one page of sessions.
//
// It returns [es.ErrNoArguments] if the argument has neither a UserID nor an IP.
func (s *SessionBatchReader) ReadAll(ctx context.Context, args es.Session, paging es.Paginator, op es.Op) ([]es.Session, error) {
	ip := ipBytes(args.IP)

	var rows *sql.Rows
	var err error
	switch {
	case args.UserID != 0 && op&es.LoginsSince != 0:
		rows, err = s.Database.QueryContext(ctx, expr.SessionsByUserSince, args.UserID, args.CreatedAt, paging.Limit(), paging.Offset())
	case args.UserID != 0:
		rows, err = s.Database.QueryContext(ctx, expr.SessionsByUser, args.UserID, paging.Limit(), paging.Offset())
	case ip != nil && op&es.LoginsSince != 0:
		rows, err = s.Database.QueryContext(ctx, expr.SessionsByIPSince, ip, args.CreatedAt, paging.Limit(), paging.Offset())
	case ip != nil:
		rows, err = s.Database.QueryContext(ctx, expr.SessionsByIP, ip, paging.Limit(), paging.Offset())
	default:
		return nil, es.ErrNoArguments
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []es.Session
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("scan a session: %w", err)
		}

		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// SessionReplacer implements [es.Replacer] for sessions. It swaps the flags of the session with the ID of the item.
// With [es.AllOfUser] it swaps the flags of every session of the UserID of the item.
type SessionReplacer struct {
	Database *sql.DB
}

// ReplaceOne clears the oldest bits and sets the newest bits.
//
// It returns [es.ErrNoArguments] if the item has no UserID with [es.AllOfUser] or no ID without it, and
// [es.ErrNoUpdatedRows] if no session matched.
func (s *SessionReplacer) ReplaceOne(ctx context.Context, oldest, newest es.SessionFlag, item es.Session, op es.Op) error {
	var result sql.Result
	var err error
	switch {
	case op&es.AllOfUser != 0 && item.UserID != 0:
		result, err = s.Database.ExecContext(ctx, expr.ReplaceSessionFlagsByUser, oldest, newest, item.UserID)
	case op&es.AllOfUser == 0 && item.ID != 0:
		result, err = s.Database.ExecContext(ctx, expr.ReplaceSessionFlags, oldest, newest, item.ID)
	default:
		return es.ErrNoArguments
	}

	return checkUpdated(result, err)
}

// SessionTx implements [es.Tx] for sessions. It identifies a session by ID or SessionXID, in that order.
type SessionTx struct {
	SystemClock          clock.Clock
	UpdateSessionBuilder es.UpdateBuilder[es.Session]
}

// FindOneTx returns the session that the first set field of the argument identifies, without locking it.
//
// It returns [es.ErrNoArguments] if neither ID nor SessionXID is set and [es.ErrNotFound] if there is no such session.
func (s *SessionTx) FindOneTx(tx *sql.Tx, args es.Session) (es.Session, error) {
	return selectSessionTx(tx, args, expr.SessionByID, expr.SessionBySessionXID)
}

// LockOneTx locks the session that the first set field of the argument identifies and returns it. It waits for the row
// lock.
//
// It returns [es.ErrNoArguments] if neither ID nor SessionXID is set and [es.ErrNotFound] if there is no such session.
func (s *SessionTx) LockOneTx(tx *sql.Tx, args es.Session) (es.Session, error) {
	return selectSessionTx(tx, args, expr.SessionByIDForUpdate, expr.SessionBySessionXIDForUpdate)
}

// selectSessionTx runs byID or byXID, whichever the first set field of args selects, and scans the session.
func selectSessionTx(tx *sql.Tx, args es.Session, byID, byXID string) (es.Session, error) {
	var row *sql.Row
	switch {
	case args.ID != 0:
		row = tx.QueryRow(byID, args.ID)
	case args.SessionXID != 0:
		row = tx.QueryRow(byXID, args.SessionXID)
	default:
		return es.Session{}, es.ErrNoArguments
	}

	session, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return es.Session{}, es.ErrNotFound
	} else if err != nil {
		return es.Session{}, err
	}

	return session, nil
}

// CreateOneTx opens the session at the time of the clock and returns it with its ID set.
//
// It returns [es.ErrDuplicate] if the SessionXID is taken and [es.ErrNoCreatedRows] if the database adds no row.
func (s *SessionTx) CreateOneTx(tx *sql.Tx, item es.Session) (es.Session, error) {
	item.CreatedAt = s.SystemClock.Now()

	ip := ipBytes(item.IP)

	result, err := tx.Exec(expr.CreateSession,
		item.SessionXID,
		item.Flags,
		NewNullInt(item.UserID),
		sql.NullTime{
			Time:  item.AuthTime,
			Valid: !item.AuthTime.IsZero(),
		},
		item.RiskScore,
		item.Failures,
		NewDefaultBlob(item.DeviceIDHash),
		NewDefaultBlob(item.DeviceKey),
		NewDefaultBlob(item.KeyID),
		ip,
		item.Country,
		item.Latitude,
		item.Longitude,
		NewDefaultBlob(item.VerifyHash),
		sql.NullTime{
			Time:  item.VerifyExpiresAt,
			Valid: !item.VerifyExpiresAt.IsZero(),
		},
		NewDefaultBlob(item.Challenge),
		sql.NullTime{
			Time:  item.ChallengeExpiresAt,
			Valid: !item.ChallengeExpiresAt.IsZero(),
		},
		item.CreatedAt,
		item.CreatedAt,
		item.ExpiresAt,
	)
	if IsDuplicate(err) {
		return item, es.ErrDuplicate
	} else if err != nil {
		return item, fmt.Errorf("create a session: %w", err)
	}

	item.ID = MustLastID[uint64](result)

	if item.ID == 0 {
		return item, es.ErrNoCreatedRows
	}

	return item, nil
}

// UpdateOneTx updates the session that the ID of the item names, as [UpdateSessionBuilder] describes.
//
// It returns [es.ErrNoUpdatedRows] if no session matches.
func (s *SessionTx) UpdateOneTx(tx *sql.Tx, item es.Session, op es.Op) error {
	result, err := s.UpdateSessionBuilder.UpdateOneBuilder(item, op).RunWith(tx).Exec()

	return checkUpdated(result, err)
}

// ReplaceFlagOneTx clears the oldest bits and sets the newest bits of the session with the ID of args. If the ID is
// zero, it does so for every session of the UserID of args.
//
// It returns [es.ErrNoArguments] if args has neither an ID nor a UserID, and [es.ErrNoUpdatedRows] if no session
// matched.
func (s *SessionTx) ReplaceFlagOneTx(tx *sql.Tx, oldest, newest es.SessionFlag, args es.Session) error {
	switch {
	case args.ID != 0:
		return checkUpdated(tx.Exec(expr.ReplaceSessionFlags, oldest, newest, args.ID))
	case args.UserID != 0:
		return checkUpdated(tx.Exec(expr.ReplaceSessionFlagsByUser, oldest, newest, args.UserID))
	}

	return es.ErrNoArguments
}

// UpdateSessionBuilder implements [es.UpdateBuilder] for sessions. The update writes only the fields that are set.
type UpdateSessionBuilder struct {
	QueryBuilder squirrel.StatementBuilderType
}

// UpdateOneBuilder returns the update of the session that the ID names. With [es.ConsumeChallenge] the update
// matches only a session that still holds a challenge.
func (b *UpdateSessionBuilder) UpdateOneBuilder(session es.Session, op es.Op) squirrel.UpdateBuilder {
	sb := b.QueryBuilder.Update("sessions")
	switch {
	case op&es.ClearFlag != 0:
		sb = sb.Set("flags", squirrel.Expr("flags & ~?", session.Flags))
	case op&es.AppendFlag != 0:
		sb = sb.Set("flags", squirrel.Expr("flags | ?", session.Flags))
	case op&es.RewriteFlag != 0:
		sb = sb.Set("flags", session.Flags)
	}

	if session.UserID != 0 {
		sb = sb.Set("user_id", session.UserID)
	}

	if !session.AuthTime.IsZero() {
		sb = sb.Set("auth_time", session.AuthTime)
	}

	if session.RiskScore != 0 || op&es.StoreRiskOutcome != 0 {
		sb = sb.Set("risk_score", session.RiskScore)
	}

	if session.Failures != 0 || op&es.StoreRiskOutcome != 0 {
		sb = sb.Set("failures", session.Failures)
	}

	if len(session.VerifyHash) != 0 || op&es.ClearVerifyToken != 0 {
		sb = sb.Set("verify_hash", NewDefaultBlob(session.VerifyHash))
		sb = sb.Set("verify_expires_at", sql.NullTime{
			Time:  session.VerifyExpiresAt,
			Valid: !session.VerifyExpiresAt.IsZero(),
		})
	}

	if len(session.Challenge) != 0 || op&es.ConsumeChallenge != 0 {
		sb = sb.Set("challenge", NewDefaultBlob(session.Challenge))
		sb = sb.Set("challenge_expires_at", sql.NullTime{
			Time:  session.ChallengeExpiresAt,
			Valid: !session.ChallengeExpiresAt.IsZero(),
		})
	}

	if !session.LastSeenAt.IsZero() {
		sb = sb.Set("last_seen_at", session.LastSeenAt)
	}

	if !session.ExpiresAt.IsZero() {
		sb = sb.Set("expires_at", session.ExpiresAt)
	}

	sb = sb.Where(squirrel.Eq{"id": session.ID})
	if op&es.ConsumeChallenge != 0 {
		sb = sb.Where("challenge <> 0x00")
	}

	return sb
}
