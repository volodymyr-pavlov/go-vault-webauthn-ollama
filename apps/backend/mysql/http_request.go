package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql/expr"
)

var _ es.Writer[es.HTTPRequest] = &HTTPRequestWriter{}
var _ es.BatchReader[es.HTTPRequest] = &HTTPRequestBatchReader{}

// HTTPRequestWriter implements [es.Writer] for the log of the requests that the API received. It creates rows, and with
// [es.PurgeHTTPRequests] it deletes the old ones.
type HTTPRequestWriter struct {
	Database    *sql.DB
	SystemClock clock.Clock
}

// WriteOne saves the request in item and returns it with its ID and, if it was zero, its time set. It cuts the text
// fields to the width of their columns.
//
// With [es.PurgeHTTPRequests] it deletes the rows that are older than item.CreatedAt and returns the number of deleted
// rows in ID.
//
// It returns [es.ErrNoMethod] for an update and [es.ErrNoArguments] if op is not a create or a purge, or if a purge has
// no time.
func (s *HTTPRequestWriter) WriteOne(ctx context.Context, item es.HTTPRequest, op es.Op) (es.HTTPRequest, error) {
	if op&es.PurgeHTTPRequests != 0 {
		deleted, err := s.purge(ctx, item.CreatedAt)
		item.ID = deleted

		return item, err
	}

	switch {
	case es.IsUpdate(op):
		return item, es.ErrNoMethod
	case !es.IsCreate(op):
		return item, es.ErrNoArguments
	}

	if item.CreatedAt.IsZero() {
		item.CreatedAt = s.SystemClock.Now()
	}

	ip := ipBytes(item.IP)

	result, err := s.Database.ExecContext(ctx, expr.CreateHTTPRequest,
		item.ResourceCode,
		cutText(item.Method, 8),
		item.StatusCode,
		item.ErrorCode,
		item.DurationMs,
		item.SessionXID,
		item.UserXID,
		ip,
		cutText(item.Path, 255),
		cutText(item.RequestID, 64),
		cutText(item.Host, 255),
		cutText(item.UserAgent, 255),
		cutText(item.BuildVersion, 64),
		cutText(string(item.Event), 64),
		cutText(item.EventAttrs, 255),
		cutText(item.ErrorText, 255),
		item.CreatedAt.UTC(),
	)
	if err != nil {
		return item, fmt.Errorf("create a request log row: %w", err)
	}

	item.ID = MustLastID[uint64](result)

	return item, nil
}

// purge deletes the rows that are older than cutoff and returns how many it deleted.
func (s *HTTPRequestWriter) purge(ctx context.Context, cutoff time.Time) (uint64, error) {
	if cutoff.IsZero() {
		return 0, es.ErrNoArguments
	}

	result, err := s.Database.ExecContext(ctx, expr.DeleteExpiredHTTPRequests, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("delete the old request log rows: %w", err)
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count the deleted request log rows: %w", err)
	}

	if deleted < 0 {
		return 0, fmt.Errorf("count the deleted request log rows: negative count %d", deleted)
	}

	return uint64(deleted), nil
}

// cutText returns text cut to at most limit bytes, at the start of a character. It never changes the part before the
// cut, so a stray invalid byte early in text does not shorten the result.
func cutText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}

	for limit > 0 && !utf8.RuneStart(text[limit]) {
		limit--
	}

	return text[:limit]
}

// HTTPRequestBatchReader implements [es.BatchReader] for the request log. It lists the rows of one user, newest first.
type HTTPRequestBatchReader struct {
	Database *sql.DB
}

// ReadAll returns one page of the rows that carry the UserXID of the argument.
//
// It returns [es.ErrNoArguments] if the argument has no UserXID.
func (s *HTTPRequestBatchReader) ReadAll(ctx context.Context, args es.HTTPRequest, paging es.Paginator, _ es.Op) ([]es.HTTPRequest, error) {
	if args.UserXID == 0 {
		return nil, es.ErrNoArguments
	}

	rows, err := s.Database.QueryContext(ctx, expr.HTTPRequestsByUser, args.UserXID, paging.Limit(), paging.Offset())
	if err != nil {
		return nil, fmt.Errorf("read the request log: %w", err)
	}
	defer rows.Close()

	var items []es.HTTPRequest
	for rows.Next() {
		var item es.HTTPRequest
		var ip []byte
		var resource uint16

		err := rows.Scan(&item.ID, &resource, &item.Method, &item.StatusCode, &item.ErrorCode, &item.DurationMs,
			&item.SessionXID, &item.UserXID, &ip, &item.Path, &item.RequestID, &item.Host, &item.UserAgent,
			&item.BuildVersion, &item.Event, &item.EventAttrs, &item.ErrorText, &item.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan a request log row: %w", err)
		}

		item.ResourceCode = es.ResourceCode(resource)

		if addr, ok := netip.AddrFromSlice(ip); ok {
			item.IP = addr
		}

		items = append(items, item)
	}

	return items, rows.Err()
}
