package api

import (
	"errors"
	"fmt"
	"time"

	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/metrics"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &ListSessionsHandler{}
var _ web.Handler = &RemoveSessionHandler{}

// DeviceResult describes one logged-in device of the account.
type DeviceResult struct {
	SessionXID uint64    `json:"session_xid,string"`
	Country    string    `json:"country,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`

	// Current is true for the session that made the request.
	Current bool `json:"current"`
}

// ListSessionsHandlerResult is the response of GET /sessions.
type ListSessionsHandlerResult struct {
	Sessions []DeviceResult `json:"sessions"`
}

// ListSessionsHandler handles GET /sessions. It lists the logged-in sessions of the account, newest first, so that the
// user can see where the account is in use and end a session that is not theirs.
type ListSessionsHandler struct {
	SessionBatchReader es.BatchReader[es.Session]
	SystemClock        clock.Clock

	// IdleTimeout is the idle limit of a session. A session over the limit is not in the list.
	IdleTimeout time.Duration
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrNoAccount] if the session is bound to no account.
func (h *ListSessionsHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	user, err := User(ctx)
	if err != nil {
		return ErrNoAccount
	}

	current, err := Session(ctx)
	if err != nil {
		return err
	}

	sessions, err := h.SessionBatchReader.ReadAll(ctx, es.Session{
		UserID: user.ID,
	}, es.PageNumberPagination{
		PageSize: 100,
	}, 0)
	if err != nil {
		return fmt.Errorf("read the sessions: %w", err)
	}

	now := h.SystemClock.Now()
	result := ListSessionsHandlerResult{
		Sessions: []DeviceResult{},
	}
	for _, session := range sessions {
		if session.Flags&es.SessionFlagAuthorized == 0 || !session.Active(now, h.IdleTimeout) {
			continue
		}

		result.Sessions = append(result.Sessions, DeviceResult{
			SessionXID: session.SessionXID,
			Country:    session.Country,
			CreatedAt:  session.CreatedAt.UTC(),
			LastSeenAt: session.LastSeenAt.UTC(),
			Current:    session.ID == current.ID,
		})
	}

	return web.Write(ctx, fasthttp.StatusOK, result)
}

// RemoveSessionHandler handles DELETE /sessions/{session_xid}. It ends another session of the account, for example one
// on a lost device. The session middleware refuses the ended session from its next request.
type RemoveSessionHandler struct {
	SessionReader      es.Reader[es.Session]
	SessionGroupWriter es.Writer[es.SessionGroup]
	Metrics            *metrics.Metrics
}

// ServeHTTP implements [web.Handler]. It responds with status 204.
//
// It returns [ErrNoParamSessionXID] if the path has no session identifier and [ErrNoAccount] if the session is bound to
// no account. It returns [ErrNotFoundDevice] if the account has no such session.
func (h *RemoveSessionHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	sessionXID := web.ParamUint[uint64](ctx, "session_xid")
	if sessionXID == 0 {
		return ErrNoParamSessionXID
	}

	user, err := User(ctx)
	if err != nil {
		return ErrNoAccount
	}

	target, err := h.SessionReader.ReadOne(ctx, es.Session{
		SessionXID: sessionXID,
	}, 0)
	if errors.Is(err, es.ErrNotFound) || (err == nil && target.UserID != user.ID) {
		return ErrNotFoundDevice
	} else if err != nil {
		return fmt.Errorf("read the session: %w", err)
	}

	_, err = h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID: target.ID,
		},
	}, es.RevokeSession)
	if err != nil {
		return fmt.Errorf("revoke the session: %w", err)
	}

	SetEvent(ctx, es.EventSessionRevoked)

	h.Metrics.Session(metrics.SessionRevoked, 1)

	ctx.SetStatusCode(fasthttp.StatusNoContent)

	return nil
}
