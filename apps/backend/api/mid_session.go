package api

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

// SessionMiddleware authenticates a request by its signature. The request names the key of the device in its
// Signature-Input field. The middleware loads the newest session of that key and verifies the signature with the key of
// the session. It then checks the permission of the endpoint and stores the session and its user in the request
// context. The request carries no token: the key is the identity.
type SessionMiddleware struct {
	SessionReader       es.Reader[es.Session]
	UserReader          es.Reader[es.User]
	RequestVerifier     es.Reader[es.SignedRequest]
	PermissionValidator *PermissionValidator

	// SessionWriter records the time of the last request of a session. SystemClock supplies the time.
	SessionWriter es.Writer[es.Session]
	SystemClock   clock.Clock
}

// Middleware returns the middleware for the endpoint with code. The permission it checks is the entry of code in
// [CodeToPermission].
//
// The middleware returns [ErrNoHeaderRequestSignature] or [ErrInvalidRequestSignature] if the signature fields are
// missing or wrong, and [ErrNotFoundSession] if no session has the key. It returns the errors of
// [PermissionValidator.ValidateSession] if the session lacks the permission.
func (m *SessionMiddleware) Middleware(code es.ResourceCode) web.Middleware {
	perm := CodeToPermission[code]
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(ctx *fasthttp.RequestCtx) error {
			keyID, sessionXID, err := requestSessionRef(ctx)
			if err != nil {
				return err
			}

			session, err := m.SessionReader.ReadOne(ctx, es.Session{
				SessionXID: sessionXID,
			}, 0)
			if errors.Is(err, es.ErrNotFound) {
				return ErrNotFoundSession
			} else if err != nil {
				return fmt.Errorf("read the session: %w", err)
			}

			// The tag names the session, and the key ID must belong to it. Otherwise a device could use the session of
			// another device by naming it.
			if subtle.ConstantTimeCompare(keyID, session.KeyID) != 1 {
				return ErrNotFoundSession
			}

			if err := verifySignature(ctx, m.RequestVerifier, session.DeviceKey); err != nil {
				return err
			}

			if err := m.PermissionValidator.ValidateSession(session, perm); err != nil {
				return err
			}

			// The last request time is recorded at most once in [SeenInterval], so a busy session does not write on every
			// request.
			now := m.SystemClock.Now()
			if now.Sub(session.LastSeenAt) > SeenInterval {
				_, err := m.SessionWriter.WriteOne(ctx, es.Session{
					ID:         session.ID,
					LastSeenAt: now,
				}, es.WriteUpdate)
				if err != nil {
					return fmt.Errorf("record the last request: %w", err)
				}

				session.LastSeenAt = now
			}

			SetSession(ctx, session)

			if session.UserID != 0 {
				user, err := m.UserReader.ReadOne(ctx, es.User{
					ID: session.UserID,
				}, 0)
				if err != nil {
					return fmt.Errorf("read the user: %w", err)
				}

				SetUser(ctx, user)
			}

			return next(ctx)
		}
	}
}
