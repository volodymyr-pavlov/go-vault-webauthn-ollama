package api

import (
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// DefaultFreshWindow is the default time after a factor passes during which an action that needs fresh authentication
// may run.
const DefaultFreshWindow = 5 * time.Minute

// DefaultIdleTimeout is the default time a session may stay without a request.
const DefaultIdleTimeout = 7 * 24 * time.Hour

// SeenInterval is how often a session records that it is in use. A request records it only if the last record is older.
const SeenInterval = 5 * time.Minute

// PermissionValidator checks a session against the permission of an endpoint.
type PermissionValidator struct {
	// FreshWindow is how long after the last factor the session counts as fresh. Zero means [DefaultFreshWindow].
	FreshWindow time.Duration

	// IdleTimeout is how long a session may stay without a request before it ends. Zero turns the idle limit off.
	IdleTimeout time.Duration

	SystemClock clock.Clock
}

// ValidateSession checks session against perm.
//
// It returns [ErrUnauthorizedSession] if the session is revoked, expired or has no flags. It returns the same error if
// the session lacks a flag that perm requires, or has none of the flags that perm lists as alternatives. It also
// returns it if perm is strict and the session has a flag that perm does not require.
//
// It returns [ErrStaleAuthentication] if perm needs fresh authentication and the session is authorized, but its last
// factor passed longer ago than [PermissionValidator.FreshWindow]. A session that is only in an enrollment state has no
// factor yet, so this check does not apply to it.
func (v *PermissionValidator) ValidateSession(session es.Session, perm es.Permission) error {
	now := v.SystemClock.Now()
	if session.Flags == es.SessionFlagUnauthorized || !session.Active(now, v.IdleTimeout) {
		return ErrUnauthorizedSession
	}

	if perm.Rules&es.RuleStrict != 0 && session.Flags != perm.SessionFlag {
		return ErrUnauthorizedSession
	}

	if session.Flags&perm.SessionFlag != perm.SessionFlag {
		return ErrUnauthorizedSession
	}

	if perm.SessionAnyFlag != 0 && session.Flags&perm.SessionAnyFlag == 0 {
		return ErrUnauthorizedSession
	}

	window := v.FreshWindow
	if window == 0 {
		window = DefaultFreshWindow
	}

	if perm.Rules&es.RuleFresh != 0 && session.Flags&es.SessionFlagAuthorized != 0 && !session.Fresh(now, window) {
		return ErrStaleAuthentication
	}

	return nil
}
