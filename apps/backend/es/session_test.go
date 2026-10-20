package es

import (
	"testing"
	"time"
)

// TestSessionActive proves that a session stops being active when it is revoked, expired or idle for too long, and that
// a zero idle limit turns the idle rule off.
func TestSessionActive(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	live := Session{
		Flags:      SessionFlagStarted,
		LastSeenAt: now.Add(-time.Hour),
		ExpiresAt:  now.Add(time.Hour),
	}

	revoked := live
	revoked.Flags |= SessionFlagRevoked

	expired := live
	expired.ExpiresAt = now

	cases := []struct {
		name    string
		session Session
		idle    time.Duration
		want    bool
	}{
		{"a live session", live, 24 * time.Hour, true},
		{"a revoked session", revoked, 24 * time.Hour, false},
		{"an expired session", expired, 24 * time.Hour, false},
		{"an idle session", live, 30 * time.Minute, false},
		{"an idle session with the idle rule off", live, 0, true},
		{"a session never seen", Session{
			Flags:     SessionFlagStarted,
			ExpiresAt: now.Add(time.Hour),
		}, time.Minute, true},
	}
	for _, c := range cases {
		if got := c.session.Active(now, c.idle); got != c.want {
			t.Errorf("%s: Active = %v, want %v", c.name, got, c.want)
		}
	}
}
