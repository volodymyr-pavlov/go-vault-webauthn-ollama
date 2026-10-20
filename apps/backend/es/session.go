package es

import (
	"net/netip"
	"time"
)

// Session is the sign-in of one device. The service opens it before it checks any factor. It collects one
// [SessionFlag] bit for each step that passes and holds the state of the step in progress. The sessions of a user are
// also the login history that the risk engine reads.
//
// A [Reader] identifies a session by ID or SessionXID, in that order. A [Writer] update identifies a session by ID and writes the fields that are set. A [BatchReader] lists the
// sessions of a UserID, or of an IP if the argument has no user, newest first. With [LoginsSince] it lists only the
// sessions created at or after CreatedAt. A [Replacer] swaps flags by ID, or with [AllOfUser] for every session of a
// UserID.
type Session struct {
	// ID is the internal key of the row.
	ID uint64

	// SessionXID is the external identifier of the session, from the snowflake of sessions.
	SessionXID uint64

	// Flags holds the state of the session. See [SessionFlag].
	Flags SessionFlag

	// UserID is the ID of the user of the session. It is zero until a step binds the session to a user: a
	// verified registration, an accepted password, an accepted passkey or an accepted recovery code.
	UserID uint64

	// AuthTime is the time when the user last passed a factor in this session. It is zero until a factor passes. See
	// [Session.Fresh].
	AuthTime time.Time

	// RiskScore is the score of the last login, from 0 to 100.
	RiskScore uint8

	// Failures counts the factors that failed in this session. The throttle and the risk signals use it.
	Failures uint16

	// DeviceIDHash is the keyed hash of the device identifier that the client sent when it opened the session.
	DeviceIDHash []byte

	// DeviceKey is the Ed25519 public key of the device. It has 32 bytes. KeyID is the SHA-256 hash of it. The device
	// signs every request with its private key. The request names the key by its KeyID and the session by its
	// SessionXID. The client sends the key when it opens the session. The session has no token.
	DeviceKey []byte
	KeyID     []byte

	// IP is the address that the session was opened from, as seen behind the trusted proxy. Country, Latitude and
	// Longitude are the place of the address in the geo-IP table.
	IP        netip.Addr
	Country   string
	Latitude  float64
	Longitude float64

	// VerifyHash is the SHA-256 hash of the verification token of a registration in progress. VerifyExpiresAt is the
	// time when the verification token stops being valid. The service sends the token to the user by email.
	// Accepting it clears both fields.
	VerifyHash      []byte
	VerifyExpiresAt time.Time

	// Challenge is the encoded session data of the WebAuthn ceremony in progress. ChallengeExpiresAt is the time when
	// the challenge stops being valid. [SessionFlagChallengeRegistration] or [SessionFlagChallengeLogin] says which
	// ceremony it is. Finishing the ceremony clears both fields in the same statement that checks that a challenge
	// exists, so a challenge is accepted once.
	Challenge          []byte
	ChallengeExpiresAt time.Time

	// CreatedAt is the time when the session opened. LastSeenAt is the time of its last request, rounded to a few minutes.
	// ExpiresAt is the end of the session, whatever its activity.
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// Active reports whether the session may be used at now. It is not revoked, it has not expired, and its last request was
// not longer than idle ago. A zero idle turns the idle limit off.
func (s Session) Active(now time.Time, idle time.Duration) bool {
	if s.Flags&SessionFlagRevoked != 0 || !now.Before(s.ExpiresAt) {
		return false
	}

	return idle == 0 || s.LastSeenAt.IsZero() || now.Sub(s.LastSeenAt) <= idle
}

// Fresh reports whether the last factor passed no more than window before now.
func (s Session) Fresh(now time.Time, window time.Duration) bool {
	return !s.AuthTime.IsZero() && now.Sub(s.AuthTime) <= window
}
