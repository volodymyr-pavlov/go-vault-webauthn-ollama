package es

import "time"

// RecoveryCode is a single-use code that lets a user enroll a new factor after the user loses the others. The table
// holds the keyed hash of the code, never the code itself.
//
// A [Writer] update with [UseUpRecoveryCode] identifies a code by UserID and MAC. A [Replacer] with [AllOfUser] reaches
// every code of a UserID. A [BatchWriter] creates a set of codes.
type RecoveryCode struct {
	// ID is the internal key of the row.
	ID uint64

	// RecoveryCodeXID is the external identifier of the code, from the snowflake of recovery codes.
	RecoveryCodeXID uint64

	// Flags holds the state of the code. See [RecoveryCodeFlag].
	Flags RecoveryCodeFlag

	// UserID is the ID of the user that owns the code.
	UserID uint64

	// MAC is the keyed hash of the code, as Vault returns it.
	MAC string

	// CreatedAt is the time when the code was stored.
	CreatedAt time.Time
}
