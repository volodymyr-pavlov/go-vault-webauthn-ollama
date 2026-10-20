package es

import "time"

// User is an account.
//
// A [Reader] identifies a user by ID, UserXID, Handle or Email, in that order. A [Writer] update identifies a user by
// ID and writes the fields that are set. A [Tx] locks a user by ID, so that two logins cannot race on a passkey
// counter.
type User struct {
	// ID is the internal key of the row. It never leaves the service.
	ID uint64

	// UserXID is the external identifier of the user. The API and the logs carry it. It is a time-ordered number from
	// the snowflake of users.
	UserXID uint64

	// Flags holds the state of the account. See [UserFlag].
	Flags UserFlag

	// Email is the address that the user registered with, in lower case. The user logs in with it. It is not the
	// WebAuthn user handle.
	Email string

	// Handle is the WebAuthn user handle. It is 64 random bytes chosen at registration and never shown to anyone. It is
	// random, not the UserXID, so that an authenticator holds nothing that orders users in time.
	Handle []byte

	// PasswordHash is the Argon2id hash of the password, in the PHC string format.
	PasswordHash string

	// TOTPCiphertext is the TOTP secret, encrypted by Vault Transit with the UserXID as the derivation context. It is
	// empty if no secret is enrolled. The plaintext never reaches a store.
	TOTPCiphertext string

	// TOTPLastStep is the time step of the last accepted code. A code of the same step or of an earlier step is
	// refused.
	TOTPLastStep uint64

	// TOTPFailures counts the wrong codes since the last accepted code. The throttle and the risk signals use it.
	TOTPFailures uint16

	// CreatedAt is the time when the account was created.
	CreatedAt time.Time
}

// CanAuthenticate reports whether the account may authenticate. It must be verified and not disabled.
func (u User) CanAuthenticate() bool {
	return u.Flags&UserFlagVerified != 0 && u.Flags&UserFlagDisabled == 0
}

// HasTOTP reports whether the user has a confirmed TOTP secret.
func (u User) HasTOTP() bool {
	return u.TOTPCiphertext != "" && u.Flags&UserFlagTOTPConfirmed != 0
}
