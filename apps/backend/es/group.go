package es

// SessionGroup is the unit of work that is anchored at one session. A [Writer] changes the session, and the user, the
// passkey and the recovery code that go with it, all in one transaction.
//
// The [Op] of the write sets exactly one of the intents in [SessionIntents]. The intent says which records of the
// group the writer changes and in which order. A record that an intent does not name stays as it is.
type SessionGroup struct {
	// Session names the session by ID and holds the fields to write. Each intent documents which of them it reads.
	Session Session

	// User is the user of the intent. [OpenRegistry] creates it. [VerifyRegistry] and the login intents name it by
	// ID. If the ID is zero, an intent that updates the user leaves it as it is.
	User User

	// Passkey names a passkey by ID and holds the flag bits and the counter to write. If the ID is zero, an intent
	// that updates the passkey leaves it as it is.
	Passkey Passkey

	// RecoveryCode holds the MAC of the recovery code that [ApproveRecoveryCode] uses up.
	RecoveryCode RecoveryCode
}

// UserGroup is the unit of work that is anchored at one user. A [Writer] changes the factors of the user in
// one transaction. Each intent locks the user first.
//
// The [Op] of the write sets exactly one of the intents in [UserIntents].
type UserGroup struct {
	// User names the owner by ID. For [ConfirmTOTP] it also holds the TOTPCiphertext and the TOTPLastStep of the
	// accepted code.
	User User

	// Passkey names the passkey that [RemovePasskey] removes, by ID.
	Passkey Passkey

	// Session names the session whose confirmation challenge [RemovePasskey] uses up with [ConsumeChallenge], by ID. If
	// the ID is zero, the write uses up no challenge.
	Session Session

	// Codes is the new set of recovery codes of [ReissueRecoveryCodes]. The writer returns the stored codes.
	Codes []RecoveryCode
}

// RecoveryGroup is the unit of work that is anchored at one recovery request. A [Writer] changes the request, and the
// sessions that go with it, and in one transaction.
//
// The [Op] of the write sets exactly one of the intents in [RecoveryIntents].
type RecoveryGroup struct {
	// Request is the new request of [OpenRecoveryRequest], or the fields that name and change the stored request for
	// the other intents. [RedeemRecoveryGrant] reads its GrantHash.
	Request RecoveryRequest

	// Session names the current session of [RedeemRecoveryGrant] by ID. Flags holds the bit of the step and UserID the
	// user.
	Session Session
}
