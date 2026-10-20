package es

// Op is a set of option bits that a caller passes to a store method. The options select the action of
// [Writer.WriteOne], how an update writes the flag bits, which zero values an update writes, and which special search
// a store runs.
//
// A store reads only the bits that it knows. Zero selects the default behavior.
type Op uint64

// IsCreate reports whether op asks [Writer.WriteOne] to create a record. It is true if [WriteCreate] is set and
// [WriteUpdate] is not.
func IsCreate(op Op) bool {
	return op&(WriteCreate|WriteUpdate) == WriteCreate
}

// IsUpdate reports whether op asks [Writer.WriteOne] to update a record. It is true if [WriteUpdate] is set and
// [WriteCreate] is not.
func IsUpdate(op Op) bool {
	return op&(WriteCreate|WriteUpdate) == WriteUpdate
}

// The options below combine with | into the [Op] argument of a store call.
//
// [WriteCreate] and [WriteUpdate] select the action of [Writer.WriteOne]. The other options change how a call treats
// flags and zero values, or select a special search. With no flag option, an update leaves the flags as they are. An
// update skips zero values, except where an option makes it write them. This is how a pending step is cleared.
const (
	// WriteCreate makes [Writer.WriteOne] save the record as a new one.
	WriteCreate Op = 1 << iota

	// WriteUpdate makes [Writer.WriteOne] change the stored record that matches the identifying fields of the request.
	WriteUpdate

	// AppendFlag adds the given flag bits to the stored ones on an update.
	AppendFlag

	// ClearFlag removes the given flag bits from the stored bits on an update. It takes priority over [AppendFlag].
	ClearFlag

	// RewriteFlag overwrites the stored flag bits with the given bits on an update.
	RewriteFlag

	// ResetTOTP makes an update of a user write the TOTP secret, the last step and the failure count even if they are
	// zero or empty. This removes the secret and resets the failures.
	ResetTOTP

	// AdvanceTOTPStep makes an update of a user store the last TOTP step and reset the failure count, but only if the
	// stored step is lower than the given step. It leaves the other fields alone. The update matches no row for a
	// step that was used already, so two requests cannot both spend the same code.
	AdvanceTOTPStep

	// CountTOTPFailure makes an update of a user add one to the stored failure count in the database. It leaves the
	// other fields alone.
	CountTOTPFailure

	// ClearVerifyToken makes an update of a session write the verification token hash and its expiry even if they are
	// empty. This clears an accepted verification token.
	ClearVerifyToken

	// ConsumeChallenge makes an update of a session write the challenge and its expiry even if they are empty. The
	// update matches only a session that still holds a challenge, so a challenge is consumed once. The caller clears
	// the challenge bits of the flags in the same update.
	ConsumeChallenge

	// StoreRiskOutcome makes an update of a session write the risk score and the failure count even if they are zero.
	StoreRiskOutcome

	// LoginsSince makes a search of sessions return only the sessions that were created at or after the CreatedAt of
	// the argument.
	LoginsSince

	// HoldingTOTPSecret makes a search of users return only the users that have a TOTP secret. The rewrap of the
	// secrets after a key rotation uses it.
	HoldingTOTPSecret

	// AllOfUser makes a replace match every session or recovery code of the UserID of the argument, not one record.
	// It revokes all sessions of a user at once, or retires all recovery codes of a user when a new set replaces them.
	AllOfUser

	// UseUpRecoveryCode makes an update of a recovery code match only an unused code with the UserID and the MAC of
	// the argument. The update sets the given flag bits in the same statement, so a second caller with the same code
	// changes nothing and a code works once.
	UseUpRecoveryCode

	// CancelRecoveryRequest makes an update of a recovery request add the given flag bits only while the CancelHash of the
	// argument matches an open request. The cancel token works once. It is also the intent of a [RecoveryGroup] write
	// that cancels a request .
	CancelRecoveryRequest

	// ApproveRecoveryRequest makes an update of a recovery request add the given flag bits only to the open request with
	// the RecoveryRequestXID of the argument, and only once its delay has ended.
	ApproveRecoveryRequest

	// IssueRecoveryGrant makes an update of a recovery request write the GrantHash and GrantExpiresAt of the argument
	// only while the request is approved and open. It is also the intent of a [RecoveryGroup] write that issues the
	// grant .
	IssueRecoveryGrant

	// UseUpRecoveryGrant makes an update of a recovery request add the given flag bits only to the approved, open
	// request with the GrantHash of the argument, and only before the grant expires. The update is one step, so a grant
	// works exactly once.
	UseUpRecoveryGrant

	// PurgeExpiredSessions makes a write of a session delete every session that expired before the ExpiresAt of the
	// argument. It is neither a create nor an update. The returned item carries the number of deleted sessions in its ID.
	PurgeExpiredSessions

	// PurgeHTTPRequests makes a write of an [HTTPRequest] delete every row of the request log that is older than the
	// CreatedAt of the argument. It is neither a create nor an update. The returned item carries the number of deleted
	// rows in its ID.
	PurgeHTTPRequests

	// AddAccounts makes a write of an [AccountGroup] store new accounts in the authenticator, unless the user
	// would have more than [MaxAccounts].
	AddAccounts

	// RemoveAccount makes a write of an [AccountGroup] delete one account of the user.
	RemoveAccount

	// DeleteAuthenticatorKey makes a write of an [AuthenticatorKey] delete the key from the TOTP engine of Vault.
	DeleteAuthenticatorKey

	// SendUserDeleted makes a create of a [Message] tell the owner that the user was deleted.
	SendUserDeleted

	// SendRegistryToken makes a create of a [Message] send the verification token that finishes a registration.
	SendRegistryToken

	// SendRegistryTaken makes a create of a [Message] tell the owner of an address that someone tried to register
	// with it.
	SendRegistryTaken

	// SendPasskeyAdded makes a create of a [Message] tell the owner that the passkey named Name was added.
	SendPasskeyAdded

	// SendPasskeyRemoved makes a create of a [Message] tell the owner that the passkey named Name was removed.
	SendPasskeyRemoved

	// SendPasskeyDisabled makes a create of a [Message] tell the owner that the passkey named Name was disabled after
	// a counter regression.
	SendPasskeyDisabled

	// SendTOTPAdded makes a create of a [Message] tell the owner that a TOTP factor was added.
	SendTOTPAdded

	// SendTOTPRemoved makes a create of a [Message] tell the owner that the TOTP factor was removed.
	SendTOTPRemoved

	// SendRecoveryIssued makes a create of a [Message] tell the owner that a new set of recovery codes was issued.
	SendRecoveryIssued

	// SendRecoveryUsed makes a create of a [Message] tell the owner that a recovery code was used.
	SendRecoveryUsed

	// SendRecoveryRequested makes a create of a message tell the owner that someone asked to recover the user. It
	// carries the cancel token in Token and the delay in TTL.
	SendRecoveryRequested

	// SendRecoveryGrant makes a create of a message send the grant token of an approved recovery. It carries the token
	// in Token and its lifetime in TTL.
	SendRecoveryGrant

	// SendLoginRefused makes a create of a [Message] tell the owner that a login with a valid factor was refused as
	// risky.
	SendLoginRefused

	// EncryptTOTPSecret makes a create of a [Transit] item encrypt a TOTP secret. It encrypts Plaintext with the user
	// as the Context, so that only that user can decrypt the ciphertext.
	EncryptTOTPSecret

	// DecryptTOTPSecret makes a create of a [Transit] item decrypt a TOTP secret. It decrypts Ciphertext with the
	// user as the Context.
	DecryptTOTPSecret

	// RewrapTOTPSecret makes a create of a [Transit] item move a stored TOTP secret to the latest version of its key
	// after a key rotation. The plaintext never leaves Vault.
	RewrapTOTPSecret

	// HashTheValue makes a create of a [Transit] item compute the keyed hash of Plaintext. The service stores the
	// device identifier and the recovery code only in this form. The caller puts the domain of the value in front of
	// the value.
	HashTheValue

	// OpenRegistry makes a write of a [SessionGroup] create the user of a registration, bind the session to it and
	OpenRegistry

	// OpenTakenRegistry makes a write of a [SessionGroup] set the registration flags and the verification token hash
	// on the session of a registration whose email is taken. It creates no user.
	OpenTakenRegistry

	// VerifyRegistry makes a write of a [SessionGroup] mark the user of a registration as verified, mark the session
	// as verified and clear its verification token, so the token works once.
	VerifyRegistry

	// RevokeSession makes a write of a [SessionGroup] replace [SessionFlagAuthorized] with [SessionFlagRevoked] on a
	// session, for a logout or for the removal of a device.
	RevokeSession

	// OpenPasskeyEnrollment makes a write of a [SessionGroup] save the challenge of a passkey registration on the
	// session and replace any earlier challenge.
	OpenPasskeyEnrollment

	// OpenConfirmation makes a write of a [SessionGroup] save the challenge of the confirmation of a sensitive action
	// on the session and replace any earlier challenge. The state in the challenge holds the action and its target.
	OpenConfirmation

	// EnrollPasskey makes a write of a [SessionGroup] use up the challenge of the session, store the new passkey and
	EnrollPasskey

	// RefusePasskeyEnrollment makes a write of a [SessionGroup] use up the challenge of the session after a passkey
	// registration that did not verify.
	RefusePasskeyEnrollment

	// OpenPasskeyLogin makes a write of a [SessionGroup] start a passkey login: it clears the earlier attempt from the
	// session and saves the new challenge.
	OpenPasskeyLogin

	// RefuseLogin makes a write of a [SessionGroup] record a refused attempt of a factor: the failure counters, the
	// flag bits of a passkey. With [ConsumeChallenge] it also uses up the challenge of the session.
	RefuseLogin

	// AuthorizeLogin makes a write of a [SessionGroup] record a login that a factor accepted and the risk engine
	// allowed. It authorizes the session and ends the open recovery requests of the user, because a login with a factor
	// shows that the owner is in control.
	AuthorizeLogin

	// DenyLogin makes a write of a [SessionGroup] record a login that a factor accepted and the risk engine refused.
	// It clears the factor bits of the session and stores the risk score, and it leaves the open recovery requests as
	// they are.
	DenyLogin

	// ApprovePassword makes a write of a [SessionGroup] bind the session to the user after an accepted password and
	// clear the earlier attempt.
	ApprovePassword

	// ApproveRecoveryCode makes a write of a [SessionGroup] bind the session to the user after an accepted recovery
	// code, use the code up and end the open recovery requests of the user, because a recovery code shows that the owner
	// is in control.
	ApproveRecoveryCode

	// RemovePasskey makes a write of an [UserGroup] mark a passkey as removed, unless it is the last factor of the
	// user.
	RemovePasskey

	// ConfirmTOTP makes a write of an [UserGroup] mark the TOTP secret of the user as confirmed and store the step of
	// the accepted code.
	ConfirmTOTP

	// RemoveTOTP makes a write of an [UserGroup] delete the TOTP secret of the user, unless it is the last factor of
	// the user.
	RemoveTOTP

	// ReissueRecoveryCodes makes a write of an [UserGroup] retire the earlier recovery codes of the user and store a
	// new set.
	ReissueRecoveryCodes

	// DeleteUser makes a write of an [UserGroup] delete the user, with its passkeys, recovery codes, recovery
	// requests and sessions, and remove the identity from the rows of the request log of the user.
	DeleteUser

	// OpenRecoveryRequest makes a write of a [RecoveryGroup] store a new recovery request.
	OpenRecoveryRequest

	// RedeemRecoveryGrant makes a write of a [RecoveryGroup] use up the grant of an approved request, revoke the other
	// sessions of the user and bind the current session to the user.
	RedeemRecoveryGrant
)

// SessionIntents groups the intents that a [SessionGroup] write accepts. A write sets exactly one of them.
const SessionIntents = OpenRegistry | OpenTakenRegistry | VerifyRegistry | RevokeSession | OpenPasskeyEnrollment |
	OpenConfirmation | EnrollPasskey | RefusePasskeyEnrollment | OpenPasskeyLogin | RefuseLogin | AuthorizeLogin | DenyLogin |
	ApprovePassword | ApproveRecoveryCode

// UserIntents groups the intents that an [UserGroup] write accepts. A write sets exactly one of them.
const UserIntents = RemovePasskey | ConfirmTOTP | RemoveTOTP | ReissueRecoveryCodes | DeleteUser

// AccountIntents groups the intents that an [AccountGroup] write accepts. A write sets exactly one of them.
const AccountIntents = AddAccounts | RemoveAccount

// RecoveryIntents groups the intents that a [RecoveryGroup] write accepts. A write sets exactly one of them.
const RecoveryIntents = OpenRecoveryRequest | CancelRecoveryRequest | IssueRecoveryGrant | RedeemRecoveryGrant

// UserFlag is a bit of [User.Flags].
type UserFlag uint64

const (
	// UserFlagVerified is set when the service accepts the verification token of the registration. Until then the
	// user cannot authenticate or enroll a factor.
	UserFlagVerified UserFlag = 1 << iota

	// UserFlagTOTPConfirmed is set when the service accepts the first valid code of the enrolled TOTP secret. Until
	// then the secret is stored but is not a factor.
	UserFlagTOTPConfirmed

	// UserFlagDisabled is set by an operator. A disabled user cannot authenticate.
	UserFlagDisabled
)

// AccountFlag is a bit of [Authenticator.Flags]. It has no bits yet, and the column exists so that a state can be
// added without a migration.
type AccountFlag uint64

// PasskeyFlag is a bit of [Passkey.Flags]. Some bits copy the flags of the authenticator data. The others are the
// state that the service gives to the credential.
type PasskeyFlag uint64

const (
	// PasskeyFlagUserPresent is set when the authenticator reported user presence at registration.
	PasskeyFlagUserPresent PasskeyFlag = 1 << iota

	// PasskeyFlagUserVerified is set when the authenticator reported user verification at registration.
	PasskeyFlagUserVerified

	// PasskeyFlagBackupEligible is set when the credential may be synced between devices. It does not change after
	// registration. The service refuses a login whose assertion reports a different value.
	PasskeyFlagBackupEligible

	// PasskeyFlagBackedUp is set when the credential is currently backed up.
	PasskeyFlagBackedUp

	// PasskeyFlagDisabled is set when the service stops accepting the credential after a counter regression. A
	// disabled passkey still counts as a passkey of the user, so the password path stays closed.
	PasskeyFlagDisabled

	// PasskeyFlagRemoved is set when the user removes the passkey. A removed passkey does not count as a passkey of
	// the user. The row stays for support.
	PasskeyFlagRemoved
)

// SessionFlag is a bit of [Session.Flags]. The bits record which steps the session passed and which step is in
// progress. The [Permission] of each endpoint says which bits the endpoint requires.
type SessionFlag uint64

// SessionFlagUnauthorized is the empty state. No bit is set, so the session has no access. The permission check
// always refuses a session in this state.
const SessionFlagUnauthorized = SessionFlag(0)

const (
	// SessionFlagAuthorized means the user has access to private endpoints. It is set when the last factor of the
	// policy passes with an acceptable risk. Logout and security events clear it.
	SessionFlagAuthorized SessionFlag = 1 << iota

	// SessionFlagStarted means the session is open for a device. Every other step needs it.
	SessionFlagStarted

	// SessionFlagRegistryBegun means the session asked to register a user. The flag is set both if the user is
	// new and if the email is taken, so that the response does not show which case it is.
	SessionFlagRegistryBegun

	// SessionFlagRegistryVerified means the service accepted the verification token of the registration and bound the
	// session to the new user. The user has no factor yet and may enroll one.
	SessionFlagRegistryVerified

	// SessionFlagPasswordApproved means the service accepted the password of a user without a passkey. The TOTP
	// code is the next step.
	SessionFlagPasswordApproved

	// SessionFlagTOTPApproved means the service accepted the TOTP code.
	SessionFlagTOTPApproved

	// SessionFlagPasskeyApproved means the service accepted a passkey assertion.
	SessionFlagPasskeyApproved

	// SessionFlagRecoveryApproved means the service accepted a recovery code. The session is bound to the user and
	// may enroll a factor, but may do nothing else.
	SessionFlagRecoveryApproved

	// SessionFlagLimited means the risk engine asked for more verification. A sensitive action needs a fresh
	// authentication first.
	SessionFlagLimited

	// SessionFlagReview means the risk engine marked the login for review by a person.
	SessionFlagReview

	// SessionFlagRevoked means logout or a security event ended the session for good. A revoked session passes no
	// permission check.
	SessionFlagRevoked

	// SessionFlagChallengeRegistration means the challenge of the session is for the registration of a passkey.
	// SessionFlagChallengeLogin means it is for a login. A challenge for one is refused by the other.
	SessionFlagChallengeRegistration
	SessionFlagChallengeLogin

	// SessionFlagChallengeDiscoverable means the login challenge names no user. The passkey names the user in
	// its response. It is set together with [SessionFlagChallengeLogin].
	SessionFlagChallengeDiscoverable

	// SessionFlagChallengeConfirmation means the challenge is for the confirmation of a sensitive action. It is set
	// together with [SessionFlagChallengeLogin]. The challenge is bound to the action and its target.
	SessionFlagChallengeConfirmation
)

// SessionFlagChallenge groups the bits that say what the challenge of the session is for. The caller clears them when
// it consumes the challenge.
const SessionFlagChallenge = SessionFlagChallengeRegistration | SessionFlagChallengeLogin | SessionFlagChallengeDiscoverable |
	SessionFlagChallengeConfirmation

// SessionFlagEnrollment groups the states in which a session may enroll a factor without a fresh authentication:
// a verified registration and an accepted recovery code. One of the two bits is enough.
const SessionFlagEnrollment = SessionFlagRegistryVerified | SessionFlagRecoveryApproved

// SessionFlagFactors groups the bits that the factors set. A new login attempt on a session clears them.
const SessionFlagFactors = SessionFlagPasswordApproved | SessionFlagTOTPApproved | SessionFlagPasskeyApproved

// SessionFlagLoginAttempt groups the bits of the session that a new login attempt clears: the factors and the outcome
// of the earlier attempt.
const SessionFlagLoginAttempt = SessionFlagFactors | SessionFlagAuthorized | SessionFlagLimited | SessionFlagReview

// RecoveryRequestFlag is a bit of [RecoveryRequest.Flags], the one column that holds every state of the request. A
// request with neither [RecoveryRequestFlagCancelled] nor [RecoveryRequestFlagGranted] is open.
type RecoveryRequestFlag uint64

const (
	// RecoveryRequestFlagCancelled is set when the owner cancels the request, or when the user logs in with a factor.
	RecoveryRequestFlagCancelled RecoveryRequestFlag = 1 << iota

	// RecoveryRequestFlagApproved is set when an operator approves the request after its delay.
	RecoveryRequestFlagApproved

	// RecoveryRequestFlagGranted is set when the grant is used. The request is then closed.
	RecoveryRequestFlagGranted
)

// RecoveryRequestClosed groups the bits that close a request.
const RecoveryRequestClosed = RecoveryRequestFlagCancelled | RecoveryRequestFlagGranted

// RecoveryCodeFlag is a bit of [RecoveryCode.Flags].
type RecoveryCodeFlag uint64

const (
	// RecoveryCodeFlagUsed is set when the code is used or when a new set replaces it. A code with this bit passes no
	// check.
	RecoveryCodeFlagUsed RecoveryCodeFlag = 1 << iota
)
