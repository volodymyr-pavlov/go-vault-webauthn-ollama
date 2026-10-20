package es

// Event names a security event that a handler reports for its request. The request log stores the name next to the
// request. The set is closed: a handler reports one of these constants and no other text.
type Event string

// The security events. A request reports at most one.
const (
	EventAccountAdded             Event = "account_added"
	EventAccountRemoved           Event = "account_removed"
	EventUserDeleted              Event = "user_deleted"
	EventUserDeletionRefused      Event = "user_deletion_refused"
	EventUserExported             Event = "user_exported"
	EventCounterRegression        Event = "counter_regression"
	EventLogin                    Event = "login"
	EventLoginDenied              Event = "login_denied"
	EventLogout                   Event = "logout"
	EventPasskeyEnrolled          Event = "passkey_enrolled"
	EventPasskeyEnrollmentRefused Event = "passkey_enrollment_refused"
	EventPasskeyRefused           Event = "passkey_refused"
	EventPasskeyRemovalRefused    Event = "passkey_removal_refused"
	EventPasskeyRemoved           Event = "passkey_removed"
	EventPasswordApproved         Event = "password_approved"
	EventPasswordRefused          Event = "password_refused"
	EventRecoveryCancelled        Event = "recovery_cancelled"
	EventRecoveryClaimed          Event = "recovery_claimed"
	EventRecoveryCodesIssued      Event = "recovery_codes_issued"
	EventRecoveryGranted          Event = "recovery_granted"
	EventRecoveryRefused          Event = "recovery_refused"
	EventRecoveryRequested        Event = "recovery_requested"
	EventRecoveryUsed             Event = "recovery_used"
	EventRegistrationBegun        Event = "registration_begun"
	EventRegistrationTokenRefused Event = "registration_token_refused"
	EventRegistrationVerified     Event = "registration_verified"
	EventSessionRevoked           Event = "session_revoked"
	EventTOTPCiphertextRefused    Event = "totp_ciphertext_refused"
	EventTOTPEnrolled             Event = "totp_enrolled"
	EventTOTPEnrollmentRefused    Event = "totp_enrollment_refused"
	EventTOTPRefused              Event = "totp_refused"
	EventTOTPRemoved              Event = "totp_removed"
)
