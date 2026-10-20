package es

import "time"

// RecoveryRequest is the request of a user who lost every factor and every recovery code to get back into the user.
// An email alone never grants access. The request waits for a delay, during which the owner can cancel it, and then
// needs the approval of an operator. The approved request yields one single-use grant that lets a session enroll a new
// factor.
//
// A [Reader] finds the newest open request of a UserID, or the request with a GrantHash. A [Writer] creates a request,
// and updates one with [CancelRecoveryRequest], [ApproveRecoveryRequest], [IssueRecoveryGrant] or [UseUpRecoveryGrant].
// A [Replacer] with [AllOfUser] cancels every open request of a UserID. A [BatchReader] lists the requests that are
// open.
type RecoveryRequest struct {
	// ID is the internal key of the row.
	ID uint64

	// RecoveryRequestXID is the external identifier of the request, from the snowflake of recovery requests.
	RecoveryRequestXID uint64

	// Flags holds the state of the request. See [RecoveryRequestFlag].
	Flags RecoveryRequestFlag

	// UserID is the ID of the user that the request is for.
	UserID uint64

	// CancelHash is the SHA-256 of the cancel token. The token itself goes to the owner by email.
	CancelHash []byte

	// GrantHash is the SHA-256 of the grant token. GrantExpiresAt is when the grant stops working. Both are empty until
	// the owner claims an approved request.
	GrantHash      []byte
	GrantExpiresAt time.Time

	// ReadyAt is when the delay ends. An operator can approve the request only from this time on.
	ReadyAt time.Time

	// CreatedAt is the time when the request was stored.
	CreatedAt time.Time
}
