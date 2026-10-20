package auth

import (
	"errors"
	"time"
)

// ErrMismatch is returned by [Hasher.Verify] when the password is not the one that the hash was made from.
var ErrMismatch = errors.New("auth: the password does not match")

// ErrHashFormat is returned by [Hasher.Verify] when the hash is not an Argon2id hash in the PHC string format.
var ErrHashFormat = errors.New("auth: the hash is not an argon2id PHC string")

// ErrTooLong is returned by [Hasher.Hash] when the password is longer than [MaxLength].
var ErrTooLong = errors.New("auth: the password is too long")

// ErrVerify is returned by [RelyingParty.FinishRegistration], [RelyingParty.FinishLogin] and
// [RelyingParty.FinishDiscoverableLogin] when the response does not verify. Some causes are a wrong origin or RP ID, a
// wrong or reused challenge, and a bad signature. Others are a changed backup-eligible flag and a missing user
// verification. The cause is joined to the error for the log. The client sees only that the request is refused.
var ErrVerify = errors.New("auth: the response does not verify")

// ErrUserVerification is the cause joined to [ErrVerify] when the authenticator did not verify the user.
var ErrUserVerification = errors.New("auth: the user was not verified")

// ErrUnknownCredential is the cause joined to [ErrVerify] when the credential that signed is not one of the user's
// passkeys.
var ErrUnknownCredential = errors.New("auth: the credential is not the user's")

// ErrInvalidDeviceKey is returned by [RequestVerifier.ReadOne] when the device key does not have the size of an
// Ed25519 public key.
var ErrInvalidDeviceKey = errors.New("auth: the device key is not an Ed25519 public key")

// ErrInvalidSignature is returned by [RequestVerifier.ReadOne] when the signature fields are malformed or do not have
// the shape that the service signs. It is also returned when they do not match the request and the key.
var ErrInvalidSignature = errors.New("auth: the request signature is invalid")

// ErrReplayedRequest is returned by [RequestVerifier.ReadOne] when the nonce of the request was used before.
var ErrReplayedRequest = errors.New("auth: the request was sent before")

// StaleRequestError is the error that [RequestVerifier.ReadOne] returns for a request whose time is outside the window.
// It carries the time of the server, so that the client can correct its clock. It matches [ErrStaleRequest] with
// [errors.Is].
type StaleRequestError struct {
	// ServerTime is the time of the server when it checked the request.
	ServerTime time.Time
}

// Error implements the error interface.
func (e *StaleRequestError) Error() string {
	return ErrStaleRequest.Error()
}

// Is reports whether target is [ErrStaleRequest].
func (e *StaleRequestError) Is(target error) bool {
	return target == ErrStaleRequest
}

// ErrStaleRequest is returned by [RequestVerifier.ReadOne] when the time of the request is too far from the time of
// the server.
var ErrStaleRequest = errors.New("auth: the request is too old or too new")
