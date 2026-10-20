package authtest

import "errors"

// ErrNoChallenge is returned by [Challenge] when the options carry no challenge.
var ErrNoChallenge = errors.New("authtest: the options carry no challenge")

// ErrInvalidJSON is wrapped by the error that [Challenge] returns when the options are not valid JSON.
var ErrInvalidJSON = errors.New("authtest: the options are not valid JSON")

// ErrCredentialID is returned by [Authenticator.Register] when the credential ID is longer than 1023 bytes.
var ErrCredentialID = errors.New("authtest: the credential ID is longer than 1023 bytes")
