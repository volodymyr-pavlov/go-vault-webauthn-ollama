package totp

import "errors"

// ErrFormat is returned by [Options.Verify] when the code has the wrong length or a character that is not a digit.
var ErrFormat = errors.New("the code is not a string of the right number of digits")

// ErrInvalid is returned by [Options.Verify] when the code matches no step of the window.
var ErrInvalid = errors.New("the code is wrong")

// ErrReused is returned by [Options.Verify] when the code is valid but its step is not after the last accepted step.
var ErrReused = errors.New("the code was already used")

// ErrOptions is returned by [Options.Validate] and [Options.Verify] when the number of digits is negative or above
// [MaxDigits].
var ErrOptions = errors.New("the number of digits is out of range")

// ErrImport is returned by [ParseURI] and [ParseSecret] when a link or a secret cannot be imported. The text says why.
var ErrImport = errors.New("totp: the account cannot be imported")

// errTruncated is the cause inside [ErrImport] when the migration data ends in the middle of a field.
var errTruncated = errors.New("truncated")
