// Package validate checks the size and the shape of the strings in a client request.
//
// A check returns a bool, and the caller decides how to refuse the field. The checks never change their input. They do
// not check what a value means.
package validate

import (
	"encoding/base32"
	"encoding/hex"
	"regexp"
	"strings"
)

const (
	// MaxEmailLength is the length limit of an email address, in bytes. It is the limit of RFC 5321.
	MaxEmailLength = 254

	// MinPasswordLength is the minimum length of a password, in bytes.
	MinPasswordLength = 10

	// MaxDeviceIDLength is the length limit of a device identifier, in bytes.
	MaxDeviceIDLength = 128

	// MaxNameLength is the length limit of a passkey name, in bytes.
	MaxNameLength = 64

	// TokenLength is the length of a verification token, in bytes.
	TokenLength = 32

	// RecoveryCodeLength is the length of a recovery code, in base32 characters. The code holds 80 bits.
	RecoveryCodeLength = 16
)

// emailPattern matches an address with one @, no white space and a dot in the domain.
var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Validate holds a string and the size limits to check it against. Max and Min are in bytes.
type Validate struct {
	Input string
	Max   int
	Min   int
}

// IsEmpty reports whether Input is empty or contains only white space.
func (v Validate) IsEmpty() bool {
	return len(strings.TrimSpace(v.Input)) == 0
}

// TooLong reports whether Input is longer than Max. It reports false for an empty input.
func (v Validate) TooLong() bool {
	return len(v.Input) > v.Max && len(v.Input) != 0
}

// TooShort reports whether Input is empty or shorter than Min.
func (v Validate) TooShort() bool {
	return len(v.Input) < v.Min || len(v.Input) == 0
}

// IsEmail reports whether input looks like an email address and is at most [MaxEmailLength] bytes long.
func IsEmail(input string) bool {
	return len(input) <= MaxEmailLength && emailPattern.MatchString(input)
}

// IsDigits reports whether input is exactly n ASCII decimal digits.
func IsDigits(input string, n int) bool {
	if len(input) != n {
		return false
	}

	for _, r := range input {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

// IsRecoveryCode reports whether input is a recovery code. A recovery code has [RecoveryCodeLength] upper case base32
// characters.
func IsRecoveryCode(input string) bool {
	if len(input) != RecoveryCodeLength {
		return false
	}

	_, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(input)
	return err == nil
}

// HexToken decodes input as a hex string of [TokenLength] bytes. It reports false if input is not such a string, for
// example if it contains white space.
func HexToken(input string) ([]byte, bool) {
	token, err := hex.DecodeString(input)
	if err != nil || len(token) != TokenLength {
		return nil, false
	}

	return token, true
}
