package es

import (
	"math/bits"
	"strings"
)

// Factors is a set of the factors that a person proved in a login, one bit for each. A login with a password and a
// code of the authenticator app holds two bits.
type Factors uint8

// The factors.
const (
	FactorPassword Factors = 1 << iota
	FactorTOTP
	FactorPasskey
	FactorRecoveryCode
)

// factorNames are the names of the factors in bit order.
var factorNames = [...]string{
	"password",
	"totp",
	"passkey",
	"recovery_code",
}

// Single reports whether the set holds exactly one factor.
func (f Factors) Single() bool {
	return bits.OnesCount8(uint8(f)) == 1
}

// String returns the names of the factors in the set, in bit order, joined by a plus sign, such as "password+totp".
func (f Factors) String() string {
	var names []string
	for bit, name := range factorNames {
		if f&(1<<bit) != 0 {
			names = append(names, name)
		}
	}

	return strings.Join(names, "+")
}

// MarshalText implements [encoding.TextMarshaler], so that JSON and templates show the names, not the number.
func (f Factors) MarshalText() ([]byte, error) {
	return []byte(f.String()), nil
}
