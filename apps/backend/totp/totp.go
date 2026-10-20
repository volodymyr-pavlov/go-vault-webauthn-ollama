// Package totp implements the time-based one-time password of RFC 6238. It uses HOTP of RFC 4226 over time steps with
// HMAC-SHA1, as authenticator apps do.
//
// With the default options, a code is valid for the current 30-second step and for the step before and the step after
// it. [Options.Verify] accepts a code once: it never accepts a step at or before the last accepted one.
//
// The secret is the only sensitive value. The package neither stores nor logs it. The service keeps the secret
// encrypted in Vault Transit and passes the plaintext to this package for one check.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

const (
	// SecretLength is the length of a new secret in bytes. It is 160 bits, the minimum of RFC 4226.
	SecretLength = 20

	// DefaultDigits, DefaultPeriod and DefaultSkew are the default parameters: six digits, 30-second steps and one step
	// either way.
	DefaultDigits = 6
	DefaultPeriod = 30
	DefaultSkew   = 1

	// MaxDigits is the largest number of digits that HOTP defines.
	MaxDigits = 8
)

// NewSecret returns a new secret of [SecretLength] random bytes.
//
// It returns an error if the system cannot supply random bytes.
func NewSecret() ([]byte, error) {
	secret := make([]byte, SecretLength)

	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("make the secret: %w", err)
	}
	return secret, nil
}

// URI returns the otpauth URI that an authenticator app reads to enroll account at issuer. It uses the parameters of
// opts and the algorithm SHA-1.
func URI(issuer, account string, secret []byte, opts Options) string {
	opts = opts.withDefaults()
	query := url.Values{}
	query.Set("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret))
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", strconv.Itoa(opts.Digits))
	query.Set("period", strconv.FormatUint(uint64(opts.Period), 10))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + query.Encode()
}

// Options holds the parameters of the codes. A zero field means its default.
type Options struct {
	// Digits is the length of a code. It must not be more than [MaxDigits].
	Digits int

	// Period is the length of a time step, in seconds.
	Period uint

	// Skew is how many steps before and after the current one are accepted. Zero means [DefaultSkew], so the window
	// always holds at least the steps next to the current one, which absorbs the drift of the clock of a phone.
	Skew uint
}

// Validate checks the parameters of o.
//
// It returns [ErrOptions] if Digits is negative or more than [MaxDigits].
func (o Options) Validate() error {
	if o.Digits < 0 || o.Digits > MaxDigits {
		return fmt.Errorf("%w: %d digits, want 1 to %d", ErrOptions, o.Digits, MaxDigits)
	}

	return nil
}

// withDefaults returns o with the default value in each field that is zero.
func (o Options) withDefaults() Options {
	if o.Digits == 0 {
		o.Digits = DefaultDigits
	}

	if o.Period == 0 {
		o.Period = DefaultPeriod
	}

	if o.Skew == 0 {
		o.Skew = DefaultSkew
	}

	return o
}

// Step returns the time step of t, using the period of o. A time before 1970 gives step 0.
func (o Options) Step(t time.Time) uint64 {
	o = o.withDefaults()

	unix := t.Unix()
	if unix < 0 {
		return 0
	}

	return uint64(unix) / uint64(o.Period)
}

// Code returns the code of secret at step. It is HOTP with HMAC-SHA1, cut to the number of digits of o and padded with
// leading zeros.
func (o Options) Code(secret []byte, step uint64) string {
	o = o.withDefaults()
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for range o.Digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", o.Digits, value%modulus)
}

// Verify checks code against the steps around now. It returns the step that the code was made for, so the caller can
// store it as the last accepted step. If more than one step matches, it returns the latest. It compares every candidate
// step in constant time.
//
// Verify never accepts a step at or before lastStep. This refuses a code that was used already and a code older than
// the last accepted one.
//
// It returns [ErrOptions] if the digits of o are out of range. It returns [ErrFormat] for a code of the wrong length or with a character that is not a digit. It returns [ErrReused]
// for a valid code whose step is not after lastStep. It returns [ErrInvalid] for a code that matches no step of the
// window.
func (o Options) Verify(secret []byte, code string, now time.Time, lastStep uint64) (uint64, error) {
	if err := o.Validate(); err != nil {
		return 0, err
	}

	o = o.withDefaults()
	if len(code) != o.Digits {
		return 0, ErrFormat
	}

	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, ErrFormat
		}
	}

	current := o.Step(now)
	skew := uint64(o.Skew)
	first := uint64(0)
	if current > skew {
		first = current - skew
	}

	matched := uint64(0)
	found := false
	reused := false
	for step := first; step <= current+skew; step++ {
		if subtle.ConstantTimeCompare([]byte(o.Code(secret, step)), []byte(code)) == 1 {
			if step <= lastStep {
				reused = true
				continue
			}

			if !found || step > matched {
				matched = step
				found = true
			}
		}
	}

	if found {
		return matched, nil
	}

	if reused {
		return 0, ErrReused
	}

	return 0, ErrInvalid
}
