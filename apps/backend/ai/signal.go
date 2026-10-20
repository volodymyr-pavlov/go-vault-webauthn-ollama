package ai

import (
	"encoding/json"
	"math/bits"
	"strings"
)

// Signal is one fact about a login attempt that the rules score. A [Signals] value holds a set of them as bits.
type Signal uint16

const (
	// SignalNewDevice is set when the user has logged in before, but no earlier login has the device hash of this
	// attempt.
	SignalNewDevice Signal = 1 << iota

	// SignalRecentEnrollment is set when the user enrolled a factor within [RecentCredential] before the attempt.
	SignalRecentEnrollment

	// SignalUnusualHour is set when the user has logged in at least three times before and the hour of the attempt is far
	// from the hours of those logins.
	SignalUnusualHour

	// SignalImpossibleTravel is set when the speed needed to travel from the place of the last login is above
	// [ImpossibleSpeedKmh].
	SignalImpossibleTravel

	// SignalSharedAddress is set when at least [SharedAddressUsers] different users tried to log in from the
	// address of the attempt within [SharedAddressWindow]. Credential stuffing from a small pool of addresses sets it,
	// and so do an office, a hotel or a mobile carrier that share one address among many people. Because of the honest
	// cases, its weight is low: alone it never moves a login to another level.
	SignalSharedAddress
)

// signalNames are the names of the signals in bit order. They are also the names of the reasons that the advisor may
// give.
var signalNames = [...]string{
	"new_device",
	"recent_enrollment",
	"unusual_hour",
	"impossible_travel",
	"shared_address",
}

// signalWeights are the points that each signal adds to the score, in bit order. The file docs/risk.md lists them.
var signalWeights = [...]uint8{
	25,
	15,
	10,
	40,
	10,
}

// The layout of a [Signals] value. The low bits hold the [Signal] set. Then come the failed attempts of the user or
// the address, and the wrong TOTP codes. Both counts stop at the number that already gives the full weight, because
// a larger number adds nothing to the score.
const (
	signalMask = 1<<len(signalNames) - 1

	// MaxFailedAttempts is the number of failed attempts from which the signal has its full weight. The count stops
	// here. MaxTOTPFailures is the same for the wrong TOTP codes.
	MaxFailedAttempts = 5
	MaxTOTPFailures   = 3

	failedShift = len(signalNames)
	failedMask  = 0b111 << failedShift
	totpShift   = failedShift + 3
	totpMask    = 0b11 << totpShift
)

// Signals are the facts about a login attempt that the rules score, packed into 10 bits: the set of [Signal] bits, the
// failed attempts and the wrong TOTP codes. The login handlers of the API compute them from the earlier sessions of the
// user and from the passkeys of the user. The zero value has no signal.
type Signals uint16

// Has reports whether every bit of signal is set.
func (s Signals) Has(signal Signal) bool {
	set := Signals(signal) & signalMask

	return set != 0 && s&set == set
}

// With returns the signals with the bits of signal set.
func (s Signals) With(signal Signal) Signals {
	return s | Signals(signal)&signalMask
}

// FailedAttempts returns the failed attempts for the user or from the address within [FailureWindow]. The count
// stops at [MaxFailedAttempts].
func (s Signals) FailedAttempts() uint8 {
	return uint8((s & failedMask) >> failedShift)
}

// WithFailedAttempts returns the signals with the failed attempts set to n. A negative n counts as 0 and an n above
// [MaxFailedAttempts] counts as [MaxFailedAttempts].
func (s Signals) WithFailedAttempts(n int) Signals {
	return s&^failedMask | Signals(min(max(n, 0), MaxFailedAttempts))<<failedShift
}

// TOTPFailures returns the wrong TOTP codes since the last accepted one. The count stops at [MaxTOTPFailures].
func (s Signals) TOTPFailures() uint8 {
	return uint8((s & totpMask) >> totpShift)
}

// WithTOTPFailures returns the signals with the wrong TOTP codes set to n. A negative n counts as 0 and an n above
// [MaxTOTPFailures] counts as [MaxTOTPFailures].
func (s Signals) WithTOTPFailures(n int) Signals {
	return s&^totpMask | Signals(min(max(n, 0), MaxTOTPFailures))<<totpShift
}

// Names returns the names of the signals that are set, in bit order. The names are the reasons that the advisor may
// give. The result is empty if no signal is set.
func (s Signals) Names() []string {
	names := []string{}
	for set := s & signalMask; set != 0; set &= set - 1 {
		names = append(names, signalNames[bits.TrailingZeros16(uint16(set))])
	}

	return names
}

// List returns the names of the signals that are set, separated by commas, or "none".
func (s Signals) List() string {
	if s&signalMask == 0 {
		return "none"
	}

	return strings.Join(s.Names(), ",")
}

// Score returns the risk score of the signals, from 0 to 100. Each signal adds a fixed weight, and the sum is capped
// at 100. Each failed attempt adds 5 points and each wrong TOTP code adds 5 points. The file docs/risk.md lists the
// weights.
func (s Signals) Score() uint8 {
	score := 5 * (s.FailedAttempts() + s.TOTPFailures())
	for set := s & signalMask; set != 0; set &= set - 1 {
		score += signalWeights[bits.TrailingZeros16(uint16(set))]
	}

	return min(score, 100)
}

// signalsJSON is the form of [Signals] in the summary that the advisor reads and in the evaluation report.
type signalsJSON struct {
	Signals        []string `json:"signals"`
	FailedAttempts uint8    `json:"failed_attempts"`
	TOTPFailures   uint8    `json:"totp_failures"`
}

// MarshalJSON implements [json.Marshaler]. It writes the names of the set signals and the two counts.
func (s Signals) MarshalJSON() ([]byte, error) {
	return json.Marshal(signalsJSON{
		Signals:        s.Names(),
		FailedAttempts: s.FailedAttempts(),
		TOTPFailures:   s.TOTPFailures(),
	})
}
