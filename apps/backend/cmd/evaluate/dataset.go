package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"math/rand/v2"
	"strconv"
	"strings"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// Event is one labelled login of the synthetic dataset. It has the signals that the rules score, the coarse facts that
// the model sees, the name of the scenario that made it, and the label that tells whether the login was suspicious.
type Event struct {
	ID         int
	Scenario   string
	Signals    ai.Signals
	Country    string
	HourBucket string
	Factor     es.Factors
	Suspicious bool
}

// Scenario describes one kind of login that the generator makes.
type Scenario struct {
	// Name is the name of the scenario. It is the scenario field of the dataset file.
	Name string

	// Suspicious is the label of every login of the scenario.
	Suspicious bool

	// Baseline is set for the scenarios of the original mix. The others are the hard scenarios.
	Baseline bool
}

// The names of the scenarios of the original mix.
const (
	scenarioBaselineLegitimate   = "baseline-legitimate"
	scenarioBaselineFailureBurst = "baseline-failure-burst"
	scenarioBaselineOddHour      = "baseline-new-device-odd-hour"
	scenarioBaselineTravel       = "baseline-impossible-travel"
	scenarioBaselineWrongCodes   = "baseline-wrong-codes"
	scenarioBaselineWeak         = "baseline-weak-new-credential"
)

// The names of the hard scenarios.
const (
	scenarioSlowStuffing  = "slow-stuffing"
	scenarioSameCountry   = "same-country-new-device"
	scenarioSIMSwap       = "sim-swap"
	scenarioRecoveryAbuse = "recovery-abuse"
	scenarioTraveler      = "traveler"
	scenarioShiftWorker   = "shift-worker"
	scenarioFatFinger     = "fat-finger"
	scenarioNewPhone      = "new-phone"
)

// scenarios are all the scenarios of the generator, in the order of the report.
var scenarios = []Scenario{
	{
		Name:     scenarioBaselineLegitimate,
		Baseline: true,
	},
	{
		Name:       scenarioBaselineFailureBurst,
		Suspicious: true,
		Baseline:   true,
	},
	{
		Name:       scenarioBaselineOddHour,
		Suspicious: true,
		Baseline:   true,
	},
	{
		Name:       scenarioBaselineTravel,
		Suspicious: true,
		Baseline:   true,
	},
	{
		Name:       scenarioBaselineWrongCodes,
		Suspicious: true,
		Baseline:   true,
	},
	{
		Name:       scenarioBaselineWeak,
		Suspicious: true,
		Baseline:   true,
	},
	{
		Name:       scenarioSlowStuffing,
		Suspicious: true,
	},
	{
		Name:       scenarioSameCountry,
		Suspicious: true,
	},
	{
		Name:       scenarioSIMSwap,
		Suspicious: true,
	},
	{
		Name:       scenarioRecoveryAbuse,
		Suspicious: true,
	},
	{Name: scenarioTraveler},
	{Name: scenarioShiftWorker},
	{Name: scenarioFatFinger},
	{Name: scenarioNewPhone},
}

// countries are the country codes that an [Event] can have.
var countries = []string{
	"DE",
	"US",
	"JP",
	"AU",
	"FR",
	"BR",
	"NL",
}

// factors are the factors that an [Event] can have.
var factors = []es.Factors{
	es.FactorPasskey,
	es.FactorPassword | es.FactorTOTP,
}

// dataset returns the events that it generates from seed, so the same seed gives the same events.
//
// The first baseline events are the original mix. Four in five logins are legitimate. Most of them have no signal, and
// some have a new device, an unusual hour or a new credential, as happens with travel or a new phone. One in five is
// suspicious. It has a burst of failures, a new device at an odd hour, an impossible travel, or a weak case that only a
// new credential and a failed code or two show. The rules alone let the weak case through.
//
// After them come perScenario events of each hard scenario, in the order of [scenarios]. The hard scenarios are the
// attacks that the rules are known to score low and the legitimate logins that look like attacks. See [hardEvent].
//
// The labels are true by construction. They say nothing about real traffic.
func dataset(seed uint64, baseline, perScenario int) []Event {
	random := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	events := make([]Event, 0, baseline+perScenario*len(scenarios))
	for i := range baseline {
		events = append(events, baselineEvent(random, i+1))
	}

	for _, scenario := range scenarios {
		if scenario.Baseline {
			continue
		}

		for range perScenario {
			events = append(events, hardEvent(random, len(events)+1, scenario.Name))
		}
	}

	return events
}

// bucket returns a four-hour bucket of the UTC day. It is the night, from 00 to 08, if night is set, and the daytime,
// from 08 to 20, otherwise.
func bucket(random *rand.Rand, night bool) string {
	start := 8 + 4*random.IntN(3)
	if night {
		start = 4 * random.IntN(2)
	}

	return bucketName(start)
}

// bucketName returns the name of the four-hour bucket that starts at the given hour.
func bucketName(start int) string {
	return fmt.Sprintf("%02d-%02d", start, (start+4)%24)
}

// baselineEvent returns the event with the given id of the original mix.
func baselineEvent(random *rand.Rand, id int) Event {
	event := Event{
		ID:       id,
		Scenario: scenarioBaselineLegitimate,
		Country:  countries[random.IntN(len(countries))],
	}

	// The first draw gives the start of the bucket. The second draw is dropped: it only keeps the sequence of the
	// seed the same as it was when the bucket had an independent end.
	start := 4 * random.IntN(6)
	random.IntN(6)

	event.HourBucket = bucketName(start)
	event.Factor = factors[random.IntN(len(factors))]

	if random.IntN(5) != 0 {
		switch random.IntN(10) {
		case 0:
			event.Signals = event.Signals.With(ai.SignalNewDevice)
		case 1:
			event.Signals = event.Signals.With(ai.SignalUnusualHour)
		case 2:
			event.Signals = event.Signals.With(ai.SignalRecentEnrollment)
		case 3:
			if random.IntN(2) == 1 {
				event.Signals = event.Signals.WithFailedAttempts(1)
			}
		}

		return event
	}

	event.Suspicious = true

	switch random.IntN(5) {
	case 0:
		event.Scenario = scenarioBaselineFailureBurst
		event.Signals = event.Signals.WithFailedAttempts(6)

		for range random.IntN(10) {
			event.Signals = event.Signals.WithFailedAttempts(int(event.Signals.FailedAttempts()) + 1)
		}

		event.Signals = event.Signals.With(ai.SignalNewDevice)
	case 1:
		event.Scenario = scenarioBaselineOddHour
		event.Signals = event.Signals.With(ai.SignalNewDevice)
		event.Signals = event.Signals.With(ai.SignalUnusualHour)
	case 2:
		event.Scenario = scenarioBaselineTravel
		event.Signals = event.Signals.With(ai.SignalImpossibleTravel)

		if random.IntN(2) == 0 {
			event.Signals = event.Signals.With(ai.SignalNewDevice)
		}
	case 3:
		event.Scenario = scenarioBaselineWrongCodes
		event.Signals = event.Signals.WithTOTPFailures(3)

		for range random.IntN(4) {
			event.Signals = event.Signals.WithTOTPFailures(int(event.Signals.TOTPFailures()) + 1)
		}

		event.Signals = event.Signals.With(ai.SignalNewDevice)
		event.Signals = event.Signals.With(ai.SignalUnusualHour)
	default:
		// The weak case is a new credential with a failed code or two. Its score is below the medium level.
		event.Scenario = scenarioBaselineWeak
		event.Signals = event.Signals.With(ai.SignalRecentEnrollment)
		event.Signals = event.Signals.WithTOTPFailures(1)

		if random.IntN(2) == 1 {
			event.Signals = event.Signals.WithTOTPFailures(2)
		}
	}

	return event
}

// hardEvent returns the event with the given id of the hard scenario with the given name.
//
// The attacks are the ones that the rules score low or only just medium, each with the reason why it exists:
//
//   - slow-stuffing is credential stuffing at low speed. The attacker holds a leaked list of valid passwords and tries
//     each account once, from many different residential addresses, so no account has a failure and no address has a
//     burst. The only trace is a new device. Half of the logins come from a small proxy pool that reuses an address
//     for several accounts, which sets the shared address signal.
//   - same-country-new-device is an attacker who has the password of the account and who logs in from the country of the
//     owner at a plausible hour. The signals are those of an honest new laptop, and one in four has a single failure
//     from a stale password.
//   - sim-swap is a takeover where the attacker moved the phone number of the owner to a new SIM, reset the password,
//     enrolled a new factor and logged in with a fresh TOTP. It shows a factor enrolled within a day, a new device and,
//     in three of four cases, an unusual hour.
//   - recovery-abuse is a login with a new passkey right after an account recovery that the attacker started with a
//     stolen recovery code, from a new device.
//
// The legitimate logins are the ones that look like attacks, so that the false positive rate means something:
//
//   - traveler is the owner in a new country on a new device, mostly at an unusual hour for the account, and in one of
//     four cases on the shared address of a hotel.
//   - shift-worker is an owner who logs in at an unusual hour after a change of shift, and in one of five cases on a new
//     device.
//   - fat-finger is an owner who mistypes the password and the code three times.
//   - new-phone is an owner who enrolled a passkey on a new phone and logs in with it.
func hardEvent(random *rand.Rand, id int, name string) Event {
	event := Event{
		ID:       id,
		Scenario: name,
		Country:  countries[random.IntN(len(countries))],
		Factor:   factors[random.IntN(len(factors))],
	}

	switch name {
	case scenarioSlowStuffing:
		event.Suspicious = true
		event.Signals = event.Signals.With(ai.SignalNewDevice)

		if random.IntN(2) == 0 {
			event.Signals = event.Signals.With(ai.SignalSharedAddress)
		}

		event.Factor = es.FactorPassword | es.FactorTOTP
	case scenarioSameCountry:
		event.Suspicious = true
		event.Signals = event.Signals.With(ai.SignalNewDevice)

		if random.IntN(4) == 0 {
			event.Signals = event.Signals.WithFailedAttempts(1)
		}
	case scenarioSIMSwap:
		event.Suspicious = true
		event.Signals = event.Signals.With(ai.SignalRecentEnrollment)
		event.Signals = event.Signals.With(ai.SignalNewDevice)

		if random.IntN(4) != 0 {
			event.Signals = event.Signals.With(ai.SignalUnusualHour)
		}

		event.Factor = es.FactorPassword | es.FactorTOTP
	case scenarioRecoveryAbuse:
		event.Suspicious = true
		event.Signals = event.Signals.With(ai.SignalRecentEnrollment)
		event.Signals = event.Signals.With(ai.SignalNewDevice)
		event.Factor = es.FactorPasskey
	case scenarioTraveler:
		event.Signals = event.Signals.With(ai.SignalNewDevice)

		if random.IntN(3) != 0 {
			event.Signals = event.Signals.With(ai.SignalUnusualHour)
		}

		if random.IntN(4) == 0 {
			event.Signals = event.Signals.With(ai.SignalSharedAddress)
		}
	case scenarioShiftWorker:
		event.Signals = event.Signals.With(ai.SignalUnusualHour)

		if random.IntN(5) == 0 {
			event.Signals = event.Signals.With(ai.SignalNewDevice)
		}
	case scenarioFatFinger:
		event.Signals = event.Signals.WithFailedAttempts(3)
		event.Signals = event.Signals.WithTOTPFailures(3)
		event.Factor = es.FactorPassword | es.FactorTOTP
	case scenarioNewPhone:
		event.Signals = event.Signals.With(ai.SignalNewDevice)
		event.Signals = event.Signals.With(ai.SignalRecentEnrollment)
		event.Factor = es.FactorPasskey
	}

	event.HourBucket = bucket(random, event.Signals.Has(ai.SignalUnusualHour))
	return event
}

// writeCSV writes events to w as CSV, one line for each event, after a header line. The label is the last field.
func writeCSV(w io.Writer, events []Event) error {
	writer := csv.NewWriter(w)
	header := []string{
		"id",
		"scenario",
		"country",
		"hour_bucket",
		"factor",
		"signals",
		"failed_attempts",
		"totp_failures",
		"score",
		"label",
	}

	if err := writer.Write(header); err != nil {
		return err
	}

	for _, event := range events {
		label := "legitimate"
		if event.Suspicious {
			label = "suspicious"
		}

		record := []string{
			strconv.Itoa(event.ID),
			event.Scenario,
			event.Country,
			event.HourBucket,
			event.Factor.String(),
			strings.Join(event.Signals.Names(), "|"),
			strconv.Itoa(int(event.Signals.FailedAttempts())),
			strconv.Itoa(int(event.Signals.TOTPFailures())),
			strconv.Itoa(int(event.Signals.Score())),
			label,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}
