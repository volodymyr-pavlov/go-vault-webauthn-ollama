package ai

import (
	"encoding/json"
	"testing"
)

// TestSignalsPackBits proves that the flags and the two counts live in separate bits of one value, so that setting one
// never changes another, and that the counts stop at the number that gives the full weight.
func TestSignalsPackBits(t *testing.T) {
	var signals Signals
	signals = signals.With(SignalNewDevice | SignalSharedAddress)
	signals = signals.WithFailedAttempts(4)

	signals = signals.WithTOTPFailures(2)

	if !signals.Has(SignalNewDevice) || !signals.Has(SignalSharedAddress) || signals.Has(SignalUnusualHour) {
		t.Fatalf("flags: %v", signals.List())
	}

	if signals.FailedAttempts() != 4 || signals.TOTPFailures() != 2 {
		t.Fatalf("counts: %d %d", signals.FailedAttempts(), signals.TOTPFailures())
	}

	// Changing one count leaves the other count and the flags alone.
	signals = signals.WithFailedAttempts(1)
	if signals.FailedAttempts() != 1 || signals.TOTPFailures() != 2 || !signals.Has(SignalNewDevice) {
		t.Fatalf("after a change: %v %d %d", signals.List(), signals.FailedAttempts(), signals.TOTPFailures())
	}

	// A count above its limit stops at the limit, and a negative count is zero.
	if got := signals.WithFailedAttempts(900).FailedAttempts(); got != MaxFailedAttempts {
		t.Errorf("failed attempts stop at %d, got %d", MaxFailedAttempts, got)
	}

	if got := signals.WithTOTPFailures(900).TOTPFailures(); got != MaxTOTPFailures {
		t.Errorf("TOTP failures stop at %d, got %d", MaxTOTPFailures, got)
	}

	if got := signals.WithFailedAttempts(-3).FailedAttempts(); got != 0 {
		t.Errorf("a negative count must be zero, got %d", got)
	}

	// The whole value fits in eleven bits.
	if signals.WithFailedAttempts(900).WithTOTPFailures(900).With(^Signal(0)) >= 1<<11 {
		t.Error("the signals must use no more than eleven bits")
	}
}

// TestSignalsNamesAndWeights proves that every signal has a name, a weight and the order of its bit, and that Has
// refuses an empty or unknown mask.
func TestSignalsNamesAndWeights(t *testing.T) {
	want := []struct {
		signal Signal
		name   string
		points uint8
	}{
		{SignalNewDevice, "new_device", 25},
		{SignalRecentEnrollment, "recent_enrollment", 15},
		{SignalUnusualHour, "unusual_hour", 10},
		{SignalImpossibleTravel, "impossible_travel", 40},
		{SignalSharedAddress, "shared_address", 10},
		{SignalAnonymizingNetwork, "anonymizing_network", 15},
	}
	for _, c := range want {
		signals := Signals(0).With(c.signal)

		if names := signals.Names(); len(names) != 1 || names[0] != c.name {
			t.Errorf("%s: names %v", c.name, names)
		}

		if got := signals.Score(); got != c.points {
			t.Errorf("%s: score %d, want %d", c.name, got, c.points)
		}
	}

	if Signals(0).List() != "none" || len(Signals(0).Names()) != 0 {
		t.Error("no signal must list as none")
	}

	if Signals(0).With(SignalNewDevice).Has(0) || Signals(0).With(SignalNewDevice).Has(1<<12) {
		t.Error("an empty or unknown mask must not count as set")
	}
}

// TestSignalsJSON proves that the advisor reads the signals as a list of names and two counts, not as a number.
func TestSignalsJSON(t *testing.T) {
	signals := Signals(0).With(SignalUnusualHour | SignalNewDevice).WithFailedAttempts(2)

	encoded, err := json.Marshal(signals)
	if err != nil {
		t.Fatal(err)
	}

	const want = `{"signals":["new_device","unusual_hour"],"failed_attempts":2,"totp_failures":0}`

	if string(encoded) != want {
		t.Fatalf("got %s, want %s", encoded, want)
	}
}
