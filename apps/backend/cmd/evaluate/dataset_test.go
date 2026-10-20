package main

import (
	"bytes"
	"encoding/csv"
	"slices"
	"testing"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

func TestDatasetIsDeterministic(t *testing.T) {
	first := dataset(2026, 300, 50)

	second := dataset(2026, 300, 50)

	if !slices.Equal(first, second) {
		t.Error("the same seed gave different events")
	}

	if slices.Equal(first, dataset(2027, 300, 50)) {
		t.Error("another seed gave the same events")
	}
}

func TestDatasetScenarioCountsAndLabels(t *testing.T) {
	const perScenario = 50

	events := dataset(2026, 300, perScenario)
	byName := make(map[string]Scenario, len(scenarios))
	for _, scenario := range scenarios {
		byName[scenario.Name] = scenario
	}

	seen := make(map[string]int)
	baseline := 0
	for i, event := range events {
		scenario, ok := byName[event.Scenario]
		if !ok {
			t.Fatalf("event %d has the unknown scenario %q", event.ID, event.Scenario)
		}

		if event.ID != i+1 {
			t.Errorf("event %d has the id %d", i+1, event.ID)
		}

		if event.Suspicious != scenario.Suspicious {
			t.Errorf("event %d of %s has the label %v, want %v", event.ID, event.Scenario, event.Suspicious, scenario.Suspicious)
		}

		seen[event.Scenario]++

		if scenario.Baseline {
			baseline++
		}
	}

	if baseline != 300 {
		t.Errorf("%d baseline events, want 300", baseline)
	}

	for _, scenario := range scenarios {
		if scenario.Baseline {
			continue
		}

		if seen[scenario.Name] != perScenario {
			t.Errorf("%s has %d events, want %d", scenario.Name, seen[scenario.Name], perScenario)
		}
	}
}

func TestBaselineMixDoesNotDependOnTheHardScenarios(t *testing.T) {
	small := dataset(2026, 300, 0)

	large := dataset(2026, 300, 50)

	if !slices.Equal(small, large[:300]) {
		t.Error("the baseline events changed when the hard scenarios were added")
	}
}

func TestBaselineKeepsTheOriginalSplit(t *testing.T) {
	suspicious := 0
	for _, event := range dataset(2026, 300, 0) {
		if event.Suspicious {
			suspicious++
		}
	}

	if suspicious != 62 {
		t.Errorf("%d suspicious baseline events, want 62", suspicious)
	}
}

func TestHardScenariosHaveTheirSignals(t *testing.T) {
	for _, event := range dataset(2026, 300, 50)[300:] {
		signals := event.Signals

		var ok bool
		switch event.Scenario {
		case scenarioSlowStuffing:
			ok = signals.Has(ai.SignalNewDevice) && signals.FailedAttempts() == 0 && signals.TOTPFailures() == 0
		case scenarioSameCountry:
			ok = signals.Has(ai.SignalNewDevice) && !signals.Has(ai.SignalRecentEnrollment) && !signals.Has(ai.SignalUnusualHour)
		case scenarioSIMSwap:
			ok = signals.Has(ai.SignalNewDevice) && signals.Has(ai.SignalRecentEnrollment) && event.Factor == es.FactorPassword|es.FactorTOTP
		case scenarioRecoveryAbuse:
			ok = signals.Has(ai.SignalNewDevice) && signals.Has(ai.SignalRecentEnrollment) && event.Factor == es.FactorPasskey
		case scenarioTraveler:
			ok = signals.Has(ai.SignalNewDevice) && signals.FailedAttempts() == 0
		case scenarioShiftWorker:
			ok = signals.Has(ai.SignalUnusualHour) && !signals.Has(ai.SignalRecentEnrollment)
		case scenarioFatFinger:
			ok = signals.FailedAttempts() == 3 && signals.TOTPFailures() == 3
		case scenarioNewPhone:
			ok = signals.Has(ai.SignalNewDevice) && signals.Has(ai.SignalRecentEnrollment) && event.Factor == es.FactorPasskey
		}

		if !ok {
			t.Errorf("event %d of %s has the wrong signals: %+v", event.ID, event.Scenario, signals)
		}
	}
}

func TestHourBucketIsWellFormed(t *testing.T) {
	valid := map[string]bool{}
	for start := 0; start < 24; start += 4 {
		valid[bucketName(start)] = true
	}

	for _, event := range dataset(2026, 300, 50) {
		if !valid[event.HourBucket] {
			t.Errorf("event %d has the bucket %q", event.ID, event.HourBucket)
		}
	}
}

func TestWriteCSV(t *testing.T) {
	events := dataset(2026, 20, 2)

	var out bytes.Buffer

	if err := writeCSV(&out, events); err != nil {
		t.Fatal(err)
	}

	rows, err := csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	if len(rows) != len(events)+1 {
		t.Fatalf("%d rows, want %d", len(rows), len(events)+1)
	}

	if rows[0][1] != "scenario" || rows[1][1] != events[0].Scenario {
		t.Errorf("the scenario field is %q and %q", rows[0][1], rows[1][1])
	}
}

func TestRulesAloneOnTheHardScenarios(t *testing.T) {
	tallies := map[string]*tally{}
	for _, scenario := range scenarios {
		tallies[scenario.Name] = &tally{}
	}

	for _, event := range dataset(2026, 300, 50) {
		flagged := event.Signals.Score() >= 30
		tallies[event.Scenario].rules.count(flagged, event.Suspicious)
	}

	if got := tallies[scenarioSlowStuffing].rules; got.truePositive == 0 || got.falseNegative == 0 {
		t.Errorf("slow-stuffing should be caught only in part by the rules: %+v", got)
	}

	if got := tallies[scenarioFatFinger].rules; got.falsePositive != 50 {
		t.Errorf("fat-finger should always be flagged by the rules: %+v", got)
	}
}
