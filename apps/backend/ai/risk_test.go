package ai

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

var quiet = slog.New(slog.DiscardHandler)

func TestSummaryLimitCountsCharacters(t *testing.T) {
	multibyte := strings.Repeat("é", MaxSummaryText)
	raw := []byte(`{"risk_level":"low","reasons":[],"summary":"` + multibyte + `"}`)

	if _, err := ParseAdvice(raw); err != nil {
		t.Fatalf("a summary of %d characters: %v", MaxSummaryText, err)
	}

	raw = []byte(`{"risk_level":"low","reasons":[],"summary":"` + multibyte + `é"}`)

	if _, err := ParseAdvice(raw); !IsRefusedAdvice(err) {
		t.Fatalf("a summary of %d characters: %v, want a refusal", MaxSummaryText+1, err)
	}
}

func TestScoreAndLevel(t *testing.T) {
	cases := []struct {
		signals Signals
		score   uint8
		level   Level
	}{
		{Signals(0), 0, LevelLow},
		{Signals(0).With(SignalNewDevice), 25, LevelLow},
		{Signals(0).With(SignalNewDevice | SignalUnusualHour), 35, LevelMedium},
		{Signals(0).WithFailedAttempts(10), 25, LevelLow},
		{Signals(0).With(SignalSharedAddress), 10, LevelLow},
		{Signals(0).With(SignalSharedAddress | SignalNewDevice), 35, LevelMedium},
		{Signals(0).With(SignalSharedAddress | SignalImpossibleTravel | SignalNewDevice), 75, LevelHigh},
		{Signals(0).WithFailedAttempts(10).WithTOTPFailures(10), 40, LevelMedium},
		{Signals(0).With(SignalImpossibleTravel | SignalNewDevice | SignalRecentEnrollment), 80, LevelHigh},
		{Signals(0).With(SignalImpossibleTravel | SignalNewDevice | SignalRecentEnrollment | SignalUnusualHour).WithFailedAttempts(9).WithTOTPFailures(9), 100, LevelHigh},
	}
	for _, c := range cases {
		if score := c.signals.Score(); score != c.score || LevelOf(score) != c.level {
			t.Errorf("%+v: score %d level %s, want %d %s", c.signals, score, LevelOf(score), c.score, c.level)
		}
	}
}

func TestRulesDecideAlone(t *testing.T) {
	engine := &Engine{
		Logger: quiet,
	}
	cases := []struct {
		signals  Signals
		decision Decision
	}{
		{Signals(0), DecisionAllow},
		{Signals(0).With(SignalNewDevice | SignalUnusualHour), DecisionLimit},
		{Signals(0).With(SignalImpossibleTravel | SignalNewDevice | SignalRecentEnrollment), DecisionDeny},
	}
	for _, c := range cases {
		outcome := engine.Decide(context.Background(), Summary{Signals: c.signals})
		if outcome.Decision != c.decision || outcome.Advised() {
			t.Errorf("%+v: %s advised %v, want %s", c.signals, outcome.Decision, outcome.Advised(), c.decision)
		}
	}
}

func TestAdvisorOnlyRaises(t *testing.T) {
	cases := []struct {
		name     string
		signals  Signals
		advice   Advice
		err      error
		decision Decision
		raised   bool
	}{
		{"a low advice on a low login changes nothing", Signals(0), Advice{Level: LevelLow}, nil, DecisionAllow, false},
		{"a high advice on a low login limits", Signals(0), Advice{Level: LevelHigh}, nil, DecisionLimit, true},
		{"a high advice on a medium login flags for review", Signals(0).With(SignalNewDevice | SignalUnusualHour), Advice{Level: LevelHigh}, nil, DecisionReview, true},
		{"a low advice on a medium login cannot lower it", Signals(0).With(SignalNewDevice | SignalUnusualHour), Advice{Level: LevelLow}, nil, DecisionLimit, false},
		{"a low advice on a high login cannot approve it", Signals(0).With(SignalImpossibleTravel | SignalNewDevice | SignalRecentEnrollment), Advice{Level: LevelLow}, nil, DecisionDeny, false},
		{"an advisor failure falls back to the rules", Signals(0).With(SignalNewDevice | SignalUnusualHour), Advice{}, errors.New("down"), DecisionLimit, false},
	}
	for _, c := range cases {
		engine := &Engine{
			Advisor: &MockAdvisor{
				Advice: c.advice,
				Err:    c.err,
			},
			Timeout: time.Second,
			Logger:  quiet,
		}
		outcome := engine.Decide(context.Background(), Summary{Signals: c.signals})
		if outcome.Decision != c.decision || outcome.Raised() != c.raised {
			t.Errorf("%s: %s raised %v, want %s raised %v", c.name, outcome.Decision, outcome.Raised(), c.decision, c.raised)
		}
	}
}

func TestSlowAdvisorIsIgnored(t *testing.T) {
	engine := &Engine{
		Advisor: slowAdvisor{},
		Timeout: 10 * time.Millisecond,
		Logger:  quiet,
	}

	outcome := engine.Decide(context.Background(), Summary{})
	if outcome.Decision != DecisionAllow || outcome.Advised() {
		t.Fatalf("a slow advisor: %s advised %v", outcome.Decision, outcome.Advised())
	}
}

type slowAdvisor struct{}

func (slowAdvisor) ReadOne(ctx context.Context, item Consultation, _ es.Op) (Consultation, error) {
	<-ctx.Done()
	return item, ctx.Err()
}

func TestHostileOutput(t *testing.T) {
	long := strings.Repeat("a", MaxSummaryText+1)
	cases := []struct {
		name string
		raw  string
	}{
		{"extra field", `{"risk_level":"low","reasons":[],"summary":"ok","approve":true}`},
		{"wrong type", `{"risk_level":1,"reasons":[],"summary":"ok"}`},
		{"unknown level", `{"risk_level":"safe","reasons":[],"summary":"ok"}`},
		{"unknown reason", `{"risk_level":"low","reasons":["trust_me"],"summary":"ok"}`},
		{"too many reasons", `{"risk_level":"low","reasons":["none","none","none","none","none","none"],"summary":"ok"}`},
		{"oversized summary", `{"risk_level":"low","reasons":[],"summary":"` + long + `"}`},
		{"control character", "{\"risk_level\":\"low\",\"reasons\":[],\"summary\":\"a\\u0007b\"}"},
		{"two values", `{"risk_level":"low","reasons":[],"summary":"ok"}{"risk_level":"high"}`},
		{"not json", `the login looks fine`},
		{"empty", ``},
		{"array", `[]`},
	}
	for _, c := range cases {
		if _, err := ParseAdvice([]byte(c.raw)); !IsRefusedAdvice(err) {
			t.Errorf("%s: %v, want a refusal", c.name, err)
		}
	}

	advice, err := ParseAdvice([]byte(`{"risk_level":"medium","reasons":["new_device","unusual_hour"],"summary":"New device at night."}`))
	if err != nil || advice.Level != LevelMedium || len(advice.Reasons.Names()) != 2 || advice.Summary != "New device at night." {
		t.Fatalf("a good advice: %+v, %v", advice, err)
	}

	if _, err := ParseAdvice([]byte("{" + strings.Repeat(" ", MaxAdviceBytes) + "}")); !IsRefusedAdvice(err) {
		t.Fatalf("an oversized response: %v, want a refusal", err)
	}
}

func TestHostileOutputCannotLowerRisk(t *testing.T) {
	engine := &Engine{
		Advisor: &MockAdvisor{
			Raw: []byte(`{"risk_level":"low","reasons":["none"],"summary":"all good","override":"allow"}`),
		},
		Timeout: time.Second,
		Logger:  quiet,
	}

	outcome := engine.Decide(context.Background(), Summary{Signals: Signals(0).With(SignalNewDevice | SignalUnusualHour)})
	if outcome.Decision != DecisionLimit || outcome.Advised() {
		t.Fatalf("hostile output on a medium login: %s advised %v, want limit", outcome.Decision, outcome.Advised())
	}
}

func TestParseAdviceAcceptsSharedAddress(t *testing.T) {
	advice, err := ParseAdvice([]byte(`{"risk_level":"medium","reasons":["shared_address"],"summary":"Many users from one address."}`))
	if err != nil {
		t.Fatal(err)
	}

	if advice.Reasons != ReasonSharedAddress {
		t.Errorf("reasons %v, want [shared_address]", advice.Reasons.Names())
	}
}

func TestReasonsRoundTripThroughTheirNames(t *testing.T) {
	var set Reasons
	for _, name := range []string{"new_device", "shared_address", "none"} {
		reason, ok := ParseReason(name)
		if !ok {
			t.Fatalf("%q is not a reason", name)
		}

		set |= reason
	}

	if got := set.Names(); len(got) != 3 || got[0] != "new_device" || got[2] != "none" {
		t.Fatalf("names %v", got)
	}

	if _, ok := ParseReason("made_up"); ok {
		t.Fatal("an unknown name must not parse")
	}
}
