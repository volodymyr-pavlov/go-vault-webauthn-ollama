package ai

import (
	"testing"
	"unicode/utf8"
)

// FuzzParseAdvice feeds arbitrary bytes to [ParseAdvice]. Model output is untrusted, so the parser must never panic
// and every advice it accepts must stay within the documented limits.
func FuzzParseAdvice(f *testing.F) {
	f.Add([]byte(`{"risk_level":"low","reasons":[],"summary":"ok"}`))
	f.Add([]byte(`{"risk_level":"high","reasons":["new_device","unusual_hour"],"summary":"A new device at night."}`))
	f.Add([]byte(`{"risk_level":"low","reasons":[],"summary":"ok","approve":true}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Add([]byte(`{"risk_level":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		advice, err := ParseAdvice(raw)
		if err != nil {
			if !IsRefusedAdvice(err) {
				t.Fatalf("an error that is not a refusal: %v", err)
			}

			return
		}

		if advice.Level < LevelLow || advice.Level > LevelHigh {
			t.Fatalf("accepted level %d", advice.Level)
		}

		if len(advice.Reasons.Names()) > 5 {
			t.Fatalf("accepted %d reasons", len(advice.Reasons.Names()))
		}

		if utf8.RuneCountInString(advice.Summary) > MaxSummaryText || !utf8.ValidString(advice.Summary) {
			t.Fatalf("accepted summary %q", advice.Summary)
		}
	})
}
