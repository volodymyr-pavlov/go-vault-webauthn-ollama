package ai

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"

	"github.com/tidwall/gjson"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

var _ es.Reader[Consultation] = &MockAdvisor{}

// MaxAdviceBytes is the length limit of a raw response, in bytes. [ParseAdvice] refuses a longer response before it
// reads it.
const MaxAdviceBytes = 4 << 10

// rawAdvice is the JSON object that the model must return. [ParseAdvice] refuses an object with any other field.
type rawAdvice struct {
	Level   string   `json:"risk_level"`
	Reasons []string `json:"reasons"`
	Summary string   `json:"summary"`
}

// ParseAdvice checks the raw response of the model and returns it as an [Advice].
//
// The response must be one JSON object of at most [MaxAdviceBytes] bytes. It may have only the fields risk_level,
// reasons and summary. The level must be low, medium or high. Each reason must be one of the closed set of [Reasons], and
// there may be at most five. The summary must be valid UTF-8 text of at most [MaxSummaryText] characters, without
// control characters.
//
// It returns [ErrAdvice], wrapped with the cause, if the response breaks one of these rules.
func ParseAdvice(raw []byte) (Advice, error) {
	if len(raw) > MaxAdviceBytes {
		return Advice{}, fmt.Errorf("%w: %d bytes", ErrAdvice, len(raw))
	}

	if !gjson.ValidBytes(raw) {
		return Advice{}, fmt.Errorf("%w: %w", ErrAdvice, ErrInvalidJSON)
	}

	root := gjson.ParseBytes(raw)
	if !root.IsObject() {
		return Advice{}, fmt.Errorf("%w: not an object", ErrAdvice)
	}

	var parsed rawAdvice
	var failure error
	root.ForEach(func(key, member gjson.Result) bool {
		switch key.String() {
		case "risk_level":
			if member.Type != gjson.String {
				failure = fmt.Errorf("%w: risk_level is not a string", ErrAdvice)
				return false
			}

			parsed.Level = member.String()
		case "reasons":
			if !member.IsArray() {
				failure = fmt.Errorf("%w: reasons is not an array", ErrAdvice)
				return false
			}

			for _, reason := range member.Array() {
				if reason.Type != gjson.String {
					failure = fmt.Errorf("%w: a reason is not a string", ErrAdvice)
					return false
				}

				parsed.Reasons = append(parsed.Reasons, reason.String())
			}
		case "summary":
			if member.Type != gjson.String {
				failure = fmt.Errorf("%w: summary is not a string", ErrAdvice)
				return false
			}

			parsed.Summary = member.String()
		default:
			failure = fmt.Errorf("%w: unknown field %q", ErrAdvice, key.String())
			return false
		}

		return true
	})

	if failure != nil {
		return Advice{}, failure
	}

	advice := Advice{
		Summary: parsed.Summary,
	}
	switch parsed.Level {
	case "low":
		advice.Level = LevelLow
	case "medium":
		advice.Level = LevelMedium
	case "high":
		advice.Level = LevelHigh
	default:
		return Advice{}, fmt.Errorf("%w: risk_level %q", ErrAdvice, parsed.Level)
	}

	if len(parsed.Reasons) > 5 {
		return Advice{}, fmt.Errorf("%w: %d reasons", ErrAdvice, len(parsed.Reasons))
	}

	for _, name := range parsed.Reasons {
		reason, ok := ParseReason(name)
		if !ok {
			return Advice{}, fmt.Errorf("%w: reason %q", ErrAdvice, name)
		}

		advice.Reasons |= reason
	}

	if !utf8.ValidString(parsed.Summary) || utf8.RuneCountInString(parsed.Summary) > MaxSummaryText {
		return Advice{}, fmt.Errorf("%w: summary of %d bytes", ErrAdvice, len(parsed.Summary))
	}

	for _, r := range parsed.Summary {
		if r < ' ' {
			return Advice{}, fmt.Errorf("%w: control character in the summary", ErrAdvice)
		}
	}

	return advice, nil
}

// MockAdvisor is an [es.Reader] of [Consultation] that returns a fixed advice or a fixed error. It is for tests only.
// The server command has no option to use it.
type MockAdvisor struct {
	// Advice is the advice that ReadOne returns.
	Advice Advice

	// Err is the error that ReadOne returns. If it is set, ReadOne returns no advice.
	Err error

	// Raw is a raw response of a model. If it is set, ReadOne parses it with [ParseAdvice] and returns the result
	// instead of Advice. A test can use it to pass hostile output through the same check as the output of a real
	// model.
	Raw []byte

	mu   sync.Mutex
	last Summary
}

// Last returns the [Summary] of the last item that ReadOne received. It is safe to call while requests run.
func (m *MockAdvisor) Last() Summary {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.last
}

// ReadOne implements [es.Reader]. It records the summary of item for [MockAdvisor.Last] and returns item with the configured Advice
// set.
//
// It returns Err if Err is set. It returns the error of [ParseAdvice] if Raw is set and the response is refused.
func (m *MockAdvisor) ReadOne(_ context.Context, item Consultation, _ es.Op) (Consultation, error) {
	m.mu.Lock()
	m.last = item.Summary
	m.mu.Unlock()

	if m.Err != nil {
		return item, m.Err
	}

	if m.Raw != nil {
		advice, err := ParseAdvice(m.Raw)
		item.Advice = advice
		return item, err
	}

	item.Advice = m.Advice
	return item, nil
}

// IsRefusedAdvice reports whether err means that the advisor answered but [ParseAdvice] refused the answer. It reports
// false if the advisor failed in another way.
func IsRefusedAdvice(err error) bool {
	return errors.Is(err, ErrAdvice)
}
