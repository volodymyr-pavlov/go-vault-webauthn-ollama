package metrics

import (
	"context"
	"errors"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

var _ es.Reader[ai.Consultation] = &Advisor{}

// Advisor is an [es.Reader] of [ai.Consultation] that counts the result of every question and passes the question to
// the advisor that it wraps.
type Advisor struct {
	// Next is the advisor that answers.
	Next es.Reader[ai.Consultation]

	// Metrics receives the counts. It may be nil.
	Metrics *Metrics
}

// ReadOne implements [es.Reader]. It asks Next and counts the result: advice, a refused answer, a timeout, an open
// breaker or another error.
func (a *Advisor) ReadOne(ctx context.Context, item ai.Consultation, op es.Op) (ai.Consultation, error) {
	answer, err := a.Next.ReadOne(ctx, item, op)
	a.Metrics.Advisor(advisorOutcome(err))

	return answer, err
}

// advisorOutcome returns the label for the error of the advisor.
func advisorOutcome(err error) string {
	switch {
	case err == nil:
		return OutcomeAdvice
	case ai.IsRefusedAdvice(err):
		return OutcomeRefused
	case errors.Is(err, ai.ErrBreakerOpen):
		return OutcomeBreakerOpen
	case errors.Is(err, context.DeadlineExceeded):
		return OutcomeTimeout
	}

	return OutcomeError
}
