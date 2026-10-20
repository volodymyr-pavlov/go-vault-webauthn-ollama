package ai

import (
	"context"
	"log/slog"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

const (
	// FailureWindow is the period before an attempt in which failed attempts of the user or of the address count.
	FailureWindow = 10 * time.Minute

	// RecentCredential is the period after the enrollment of a factor in which the factor counts as new.
	RecentCredential = 24 * time.Hour

	// ImpossibleSpeedKmh is the speed in kilometres per hour above which a move between two logins counts as impossible
	// travel.
	ImpossibleSpeedKmh = 1000

	// SharedAddressUsers is the number of different users that must have tried to log in from one address within
	// [SharedAddressWindow] for the address to count as shared.
	SharedAddressUsers = 5

	// SharedAddressWindow is the period before an attempt in which the users that tried to log in from the address
	// are counted.
	SharedAddressWindow = time.Hour

	// MaxSummaryText is the length limit of the summary in an [Advice], in characters.
	MaxSummaryText = 200
)

// Level is a band of the risk score. [LevelOf] maps a score to its Level.
type Level uint8

const (
	// LevelLow is a score below 30. It is an ordinary login.
	LevelLow Level = iota + 1

	// LevelMedium is a score from 30 to 69. The session is limited until the user authenticates again.
	LevelMedium

	// LevelHigh is a score of 70 or more. The login is refused.
	LevelHigh
)

// LevelOf returns the [Level] of score.
func LevelOf(score uint8) Level {
	switch {
	case score >= 70:
		return LevelHigh
	case score >= 30:
		return LevelMedium
	}

	return LevelLow
}

// String returns the name of the level: "low", "medium" or "high". It returns "unknown" for any other value.
func (l Level) String() string {
	switch l {
	case LevelLow:
		return "low"
	case LevelMedium:
		return "medium"
	case LevelHigh:
		return "high"
	}

	return "unknown"
}

// Decision is what the service does with a login after the risk check.
type Decision uint8

const (
	// DecisionAllow authorizes the session without limits.
	DecisionAllow Decision = iota + 1

	// DecisionLimit authorizes the session, but a sensitive action needs a fresh authentication first.
	DecisionLimit

	// DecisionReview limits the session like [DecisionLimit] and flags the login for a person to review.
	DecisionReview

	// DecisionDeny refuses the login.
	DecisionDeny
)

// String returns the name of the decision: "allow", "limit", "review" or "deny". It returns "unknown" for any other
// value.
func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionLimit:
		return "limit"
	case DecisionReview:
		return "review"
	case DecisionDeny:
		return "deny"
	}

	return "unknown"
}

// Summary is the reduced view of a login attempt that the advisor sees. It has a pseudonym instead of the user and
// coarse values instead of raw ones. It has no text that a user could have typed.
type Summary struct {
	// Pseudonym is a keyed hash of the user, in hex. It lets the advisor see that two attempts come from one user, and
	// nothing more.
	Pseudonym string `json:"pseudonym"`

	// Country is the ISO 3166-1 alpha-2 code of the country that the attempt comes from, or "unknown".
	Country string `json:"country"`

	// HourBucket is the time of the attempt in a four-hour bucket of the UTC day, such as "00-04" or "04-08".
	HourBucket string `json:"hour_bucket"`

	// Factor is the set of factors that passed: a passkey, or a password with a code of the authenticator app. The JSON
	// and the prompt show the names joined by a plus sign.
	Factor es.Factors `json:"factor"`

	// Signals are the signals that the rules scored.
	Signals Signals `json:"signals"`

	// Score and Level are the result of the rules. The model may confirm the level or argue for a higher one, but it
	// cannot lower it.
	Score uint8  `json:"score"`
	Level string `json:"level"`
}

// Reasons is a set of the reasons that an [Advice] may give, one bit for each. The set is closed: [ParseAdvice] refuses
// any other value.
type Reasons uint8

// The reasons that the model may give. Each one matches a [Signal] or the failed attempts of [Signals]. ReasonNone means
// that the model sees no reason for concern.
const (
	ReasonNewDevice Reasons = 1 << iota
	ReasonRecentEnrollment
	ReasonFailedAttempts
	ReasonUnusualHour
	ReasonImpossibleTravel
	ReasonSharedAddress
	ReasonNone
)

// reasonNames are the names of the reasons in bit order. They are also the values that the model writes in its answer.
var reasonNames = [...]string{
	"new_device",
	"recent_enrollment",
	"failed_attempts",
	"unusual_hour",
	"impossible_travel",
	"shared_address",
	"none",
}

// ParseReason returns the reason that the name stands for. It reports false for a name outside the closed set.
func ParseReason(name string) (Reasons, bool) {
	for bit, known := range reasonNames {
		if known == name {
			return 1 << bit, true
		}
	}

	return 0, false
}

// Has reports whether every reason of mask is in the set.
func (r Reasons) Has(mask Reasons) bool {
	return r&mask == mask
}

// Names returns the names of the reasons in the set, in bit order.
func (r Reasons) Names() []string {
	var names []string
	for bit, name := range reasonNames {
		if r&(1<<bit) != 0 {
			names = append(names, name)
		}
	}

	return names
}

// Advice is the answer of the advisor after the strict check of [ParseAdvice].
type Advice struct {
	// Level is the risk level that the advisor sees.
	Level Level

	// Reasons are the reasons for the level. They come from the closed set of [Reasons] bits.
	Reasons Reasons

	// Summary is a short text for the person who reviews the login.
	Summary string
}

// Consultation is a question to the advisor and its answer. An [es.Reader] of Consultation takes one with Summary set
// and returns it with Advice set.
type Consultation struct {
	// Summary is the question.
	Summary Summary

	// Advice is the answer. The advisor sets it.
	Advice Advice
}

// Engine turns the signals of a login into a [Decision]. [Engine.Decide] does the work.
type Engine struct {
	// Advisor is the model that advises the rules. If it is nil, the rules alone decide. The server sets it to the
	// Ollama [Client], and tests use [MockAdvisor].
	Advisor es.Reader[Consultation]

	// Timeout is the time that the advisor may take to answer. If it is zero, the advisor is not asked.
	Timeout time.Duration

	// Logger receives the log line of every decision. It must not be nil.
	Logger *slog.Logger

	// OnDecision, if it is set, receives the [Outcome] of every call of [Engine.Decide] before it returns.
	OnDecision func(Outcome)
}

// Outcome is the result of [Engine.Decide].
type Outcome struct {
	// Score and Level are the result of the rules.
	Score uint8
	Level Level

	// Decision is the final decision, after the advisor.
	Decision Decision

	// Advice is the advice that the advisor gave. It is the zero value unless [OutcomeAdvised] is set.
	Advice Advice

	// Flags tell how the decision came about, as [OutcomeFlag] bits.
	Flags OutcomeFlag
}

// OutcomeFlag is a bit of [Outcome.Flags].
type OutcomeFlag uint8

const (
	// OutcomeAdvised is set when the advisor gave a valid advice.
	OutcomeAdvised OutcomeFlag = 1 << iota

	// OutcomeRaised is set when the advice raised the decision by one step.
	OutcomeRaised
)

// Advised reports whether the advisor gave a valid advice.
func (o Outcome) Advised() bool {
	return o.Flags&OutcomeAdvised != 0
}

// Raised reports whether the advice raised the decision by one step.
func (o Outcome) Raised() bool {
	return o.Flags&OutcomeRaised != 0
}

// Decide returns the [Outcome] for the signals in summary. The rules decide first: a low level allows, a medium level
// limits and a high level denies.
//
// If the rules do not deny, the advisor is asked. If it answers in time with a valid advice whose level is above the
// level of the rules, the decision rises by one step: allow becomes limit, and limit becomes review. The advisor never
// lowers a decision and never makes it deny. If it fails, is too slow or gives a refused answer, the rules decide
// alone.
//
// Decide logs every decision with its signals.
func (e *Engine) Decide(ctx context.Context, summary Summary) Outcome {
	score := summary.Signals.Score()
	level := LevelOf(score)
	outcome := Outcome{
		Score: score,
		Level: level,
	}
	switch level {
	case LevelHigh:
		outcome.Decision = DecisionDeny
	case LevelMedium:
		outcome.Decision = DecisionLimit
	default:
		outcome.Decision = DecisionAllow
	}

	summary.Score = score
	summary.Level = level.String()

	if e.Advisor != nil && e.Timeout > 0 && outcome.Decision != DecisionDeny {
		adviseCtx, cancel := context.WithTimeout(ctx, e.Timeout)
		consultation, err := e.Advisor.ReadOne(adviseCtx, Consultation{Summary: summary}, 0)
		advice := consultation.Advice
		cancel()

		if err != nil {
			e.Logger.Warn("the risk advisor gave no advice", "error", err.Error())
		} else {
			outcome.Advice = advice
			outcome.Flags |= OutcomeAdvised

			if advice.Level > level {
				outcome.Flags |= OutcomeRaised

				if outcome.Decision == DecisionAllow {
					outcome.Decision = DecisionLimit
				} else {
					outcome.Decision = DecisionReview
				}
			}
		}
	}

	e.Logger.Info("risk decision",
		"pseudonym", summary.Pseudonym,
		"score", score,
		"level", level.String(),
		"decision", outcome.Decision.String(),
		"raised", outcome.Raised(),
		"signals", summary.Signals.List(),
		"failed_attempts", summary.Signals.FailedAttempts(),
		"totp_failures", summary.Signals.TOTPFailures(),
	)

	if e.OnDecision != nil {
		e.OnDecision(outcome)
	}

	return outcome
}
