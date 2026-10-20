// Package ai is the risk engine of the service. It scores each login with fixed rules and asks a local model for a
// second opinion.
//
// The rules turn the [Signals] of a login into a score from 0 to 100 and a [Level]. The [Engine] turns the level into
// a [Decision]. The model reads a reduced [Summary] of the attempt and returns an [Advice]. It can raise the decision
// by one step. It never lowers the decision and never approves a login that the rules refuse. If the model fails, is
// slow or gives a refused answer, the rules decide alone. [ParseAdvice] is the strict check that every answer passes.
//
// Ollama is a required part of the risk checks: the server does not start without it. [MockAdvisor] replaces the
// model in tests only.
//
// [Client] asks the model through LangChain: a prompt template and a chain over the Ollama model of langchaingo. Ollama
// has no authentication of its own, so the client treats it as an unauthenticated dependency. The client checks the digest of the model at startup and limits the size
// of what it reads. It runs only a few requests at once, gives up after a timeout, and stops asking for a while after
// repeated failures. It never logs a prompt or a raw response.
package ai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tmc/langchaingo/chains"
	"github.com/tmc/langchaingo/llms/ollama"
	"github.com/tmc/langchaingo/prompts"
	"github.com/valyala/bytebufferpool"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

var _ es.Reader[Consultation] = &Client{}

const (
	// DefaultTimeout is the default time that one request may take, and DefaultConcurrency is the default number of
	// requests that may run at once.
	DefaultTimeout     = 8 * time.Second
	DefaultConcurrency = 2

	// DefaultBreakAfter is the default number of failures in a row that opens the circuit breaker, and DefaultBreakFor
	// is the default time that the breaker stays open.
	DefaultBreakAfter = 3
	DefaultBreakFor   = 30 * time.Second

	// MaxResponseBytes is the length limit of a response from Ollama that the client reads, in bytes.
	MaxResponseBytes = 64 << 10

	// MaxPredict is the limit of tokens that the model may write in one answer.
	MaxPredict = 160
)

// promptTemplate is the fixed LangChain template of the request to the model. It has only typed and coarse values. It
// has no text that a user typed.
const promptTemplate = `You are a login risk analyst for a financial service.
Rules already scored this login {{.score}}/100, level {{.level}}. Your analysis may only confirm the level or argue
for a higher one; a lower level is ignored.

Login facts (coarse, pseudonymous):
- user pseudonym: {{.pseudonym}}
- country: {{.country}}
- hour of day (UTC bucket): {{.hour_bucket}}
- factor that passed: {{.factor}}
- signals that are set: {{.signals}}
- failed attempts in the last 10 minutes (5 means five or more): {{.failed_attempts}}
- wrong codes since the last good one (3 means three or more): {{.totp_failures}}

The signals mean: new_device = the user logged in before, but not from this device; recent_enrollment = a factor
was enrolled in the last day; unusual_hour = the hour is far from the hours of the earlier logins; impossible_travel =
the move from the last login place is too fast; shared_address = five or more users tried this address in the last
hour.

Answer with one JSON object and nothing else, with exactly these fields:
{"risk_level": "low" | "medium" | "high", "reasons": [zero to five of "new_device", "recent_enrollment", "failed_attempts", "unusual_hour", "impossible_travel", "shared_address", "none"], "summary": "one sentence under 200 characters"}
`

// promptVariables are the variables of [promptTemplate].
var promptVariables = []string{
	"score",
	"level",
	"pseudonym",
	"country",
	"hour_bucket",
	"factor",
	"signals",
	"failed_attempts",
	"totp_failures",
}

// tagsResponse is the response of the tags endpoint of Ollama.
type tagsResponse struct {
	Models []tagModel `json:"models"`
}

// tagModel is one model in a [tagsResponse].
type tagModel struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// limitedTransport reads at most [MaxResponseBytes] of a response body, so a hostile or broken server cannot make the
// client read without end.
type limitedTransport struct {
	next http.RoundTripper
}

// RoundTrip implements [http.RoundTripper].
func (t limitedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}

	response.Body = limitedBody{
		Reader: io.LimitReader(response.Body, MaxResponseBytes),
		Closer: response.Body,
	}

	return response, nil
}

// limitedBody is a response body that stops reading at a limit.
type limitedBody struct {
	io.Reader
	io.Closer
}

// Options are the settings of a [Client]. A zero value of a limit means the default.
type Options struct {
	// URL is the base URL of Ollama, such as http://ollama:11434.
	URL string

	// Model is the name and tag of the model, such as llama3.2:3b. Digest is the digest that the model must have, as
	// the tags list of Ollama shows it. [Client.Check] refuses a model with any other digest.
	Model  string
	Digest string

	// Timeout is the time that one request may take, and Concurrency is the number of requests that may run at once.
	// BreakAfter is the number of failures in a row that opens the circuit breaker, and BreakFor is the time that the
	// breaker stays open.
	Timeout     time.Duration
	Concurrency int
	BreakAfter  int
	BreakFor    time.Duration

	// Seed is the sampling seed. It makes the answers repeatable if the model supports it.
	Seed int

	// HTTP is the HTTP client to use. If it is nil, [New] builds one that uses Timeout.
	HTTP *http.Client
}

// Client asks one model of one Ollama server for [Advice]. It implements [es.Reader] of [Consultation]. [New] builds
// it.
type Client struct {
	url        string
	model      string
	digest     string
	timeout    time.Duration
	breakAfter int
	breakFor   time.Duration
	seed       int
	http       *http.Client
	chain      *chains.LLMChain
	slots      chan struct{}
	failures   atomic.Int32
	openedAt   atomic.Int64
}

// New returns a [Client] that uses opts. It returns an error if the URL of Ollama cannot be used.
func New(opts Options) (*Client, error) {
	c := &Client{
		url:        strings.TrimSuffix(opts.URL, "/"),
		model:      opts.Model,
		digest:     opts.Digest,
		timeout:    opts.Timeout,
		breakAfter: opts.BreakAfter,
		breakFor:   opts.BreakFor,
		seed:       opts.Seed,
		http:       opts.HTTP,
	}
	if c.timeout == 0 {
		c.timeout = DefaultTimeout
	}

	if c.breakAfter == 0 {
		c.breakAfter = DefaultBreakAfter
	}

	if c.breakFor == 0 {
		c.breakFor = DefaultBreakFor
	}

	concurrency := opts.Concurrency
	if concurrency == 0 {
		concurrency = DefaultConcurrency
	}

	c.slots = make(chan struct{}, concurrency)

	if c.http == nil {
		c.http = &http.Client{
			Timeout: c.timeout,
		}
	}

	transport := c.http.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	limited := *c.http
	limited.Transport = limitedTransport{next: transport}

	model, err := ollama.New(
		ollama.WithModel(c.model),
		ollama.WithServerURL(c.url),
		ollama.WithFormat("json"),
		ollama.WithHTTPClient(&limited),
	)
	if err != nil {
		return nil, fmt.Errorf("build the model: %w", err)
	}

	c.chain = chains.NewLLMChain(model, prompts.NewPromptTemplate(promptTemplate, promptVariables))

	return c, nil
}

// Check reads the tags of Ollama and returns nil if the model is there with the expected digest. The server calls it
// at startup.
//
// It returns [ErrModel] if the model is missing or has another digest. It returns an error wrapping [ErrStatus] if
// Ollama answers with another status than 200, and an error wrapping [ErrInvalidJSON] if the answer is not valid JSON.
func (c *Client) Check(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/api/tags", nil)
	if err != nil {
		return fmt.Errorf("build the tags request: %w", err)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("read the tags: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("read the tags: %w: status %d", ErrStatus, response.StatusCode)
	}

	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)

	if _, err = buf.ReadFrom(io.LimitReader(response.Body, MaxResponseBytes)); err != nil {
		return fmt.Errorf("read the tags: %w", err)
	}

	tags := buf.B

	if !gjson.ValidBytes(tags) {
		return fmt.Errorf("decode the tags: %w", ErrInvalidJSON)
	}

	for _, model := range gjson.GetBytes(tags, "models").Array() {
		name := model.Get("name").String()
		digest := model.Get("digest").String()
		if name == c.model && digest == c.digest {
			return nil
		}

		if name == c.model {
			return fmt.Errorf("%w: %s has digest %s, want %s", ErrModel, c.model, digest, c.digest)
		}
	}

	return fmt.Errorf("%w: %s is not pulled", ErrModel, c.model)
}

// ReadOne implements [es.Reader]. It asks the model about the Summary of item and returns item with the Advice set.
//
// It returns [ErrBreakerOpen] while the circuit breaker is open and [ErrBusy] when all request slots are in use. It
// returns an error wrapping [ErrAdvice] if the answer does not pass [ParseAdvice]. It returns another error if the
// request fails, including an error wrapping [ErrStatus] if Ollama answers with another status than 200.
//
// A failed request counts toward the circuit breaker. A refused answer does not.
func (c *Client) ReadOne(ctx context.Context, item Consultation, _ es.Op) (Consultation, error) {
	if opened := c.openedAt.Load(); opened != 0 {
		if time.Since(time.Unix(0, opened)) < c.breakFor {
			return item, ErrBreakerOpen
		}

		c.openedAt.Store(0)
		c.failures.Store(0)
	}

	select {
	case c.slots <- struct{}{}:
	default:
		return item, ErrBusy
	}
	defer func() { <-c.slots }()

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	summary := item.Summary
	options := []chains.ChainCallOption{
		chains.WithTemperature(0),
		chains.WithMaxTokens(MaxPredict),
	}
	if c.seed != 0 {
		options = append(options, chains.WithSeed(c.seed))
	}

	answer, err := chains.Predict(ctx, c.chain, map[string]any{
		"score":           summary.Score,
		"level":           summary.Level,
		"pseudonym":       summary.Pseudonym,
		"country":         summary.Country,
		"hour_bucket":     summary.HourBucket,
		"factor":          summary.Factor,
		"signals":         summary.Signals.List(),
		"failed_attempts": summary.Signals.FailedAttempts(),
		"totp_failures":   summary.Signals.TOTPFailures(),
	}, options...)
	if err != nil {
		c.recordFailure(err)

		return item, fmt.Errorf("ask the model: %w", err)
	}

	c.failures.Store(0)
	advice, err := ParseAdvice([]byte(answer))
	item.Advice = advice
	return item, err
}

// recordFailure counts a failed request toward the circuit breaker and opens the breaker when the count reaches the
// limit. A request that the caller cancelled does not count, because it says nothing about the health of Ollama.
func (c *Client) recordFailure(err error) {
	if errors.Is(err, context.Canceled) {
		return
	}

	if int(c.failures.Add(1)) >= c.breakAfter {
		c.openedAt.Store(time.Now().UnixNano())
	}
}
