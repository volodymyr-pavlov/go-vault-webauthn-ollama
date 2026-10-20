package ai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// fakeOllama is an HTTP handler that imitates Ollama. It lists one model at the tags endpoint and answers the
// generate endpoint with response after delay.
type fakeOllama struct {
	response string
	delay    time.Duration
	status   int
	prompts  atomic.Int32
	last     atomic.Pointer[generateRequest]
}

func (f *fakeOllama) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/tags":
		err := json.NewEncoder(w).Encode(tagsResponse{
			Models: []tagModel{{
				Name:   "llama3.2:3b",
				Digest: "abc",
			}},
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	case "/api/generate":
		f.prompts.Add(1)
		var request generateRequest

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		f.last.Store(&request)
		time.Sleep(f.delay)

		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}

		if err := json.NewEncoder(w).Encode(generateResponse{
			Response: f.response,
			Done:     true,
		}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestCheckDigest(t *testing.T) {
	server := httptest.NewServer(&fakeOllama{})
	defer server.Close()
	ctx := context.Background()
	client := New(Options{
		URL:    server.URL,
		Model:  "llama3.2:3b",
		Digest: "abc",
	})

	if err := client.Check(ctx); err != nil {
		t.Fatal(err)
	}

	client = New(Options{
		URL:    server.URL,
		Model:  "llama3.2:3b",
		Digest: "other",
	})

	if err := client.Check(ctx); !errors.Is(err, ErrModel) {
		t.Fatalf("a wrong digest: %v, want ErrModel", err)
	}

	client = New(Options{
		URL:    server.URL,
		Model:  "phi3",
		Digest: "abc",
	})

	if err := client.Check(ctx); !errors.Is(err, ErrModel) {
		t.Fatalf("a missing model: %v, want ErrModel", err)
	}
}

func TestReadOneParsesAndMinimizes(t *testing.T) {
	fake := &fakeOllama{
		response: `{"risk_level":"medium","reasons":["new_device"],"summary":"New device."}`,
	}
	server := httptest.NewServer(fake)
	defer server.Close()
	client := New(Options{
		URL:   server.URL,
		Model: "llama3.2:3b",
	})
	consultation, err := client.ReadOne(context.Background(), Consultation{
		Summary: Summary{
			Pseudonym:  "3f9a",
			Country:    "DE",
			HourBucket: "00-04",
			Factor:     es.FactorPasskey,
			Signals:    Signals(0).With(SignalNewDevice),
			Score:      25,
			Level:      "low",
		},
	}, 0)

	advice := consultation.Advice
	if err != nil || advice.Level != LevelMedium || len(advice.Reasons.Names()) != 1 {
		t.Fatalf("advice: %+v, %v", advice, err)
	}

	request := fake.last.Load()
	if request == nil || request.Stream || request.Options.Temperature != 0 || request.Options.NumPredict != MaxPredict {
		t.Fatalf("request: %+v", request)
	}

	if !strings.Contains(request.Prompt, "3f9a") || !strings.Contains(request.Prompt, "country: DE") || strings.Contains(request.Prompt, "@") {
		t.Fatalf("prompt: %s", request.Prompt)
	}

	if !strings.Contains(string(request.Format), `"additionalProperties":false`) {
		t.Fatalf("format: %s", request.Format)
	}
}

func TestReadOneRefusesHostileResponse(t *testing.T) {
	server := httptest.NewServer(&fakeOllama{
		response: `{"risk_level":"low","reasons":[],"summary":"ok","approve":true}`,
	})
	defer server.Close()
	client := New(Options{
		URL:   server.URL,
		Model: "llama3.2:3b",
	})

	if _, err := client.ReadOne(context.Background(), Consultation{}, 0); !IsRefusedAdvice(err) {
		t.Fatalf("hostile response: %v, want a refusal", err)
	}
}

func TestTimeoutOpensBreaker(t *testing.T) {
	fake := &fakeOllama{
		response: `{"risk_level":"low","reasons":[],"summary":"ok"}`,
		delay:    200 * time.Millisecond,
	}
	server := httptest.NewServer(fake)
	defer server.Close()
	client := New(Options{
		URL:        server.URL,
		Model:      "llama3.2:3b",
		Timeout:    20 * time.Millisecond,
		BreakAfter: 2,
		BreakFor:   time.Hour,
	})
	for i := range 2 {
		if _, err := client.ReadOne(context.Background(), Consultation{}, 0); err == nil || errors.Is(err, ErrBreakerOpen) {
			t.Fatalf("attempt %d: %v, want a timeout", i, err)
		}
	}

	if _, err := client.ReadOne(context.Background(), Consultation{}, 0); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("after the failures: %v, want ErrBreakerOpen", err)
	}

	if fake.prompts.Load() != 2 {
		t.Fatalf("an open breaker must not ask: %d prompts", fake.prompts.Load())
	}
}

func TestCancelledRequestDoesNotOpenBreaker(t *testing.T) {
	fake := &fakeOllama{
		response: `{"risk_level":"low","reasons":[],"summary":"ok"}`,
		delay:    200 * time.Millisecond,
	}
	server := httptest.NewServer(fake)
	defer server.Close()
	client := New(Options{
		URL:        server.URL,
		Model:      "llama3.2:3b",
		Timeout:    time.Second,
		BreakAfter: 1,
		BreakFor:   time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := client.ReadOne(ctx, Consultation{}, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request: %v, want context.Canceled", err)
	}

	if _, err := client.ReadOne(context.Background(), Consultation{}, 0); errors.Is(err, ErrBreakerOpen) {
		t.Fatal("a cancelled request must not open the breaker")
	}
}

func TestConcurrencyCap(t *testing.T) {
	fake := &fakeOllama{
		response: `{"risk_level":"low","reasons":[],"summary":"ok"}`,
		delay:    100 * time.Millisecond,
	}
	server := httptest.NewServer(fake)
	defer server.Close()
	client := New(Options{
		URL:         server.URL,
		Model:       "llama3.2:3b",
		Concurrency: 1,
	})
	done := make(chan error, 1)
	go func() {
		_, err := client.ReadOne(context.Background(), Consultation{}, 0)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)

	if _, err := client.ReadOne(context.Background(), Consultation{}, 0); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second request with one slot: %v, want ErrBusy", err)
	}

	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
