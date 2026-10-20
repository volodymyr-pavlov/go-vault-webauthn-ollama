//go:build integration

package server

// The fault tests break one dependency of the service at a time (Vault, Redis, Ollama, MySQL) and check that the
// service fails closed: it refuses the request, grants nothing and tells the caller nothing about the cause. They also
// check concurrent use: a replayed request and parallel logins.
//
// Run only the fault tests with:
//
//	go test -tags integration -race -count=1 -run Fault ./server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tidwall/gjson"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/authtest"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// leaks lists words that must never appear in a response body, because they name an internal dependency or a Go
// failure.
var leaks = []string{"vault", "redis", "mysql", "sql", "ollama", "dial", "refused", "connection", "127.0.0.1", "panic", "goroutine", "tcp", "closed"}

// reply is one response of the service, read without failing the test, so that goroutines can use it.
type reply struct {
	Status int
	Body   []byte
	Code   string
}

// try sends a request signed with the key of the device handle, like [stand.call], but it returns an error instead of
// failing the test. It is safe to call from a goroutine if the stand does not open devices at the same time.
func (s *stand) try(method, path, handle string, body any) (reply, error) {
	var encoded []byte
	if body != nil {
		var err error
		if encoded, err = json.Marshal(body); err != nil {
			return reply{}, err
		}
	}

	key, ok := s.devices[handle]
	if !ok {
		return reply{}, fmt.Errorf("no device %q", handle)
	}

	return s.trySigned(method, path, encoded, handle, func(request *http.Request) {
		s.sign(request, encoded, key, s.clock.Now().Unix(), s.nextNonce(), s.tags[handle])
	})
}

// trySigned builds a request, lets sign sign it and sends it.
func (s *stand) trySigned(method, path string, body []byte, _ string, sign func(*http.Request)) (reply, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	request, err := http.NewRequest(method, "http://inmemory"+path, reader)
	if err != nil {
		return reply{}, err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", testOrigin)
	sign(request)

	response, err := s.client.Do(request)
	if err != nil {
		return reply{}, err
	}
	defer response.Body.Close()

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return reply{}, err
	}

	return reply{
		Status: response.StatusCode,
		Body:   raw,
		Code:   gjson.GetBytes(raw, "error.code").String(),
	}, nil
}

// closed fails the test unless r is a refusal that leaks nothing: a non-2xx status with an error envelope, and a body
// without the name of any dependency.
func closed(t *testing.T, what string, r reply) {
	t.Helper()

	if r.Status >= 200 && r.Status < 300 {
		t.Fatalf("%s: the request must fail closed, got %d %s", what, r.Status, r.Body)
	}

	if r.Code == "" {
		t.Fatalf("%s: a refusal must carry an error code: %d %s", what, r.Status, r.Body)
	}

	body := strings.ToLower(string(r.Body))
	for _, word := range leaks {
		if strings.Contains(body, word) {
			t.Fatalf("%s: the body leaks %q: %s", what, word, r.Body)
		}
	}

	if r.Status == http.StatusInternalServerError && r.Code != "INTERNAL" {
		t.Fatalf("%s: a 500 must be the generic error: %s", what, r.Body)
	}
}

// sessionFlags reads the flags that the database holds for the session.
func (s *stand) sessionFlags(d device) es.SessionFlag {
	s.t.Helper()

	session, err := s.env.SessionReader.ReadOne(context.Background(), es.Session{SessionXID: d.SessionXID}, 0)
	if err != nil {
		s.t.Fatal(err)
	}

	return session.Flags
}

// TestFaultVaultDown proves that a login with a one-time code and a new registration fail closed while Vault is down,
// that the session gains no authorization from a failed attempt, and that the caller sees no detail of the outage. Vault
// holds the keys that open the TOTP secret, so a service that granted access without it would accept any code.
func TestFaultVaultDown(t *testing.T) {
	s := newStand(t)
	email := fmt.Sprintf("vault-%d@example.com", time.Now().UnixNano())
	session := s.open()
	s.register(session.Handle, email)
	secret := s.enrollTOTP(session.Handle)

	login := s.open()
	var next api.AuthorizePasswordHandlerResult
	s.decode(s.loginPassword(login.Handle, email, testPassword), &next)

	newcomer := s.open()

	s.transit.Close()

	r, err := s.try(http.MethodPost, "/v1/auth/totp", login.Handle, map[string]string{
		"code": s.code(secret),
	})
	if err != nil {
		t.Fatal(err)
	}

	closed(t, "totp login", r)

	if s.sessionFlags(login)&es.SessionFlagAuthorized != 0 {
		t.Fatal("a failed login must not authorize the session")
	}

	fresh := fmt.Sprintf("vault-new-%d@example.com", time.Now().UnixNano())
	opened, err := s.try(http.MethodPost, "/v1/register", newcomer.Handle, map[string]string{
		"email":    fresh,
		"password": testPassword,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A registration answers the same "pending" for every address, so a 202 is allowed. It must still grant nothing.
	if opened.Status != http.StatusAccepted {
		closed(t, "registration", opened)
	}

	if s.sessionFlags(newcomer)&(es.SessionFlagAuthorized|es.SessionFlagRegistryVerified) != 0 {
		t.Fatal("a registration during the outage must not verify or authorize the session")
	}

	late, err := s.trySigned(http.MethodPost, "/v1/session", nil, "", func(request *http.Request) {})
	if err != nil {
		t.Fatal(err)
	}

	closed(t, "unsigned request", late)
}

// TestFaultRedisDown proves that no request passes while Redis is down, because the nonce store and the rate limiter
// need it, and that the service works again when Redis is back. Without the nonce store a captured request could be
// replayed, and without the limiter an attacker could guess without limit.
func TestFaultRedisDown(t *testing.T) {
	s := newStand(t)
	session := s.open()

	s.redis.Close()

	r, err := s.try(http.MethodGet, "/v1/session", session.Handle, nil)
	if err != nil {
		t.Fatal(err)
	}

	closed(t, "known session", r)

	key := s.devices[session.Handle]
	body := []byte(`{"device_id":"x","device_key":"AAAA"}`)
	opening, err := s.trySigned(http.MethodPost, "/v1/session", body, "", func(request *http.Request) {
		s.sign(request, body, key, s.clock.Now().Unix(), s.nextNonce(), s.tags[session.Handle])
	})
	if err != nil {
		t.Fatal(err)
	}

	closed(t, "new session", opening)

	if err := s.redis.Restart(); err != nil {
		t.Fatal(err)
	}

	again, err := s.try(http.MethodGet, "/v1/session", session.Handle, nil)
	if err != nil {
		t.Fatal(err)
	}

	if again.Status != http.StatusOK {
		t.Fatalf("the service must work again when Redis is back: %d %s", again.Status, again.Body)
	}
}

// TestFaultMySQLDown proves that a request fails closed with the generic error while the database is down. A service
// that answered from memory could accept a revoked session.
func TestFaultMySQLDown(t *testing.T) {
	s := newStand(t)
	session := s.open()

	if err := s.env.Database.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := s.try(http.MethodGet, "/v1/session", session.Handle, nil)
	if err != nil {
		t.Fatal(err)
	}

	closed(t, "known session", r)

	if r.Status != http.StatusInternalServerError || r.Code != "INTERNAL" {
		t.Fatalf("a database failure must be the generic 500: %d %s", r.Status, r.Body)
	}
}

// brokenOllama starts an Ollama stand-in that answers every request with handler. It counts the requests. The server
// stops with the test, and the release channel frees handlers that hang.
func brokenOllama(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, release <-chan struct{})) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var hits atomic.Int64
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r, release)
	}))

	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	return server, &hits
}

// TestFaultOllamaFailures proves that a login with a valid factor gets the decision of the rules alone when Ollama
// hangs, answers with an error or answers with garbage. The advice is optional: it must not block the login, must not
// loosen the decision, and must not wait longer than the timeout.
func TestFaultOllamaFailures(t *testing.T) {
	const timeout = 300 * time.Millisecond

	cases := []struct {
		name    string
		breaks  bool
		handler func(w http.ResponseWriter, r *http.Request, release <-chan struct{})
	}{
		{
			name:   "hangs",
			breaks: true,
			handler: func(_ http.ResponseWriter, r *http.Request, release <-chan struct{}) {
				select {
				case <-r.Context().Done():
				case <-release:
				}
			},
		},
		{
			name:   "status 500",
			breaks: true,
			handler: func(w http.ResponseWriter, _ *http.Request, _ <-chan struct{}) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
		},
		{
			name:   "not json",
			breaks: true,
			handler: func(w http.ResponseWriter, _ *http.Request, _ <-chan struct{}) {
				_, _ = io.WriteString(w, "<html>not json")
			},
		},
		{
			name: "hostile advice",
			handler: func(w http.ResponseWriter, _ *http.Request, _ <-chan struct{}) {
				_, _ = io.WriteString(w, `{"message":{"role":"assistant","content":"{\"risk_level\":\"low\",\"approve\":true,\"reasons\":[\"none\"]}"},"done":true}`)
			},
		},
		{
			name:   "huge answer",
			breaks: true,
			handler: func(w http.ResponseWriter, _ *http.Request, _ <-chan struct{}) {
				_, _ = io.WriteString(w, `{"message":{"role":"assistant","content":"`+strings.Repeat("a", 2*ai.MaxResponseBytes)+`"}}`)
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			s := newStand(t)
			email := fmt.Sprintf("ollama-%d@example.com", time.Now().UnixNano())
			session := s.open()
			s.register(session.Handle, email)
			authenticator := s.authenticator()
			if _, a := s.enrollPasskey(session.Handle, authenticator, "key"); a.Error != nil {
				t.Fatalf("enroll: %+v", a.Error)
			}

			// The baseline is the decision of the rules alone.
			s.env.Engine.Advisor = nil

			var baseline api.AuthorizeResult
			s.decode(s.loginPasskey(s.open().Handle, email, authenticator), &baseline)

			server, hits := brokenOllama(t, test.handler)
			advisor, err := ai.New(ai.Options{
				URL:        server.URL,
				Model:      "test",
				Timeout:    timeout,
				BreakAfter: 3,
				BreakFor:   time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}

			s.env.Engine.Advisor = advisor
			s.env.Engine.Timeout = timeout

			for i := range 5 {
				started := time.Now()

				var login api.AuthorizeResult
				s.decode(s.loginPasskey(s.open().Handle, email, authenticator), &login)

				if login.Decision != baseline.Decision || login.Flags&es.SessionFlagAuthorized != baseline.Flags&es.SessionFlagAuthorized {
					t.Fatalf("login %d: want the rules-only result %+v, got %+v", i, baseline, login)
				}

				if elapsed := time.Since(started); elapsed > 4*timeout {
					t.Fatalf("login %d took %s, the timeout is %s", i, elapsed, timeout)
				}
			}

			if n := hits.Load(); test.breaks && n > 3 {
				t.Fatalf("the breaker must stop the requests after 3 failures, Ollama got %d", n)
			}
		})
	}
}

// TestFaultReplayedRequest proves that when 20 copies of one signed request arrive at the same time, exactly one runs
// and the others are refused as replays. A race in the nonce store would let a captured request run twice.
func TestFaultReplayedRequest(t *testing.T) {
	s := newStand(t)
	session := s.open()
	key := s.devices[session.Handle]
	created := s.clock.Now().Unix()

	var ok, replays atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			r, err := s.trySigned(http.MethodGet, "/v1/session", nil, "", func(request *http.Request) {
				s.sign(request, nil, key, created, "same-nonce", s.tags[session.Handle])
			})
			switch {
			case err != nil:
				t.Error(err)
			case r.Status == http.StatusOK:
				ok.Add(1)
			case r.Status == http.StatusUnauthorized && r.Code == "INVALID_REQUEST_SIGNATURE":
				replays.Add(1)
			default:
				t.Errorf("unexpected reply: %d %s", r.Status, r.Body)
			}
		}()
	}

	close(start)
	wg.Wait()

	if ok.Load() != 1 || replays.Load() != 19 {
		t.Fatalf("want 1 success and 19 replays, got %d and %d", ok.Load(), replays.Load())
	}
}

// lockedAdvisor serializes the calls to a [ai.MockAdvisor], which records the last summary without a lock.
type lockedAdvisor struct {
	mu    sync.Mutex
	inner *ai.MockAdvisor
}

// ReadOne implements [es.Reader].
func (a *lockedAdvisor) ReadOne(ctx context.Context, item ai.Consultation, op es.Op) (ai.Consultation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.inner.ReadOne(ctx, item, op)
}

// loginSafely runs the passkey login ceremony and returns the final reply. Unlike [stand.loginPasskey] it never fails
// the test, so a goroutine can run it.
func (s *stand) loginSafely(handle, email string, authenticator *authtest.Authenticator) (reply, error) {
	begin, err := s.try(http.MethodPost, "/v1/auth/passkey", handle, map[string]string{
		"email": email,
	})
	if err != nil {
		return reply{}, err
	}

	if begin.Status != http.StatusOK {
		return begin, nil
	}

	data := []byte(gjson.GetBytes(begin.Body, "data").Raw)

	challenge, err := authtest.Challenge(data)
	if err != nil {
		return reply{}, err
	}

	response, err := authenticator.Assert(challenge, nil)
	if err != nil {
		return reply{}, err
	}

	return s.try(http.MethodPost, "/v1/auth/passkey/complete", handle, map[string]any{
		"response": json.RawMessage(response),
	})
}

// TestFaultParallelLogins proves that 20 users who log in at the same time each get their own authorized session, and
// that no session belongs to another user. Shared state in the handlers would show here as a mixed-up result.
func TestFaultParallelLogins(t *testing.T) {
	const users = 20

	s := newStand(t)
	s.env.Engine.Advisor = &lockedAdvisor{
		inner: s.advisor,
	}
	stamp := time.Now().UnixNano()

	type account struct {
		email         string
		authenticator *authtest.Authenticator
		session       device
		xid           uint64
	}

	accounts := make([]account, users)
	// Each user sets up in a new minute of the Redis clock, so the setup stays inside the budget of the rate limiter.
	base := time.Now()
	for i := range accounts {
		s.redis.SetTime(base.Add(time.Duration(i) * time.Minute))

		email := fmt.Sprintf("parallel-%d-%d@example.com", stamp, i)
		opened := s.open()
		xid := s.register(opened.Handle, email)
		authenticator := s.authenticator()
		if _, a := s.enrollPasskey(opened.Handle, authenticator, "key"); a.Error != nil {
			t.Fatalf("enroll: %+v", a.Error)
		}

		accounts[i] = account{
			email:         email,
			authenticator: authenticator,
			session:       s.open(),
			xid:           xid,
		}
	}

	// The 60 requests of the logins fill the budget of the address, so the test starts them in a fresh minute.
	s.redis.SetTime(base.Add(time.Duration(users+1) * time.Minute))
	s.redis.FlushAll()

	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, a := range accounts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			r, err := s.loginSafely(a.session.Handle, a.email, a.authenticator)
			if err != nil {
				t.Error(err)
				return
			}

			var result api.AuthorizeResult
			if err := json.Unmarshal([]byte(gjson.GetBytes(r.Body, "data").Raw), &result); err != nil {
				t.Errorf("%s: %d %s", a.email, r.Status, r.Body)
				return
			}

			if r.Status != http.StatusOK || result.UserXID != a.xid || result.Flags&es.SessionFlagAuthorized == 0 {
				t.Errorf("%s: want user %d authorized, got %d %+v", a.email, a.xid, r.Status, result)
			}
		}()
	}

	close(start)
	wg.Wait()
}
