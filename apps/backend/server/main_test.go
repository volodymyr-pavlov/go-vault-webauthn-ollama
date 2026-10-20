//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/auth"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/config"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/vaulttest"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

const (
	testRPID   = "localhost"
	testOrigin = "http://localhost:8080"
)

// testDSN is the DSN of the MySQL database for the integration tests. It points to a container that TestMain
// starts, or to the database that TEST_MYSQL_DSN names.
var testDSN string

func TestMain(m *testing.M) {
	testDSN = os.Getenv("TEST_MYSQL_DSN")
	var purge func()
	if testDSN == "" {
		var err error
		testDSN, purge, err = startMySQL()
		if err != nil {
			log.Fatal(err)
		}
	}
	code := m.Run()
	if purge != nil {
		purge()
	}
	os.Exit(code)
}

// startMySQL runs a MySQL container. It returns the DSN of an empty database and a function that removes the
// container.
func startMySQL() (dsn string, purge func(), err error) {
	endpoint := os.Getenv("DOCKER_HOST")
	if home, err := os.UserHomeDir(); endpoint == "" && err == nil {
		if _, err := os.Stat(home + "/.docker/run/docker.sock"); err == nil {
			endpoint = "unix://" + home + "/.docker/run/docker.sock"
		}
	}
	pool, err := dockertest.NewPool(endpoint)
	if err != nil {
		return "", nil, fmt.Errorf("docker is needed for the integration tests, or TEST_MYSQL_DSN: %w", err)
	}
	if err := pool.Client.Ping(); err != nil {
		return "", nil, fmt.Errorf("docker is needed for the integration tests, or TEST_MYSQL_DSN: %w", err)
	}
	pool.MaxWait = 2 * time.Minute
	container, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mysql",
		Tag:        "8.4",
		Env: []string{
			"MYSQL_ROOT_PASSWORD=test",
			"MYSQL_DATABASE=test",
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{
			Name: "no",
		}
	})
	if err != nil {
		return "", nil, fmt.Errorf("start mysql: %w", err)
	}
	if err := container.Expire(900); err != nil {
		return "", nil, fmt.Errorf("set the expiry of the container: %w", err)
	}
	purge = func() {
		_ = pool.Purge(container)
	}
	dsn = fmt.Sprintf("root:test@tcp(127.0.0.1:%s)/test", container.GetPort("3306/tcp"))
	err = pool.Retry(func() error {
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return err
		}
		defer db.Close()
		return db.Ping()
	})
	if err != nil {
		purge()
		return "", nil, fmt.Errorf("wait for mysql: %w", err)
	}
	return dsn, purge, nil
}

// stand is one running service for a test. It has a Transit stand-in, the mock advisor, a message recorder and a
// clock that the test moves. It serves requests on an in-memory listener.
type stand struct {
	t        *testing.T
	env      *config.Env
	srv      *Server
	clock    *clock.FixedClock
	messages *messageRecorder
	advisor  *ai.MockAdvisor
	redis    *miniredis.Miniredis
	transit  *vaulttest.Server
	client   *http.Client
	listener *fasthttputil.InmemoryListener

	// devices maps the handle of each device to its private key. The stand signs every request with the key of the
	// device that the call names.
	devices map[string]ed25519.PrivateKey

	// tags maps the handle of each device to the identifier of its session, which every request of the session names in
	// the tag parameter. A device has no tag until its session is open.
	tags map[string]string

	// nonces counts the requests, so that each signature gets a unique nonce.
	nonces atomic.Int64
}

// device is a session that the stand opened, with the handle of the key that signs its requests.
type device struct {
	api.SessionResult

	Handle string
}

// stands counts the stands built so far. Each stand starts its clock one day after the previous one, so failed
// logins from earlier tests fall outside the window of the risk signals.
var stands atomic.Int64

// newStand builds and serves a stand. The tests share one database, so each stand uses its own addresses.
func newStand(t *testing.T) *stand {
	t.Helper()
	redisServer := miniredis.RunT(t)
	transit := vaulttest.New(t)
	opts := config.Options{
		HTTPAddr:      "inmemory",
		MySQLDSN:      testDSN,
		RedisAddr:     redisServer.Addr(),
		VaultAddr:     transit.URL,
		VaultRoleID:   "role",
		VaultSecretID: "secret",
		SMTPAddr:      "127.0.0.1:1025",
		MailFrom:      "login@example.com",
		RPID:          testRPID,
		RPName:        "Vault Login Test",
		Origins:       testOrigin,
		RecoveryDelay: time.Hour,
		Flags:         config.FlagMockAdvisor,
		LogLevel:      "warn",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	env, err := config.NewEnv(context.Background(), logger, opts)
	if err != nil {
		t.Fatal(err)
	}
	s := &stand{
		t:   t,
		env: env,
		clock: &clock.FixedClock{
			Time: time.Now().UTC().Truncate(time.Second).Add(time.Duration(stands.Add(1)) * 24 * time.Hour),
		},
		devices:  map[string]ed25519.PrivateKey{},
		tags:     map[string]string{},
		messages: &messageRecorder{},
		advisor:  &ai.MockAdvisor{},
		redis:    redisServer,
		transit:  transit,
	}
	env.SystemClock = s.clock
	env.MessageWriter = s.messages
	env.Engine.Advisor = s.advisor
	env.Engine.Timeout = time.Second
	// The request verifier keeps the clock it was built with, so the stand replaces it with one that uses the test
	// clock.
	// The session store stamps the creation time of a session, and the idle rule compares it with the time of the
	// request, so the store uses the test clock too.
	env.SessionWriter = &mysql.SessionWriter{
		Database:    env.Database,
		SystemClock: s.clock,
		UpdateSessionBuilder: &mysql.UpdateSessionBuilder{
			QueryBuilder: mysql.NewQueryBuilder(env.Database),
		},
	}
	// The Tx stores and the group writers stamp the time of a row and compare it with the time of the request, such as the
	// expiry of a recovery grant, so they use the test clock too.
	queryBuilder := mysql.NewQueryBuilder(env.Database)
	env.UserTx = &mysql.UserTx{
		SystemClock: s.clock,
		UpdateUserBuilder: &mysql.UpdateUserBuilder{
			QueryBuilder: queryBuilder,
		},
	}
	env.SessionTx = &mysql.SessionTx{
		SystemClock: s.clock,
		UpdateSessionBuilder: &mysql.UpdateSessionBuilder{
			QueryBuilder: queryBuilder,
		},
	}
	env.PasskeyTx = &mysql.PasskeyTx{
		SystemClock: s.clock,
		UpdatePasskeyBuilder: &mysql.UpdatePasskeyBuilder{
			QueryBuilder: queryBuilder,
		},
	}
	env.RecoveryCodeTx = &mysql.RecoveryCodeTx{
		SystemClock: s.clock,
	}
	env.RecoveryRequestTx = &mysql.RecoveryRequestTx{
		SystemClock: s.clock,
	}
	env.SessionGroupWriter = &mysql.SessionGroupWriter{
		Database:          env.Database,
		SystemClock:       s.clock,
		SessionTx:         env.SessionTx,
		UserTx:            env.UserTx,
		PasskeyTx:         env.PasskeyTx,
		RecoveryCodeTx:    env.RecoveryCodeTx,
		RecoveryRequestTx: env.RecoveryRequestTx,
	}
	env.AccountGroupWriter = &mysql.AccountGroupWriter{
		Database:       env.Database,
		SystemClock:    s.clock,
		UserTx:         env.UserTx,
		SessionTx:      env.SessionTx,
		PasskeyTx:      env.PasskeyTx,
		PasskeyBatchTx: env.PasskeyBatchTx,
		RecoveryCodeTx: env.RecoveryCodeTx,
	}
	env.RecoveryGroupWriter = &mysql.RecoveryGroupWriter{
		Database:          env.Database,
		SystemClock:       s.clock,
		SessionTx:         env.SessionTx,
		RecoveryRequestTx: env.RecoveryRequestTx,
	}
	// The recovery request store reads the time of the server, so it uses the test clock too.
	env.RecoveryRequestWriter = &mysql.RecoveryRequestWriter{
		Database:    env.Database,
		SystemClock: s.clock,
	}
	env.RequestVerifier = &auth.RequestVerifier{
		SystemClock: s.clock,
		NonceWriter: &auth.NonceStore{
			Redis: env.Redis,
		},
	}
	srv, err := NewServer("inmemory", logger, env, opts)
	if err != nil {
		t.Fatal(err)
	}
	s.srv = srv
	s.listener = fasthttputil.NewInmemoryListener()
	go func() {
		_ = fasthttp.Serve(s.listener, srv.Handler())
	}()
	s.client = &http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return s.listener.Dial()
			},
		},
	}
	t.Cleanup(func() {
		s.listener.Close()
		env.Close()
	})
	return s
}

// apiResponse is a parsed API response: the HTTP status, the error from the envelope and the raw data.
type apiResponse struct {
	Status int
	Data   json.RawMessage
	Error  *web.Error
	Header http.Header
}

// call sends a JSON request signed with the key of the device handle and returns the parsed response.
func (s *stand) call(method, path, handle string, body any) apiResponse {
	s.t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			s.t.Fatal(err)
		}
	}
	key, ok := s.devices[handle]
	if !ok {
		s.t.Fatalf("no device %q", handle)
	}
	request := s.newRequest(method, path, encoded)
	s.sign(request, encoded, key, s.clock.Now().Unix(), s.nextNonce(), s.tags[handle])
	return s.do(request)
}

// nextNonce returns a nonce that no earlier request of the stand used.
func (s *stand) nextNonce() string {
	return "nonce-" + strconv.FormatInt(s.nonces.Add(1), 10)
}

// newRequest returns an unsigned JSON request.
func (s *stand) newRequest(method, path string, body []byte) *http.Request {
	s.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, "http://inmemory"+path, reader)
	if err != nil {
		s.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", testOrigin)
	return request
}

// sign sets the Content-Digest, Signature-Input and Signature fields of request as RFC 9421 describes. The
// signature covers the method, the path and the body digest, plus the time, the key ID, the algorithm and the nonce.
func (s *stand) sign(request *http.Request, body []byte, key ed25519.PrivateKey, created int64, nonce, tag string) {
	digest := sha256.Sum256(body)
	contentDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(digest[:]) + ":"
	keyID := sha256.Sum256(key.Public().(ed25519.PublicKey))
	params := fmt.Sprintf(`("@method" "@path" "content-digest");created=%d;keyid="%s";alg="ed25519";nonce="%s"`,
		created, base64.RawURLEncoding.EncodeToString(keyID[:]), nonce)
	if tag != "" {
		params += fmt.Sprintf(`;tag="%s"`, tag)
	}
	base := fmt.Sprintf("\"@method\": %s\n\"@path\": %s\n\"content-digest\": %s\n\"@signature-params\": %s",
		request.Method, request.URL.Path, contentDigest, params)
	request.Header.Set("Content-Digest", contentDigest)
	request.Header.Set("Signature-Input", "sig="+params)
	request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(base)))+":")
}

// do sends request and parses the response envelope.
func (s *stand) do(request *http.Request) apiResponse {
	s.t.Helper()
	method, path := request.Method, request.URL.RequestURI()
	response, err := s.client.Do(request)
	if err != nil {
		s.t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		s.t.Fatal(err)
	}
	a := apiResponse{
		Status: response.StatusCode,
		Header: response.Header,
	}
	if len(raw) == 0 {
		return a
	}
	if !gjson.ValidBytes(raw) {
		s.t.Fatalf("%s %s: not an envelope: %s", method, path, raw)
	}
	envelope := gjson.ParseBytes(raw)
	a.Data = []byte(envelope.Get("data").Raw)
	if failure := envelope.Get("error"); failure.IsObject() {
		a.Error = &web.Error{
			Status:  int(failure.Get("status").Int()),
			Num:     uint16(failure.Get("num").Uint()),
			Code:    failure.Get("code").String(),
			Message: failure.Get("message").String(),
		}
		if params, ok := failure.Get("params").Value().(map[string]any); ok {
			a.Error.Params = params
		}
	}
	return a
}

// decode unmarshals the data of a response into target. It fails the test if the response is a refusal.
func (s *stand) decode(a apiResponse, target any) {
	s.t.Helper()
	if a.Error != nil {
		s.t.Fatalf("refused: %d %s", a.Status, a.Error.Code)
	}
	if err := json.Unmarshal(a.Data, target); err != nil {
		s.t.Fatalf("decode %s: %v", a.Data, err)
	}
}

// tokenFromMessages returns the verification token from the last registration message sent to the address.
func (s *stand) tokenFromMessages(to string) string {
	s.t.Helper()
	sent := s.messages.Sent()
	for i := len(sent) - 1; i >= 0; i-- {
		if sent[i].Op&es.SendRegistryToken != 0 && sent[i].Message.Email == to {
			return sent[i].Message.Token
		}
	}
	s.t.Fatalf("no verification token was sent to %s", to)
	return ""
}
