// Package vaulttest provides a stand-in for the Transit engine of Vault. It is an HTTP server that serves the Transit
// operations and the AppRole login that the service uses, with the same versions, derivation contexts and responses.
// Tests can run the real [vault.Client] against it.
//
// The server keeps its keys in memory and is not a security boundary.
package vaulttest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/tidwall/gjson"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/totp"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/vault"
)

// key is a named key with all its versions. Version numbers start at 1. The field minDecryption is the oldest version
// that still decrypts.
type key struct {
	versions      [][]byte
	minDecryption int
}

// authenticatorKey is a key of the stand-in TOTP engine.
type authenticatorKey struct {
	secret []byte
	digits int
	period uint
}

// Server is the stand-in for Vault. [New] starts it.
type Server struct {
	// URL is the address of the server.
	URL string

	http *httptest.Server
	mu   sync.Mutex
	keys map[string]*key

	// authenticators are the keys of the stand-in TOTP engine, by name.
	authenticators map[string]authenticatorKey
}

// New starts a server that has the keys "totp" and "mac". The server stops when the test ends.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		keys:           map[string]*key{},
		authenticators: map[string]authenticatorKey{},
	}
	s.Add("totp")
	s.Add("mac")
	s.http = httptest.NewServer(s)
	s.URL = s.http.URL
	t.Cleanup(s.http.Close)
	return s
}

// Client returns a [vault.Client] for the server. It fails the test if it cannot make the client.
func (s *Server) Client(t *testing.T) *vault.Client {
	t.Helper()
	config := api.DefaultConfig()
	config.Address = s.URL

	client, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}

	client.SetToken("vaulttest")
	return &vault.Client{
		API: client,
	}
}

// AuthenticatorClient returns a [vault.AuthenticatorClient] for the server. It fails the test if it cannot make the
// client.
func (s *Server) AuthenticatorClient(t *testing.T) *vault.AuthenticatorClient {
	t.Helper()

	return &vault.AuthenticatorClient{
		API: s.Client(t).API,
	}
}

// AuthenticatorKeys returns the number of keys in the stand-in TOTP engine.
func (s *Server) AuthenticatorKeys() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.authenticators)
}

// Close stops the server. A test can use it to simulate an outage of Vault.
func (s *Server) Close() {
	s.http.Close()
}

// Add adds a key named name, and replaces a key with the same name. The key encrypts with AES-256-GCM under a key
// derived from the context, and it keys HMAC-SHA256.
func (s *Server) Add(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[name] = &key{
		versions:      [][]byte{newSecret()},
		minDecryption: 1,
	}
}

// Rotate adds a version to the key named name. The key encrypts with the new version from then on. The earlier versions
// keep decrypting until [Server.Retire] retires them.
func (s *Server) Rotate(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.keys[name]
	k.versions = append(k.versions, newSecret())
}

// Retire sets the oldest version of the key named name that still decrypts. It is the min_decryption_version setting of
// Transit.
func (s *Server) Retire(name string, minDecryption int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[name].minDecryption = minDecryption
}

// newSecret returns the secret of a new version of a key.
func newSecret() []byte {
	secret := make([]byte, 32)

	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	return secret
}

// request is the body of an operation, with every field that any operation reads.
type request struct {
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
	Context    string `json:"context"`
	Input      string `json:"input"`
}

// response is the data of the response of an operation.
type response struct {
	Ciphertext string `json:"ciphertext,omitempty"`
	Plaintext  string `json:"plaintext,omitempty"`
	HMAC       string `json:"hmac,omitempty"`
}

// envelope is the body of every response of an operation.
type envelope struct {
	Data any `json:"data"`
}

// authResponse is the body of the response of an AppRole login.
type authResponse struct {
	Auth authToken `json:"auth"`
}

// authToken is the token in the response of a login.
type authToken struct {
	ClientToken   string `json:"client_token"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
}

// unwrapResponse is the body of the response of an unwrap of a secret ID.
type unwrapResponse struct {
	Data struct {
		SecretID string `json:"secret_id"`
	} `json:"data"`
}

// ServeHTTP serves the Transit operations encrypt, decrypt, rewrap and hmac at /v1/transit/{operation}/{name}, the
// AppRole login and the unwrap of a wrapped secret ID, so that [vault.Login] works against it. Every login and unwrap
// succeeds.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/auth/approle/login":
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(authResponse{Auth: authToken{
			ClientToken:   "vaulttest",
			LeaseDuration: 3600,
			Renewable:     true,
		}}); err != nil {
			http.Error(w, `{"errors":["encode failed"]}`, http.StatusInternalServerError)
		}

		return
	case "/v1/sys/wrapping/unwrap":
		var unwrapped unwrapResponse
		unwrapped.Data.SecretID = "vaulttest-secret-id"
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(unwrapped); err != nil {
			http.Error(w, `{"errors":["encode failed"]}`, http.StatusInternalServerError)
		}

		return
	}

	if strings.HasPrefix(r.URL.Path, "/v1/authenticator/") {
		s.serveAuthenticator(w, r)

		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/transit/"), "/")
	if len(parts) != 2 {
		http.Error(w, `{"errors":["unsupported path"]}`, http.StatusNotFound)
		return
	}

	operation, name := parts[0], parts[1]
	s.mu.Lock()
	defer s.mu.Unlock()

	k, ok := s.keys[name]
	if !ok {
		http.Error(w, `{"errors":["unknown key"]}`, http.StatusNotFound)
		return
	}

	raw, err := io.ReadAll(r.Body)
	if err != nil || !gjson.ValidBytes(raw) {
		http.Error(w, `{"errors":["bad body"]}`, http.StatusBadRequest)
		return
	}

	body := request{
		Plaintext:  gjson.GetBytes(raw, "plaintext").String(),
		Ciphertext: gjson.GetBytes(raw, "ciphertext").String(),
		Context:    gjson.GetBytes(raw, "context").String(),
		Input:      gjson.GetBytes(raw, "input").String(),
	}

	context, err := base64.StdEncoding.DecodeString(body.Context)
	if err != nil {
		http.Error(w, `{"errors":["bad context"]}`, http.StatusBadRequest)
		return
	}

	var result response
	switch operation {
	case "encrypt":
		plaintext, err := base64.StdEncoding.DecodeString(body.Plaintext)
		if err != nil {
			http.Error(w, `{"errors":["bad plaintext"]}`, http.StatusBadRequest)
			return
		}

		result.Ciphertext, err = seal(len(k.versions), derive(k.versions[len(k.versions)-1], context), plaintext)
		if err != nil {
			http.Error(w, `{"errors":["seal failed"]}`, http.StatusInternalServerError)
			return
		}
	case "decrypt":
		plaintext, ok := s.open(k, context, body.Ciphertext)
		if !ok {
			http.Error(w, `{"errors":["message authentication failed"]}`, http.StatusBadRequest)
			return
		}

		result.Plaintext = base64.StdEncoding.EncodeToString(plaintext)
	case "rewrap":
		plaintext, ok := s.open(k, context, body.Ciphertext)
		if !ok {
			http.Error(w, `{"errors":["message authentication failed"]}`, http.StatusBadRequest)
			return
		}

		result.Ciphertext, err = seal(len(k.versions), derive(k.versions[len(k.versions)-1], context), plaintext)
		if err != nil {
			http.Error(w, `{"errors":["seal failed"]}`, http.StatusInternalServerError)
			return
		}
	case "hmac":
		input, err := base64.StdEncoding.DecodeString(body.Input)
		if err != nil {
			http.Error(w, `{"errors":["bad input"]}`, http.StatusBadRequest)
			return
		}

		mac := hmac.New(sha256.New, k.versions[len(k.versions)-1])
		mac.Write(input)
		result.HMAC = "vault:v" + strconv.Itoa(len(k.versions)) + ":" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	default:
		http.Error(w, `{"errors":["unsupported operation"]}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(envelope{Data: result}); err != nil {
		http.Error(w, `{"errors":["encode failed"]}`, http.StatusInternalServerError)
	}
}

// open decrypts a ciphertext that was made for the context. It reports false for a ciphertext of another context, of a
// retired or unknown version, or for data that is not a ciphertext.
func (s *Server) open(k *key, context []byte, ciphertext string) ([]byte, bool) {
	version, payload, err := vault.Split(ciphertext)
	if err != nil || version > len(k.versions) || version < k.minDecryption {
		return nil, false
	}

	sealed, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, false
	}

	block, err := aes.NewCipher(derive(k.versions[version-1], context))
	if err != nil {
		return nil, false
	}

	aead, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < aead.NonceSize() {
		return nil, false
	}

	plaintext, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], nil)
	if err != nil {
		return nil, false
	}

	return plaintext, true
}

// derive returns the key for a context: the HMAC-SHA256 of the context under secret.
func derive(secret, context []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(context)
	return mac.Sum(nil)
}

// seal encrypts plaintext with AES-256-GCM under secret and returns it in the "vault:vN:payload" form. The payload is
// the base64 encoding of the nonce followed by the ciphertext.
func seal(version int, secret, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())

	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return fmt.Sprintf("vault:v%d:%s", version, base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, plaintext, nil))), nil
}

// serveAuthenticator serves the part of the TOTP engine that the service uses: it creates and deletes a key at
// /v1/authenticator/keys/{name} and reads the current code at /v1/authenticator/code/{name}. Only SHA-1 is supported.
func (s *Server) serveAuthenticator(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/authenticator/"), "/")
	if len(parts) != 2 {
		http.Error(w, `{"errors":["unsupported path"]}`, http.StatusNotFound)

		return
	}

	kind, name := parts[0], parts[1]

	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case kind == "keys" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		raw, err := io.ReadAll(r.Body)
		if err != nil || !gjson.ValidBytes(raw) {
			http.Error(w, `{"errors":["bad body"]}`, http.StatusBadRequest)

			return
		}

		secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(gjson.GetBytes(raw, "key").String())
		if err != nil || len(secret) == 0 {
			http.Error(w, `{"errors":["bad key"]}`, http.StatusBadRequest)

			return
		}

		if algorithm := gjson.GetBytes(raw, "algorithm").String(); algorithm != "" && algorithm != "SHA1" {
			http.Error(w, `{"errors":["the stand-in supports SHA1 only"]}`, http.StatusBadRequest)

			return
		}

		s.authenticators[name] = authenticatorKey{
			secret: secret,
			digits: int(gjson.GetBytes(raw, "digits").Int()),
			period: uint(gjson.GetBytes(raw, "period").Uint()),
		}

		w.WriteHeader(http.StatusNoContent)
	case kind == "keys" && r.Method == http.MethodDelete:
		delete(s.authenticators, name)
		w.WriteHeader(http.StatusNoContent)
	case kind == "code" && r.Method == http.MethodGet:
		record, ok := s.authenticators[name]
		if !ok {
			// The real engine answers a missing key with status 400.
			http.Error(w, `{"errors":["unknown key: `+name+`"]}`, http.StatusBadRequest)

			return
		}

		options := totp.Options{
			Digits: record.digits,
			Period: record.period,
		}
		code := options.Code(record.secret, options.Step(time.Now()))

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(envelope{Data: map[string]string{"code": code}}); err != nil {
			http.Error(w, `{"errors":["encode failed"]}`, http.StatusInternalServerError)
		}
	default:
		http.Error(w, `{"errors":["unsupported operation"]}`, http.StatusBadRequest)
	}
}
