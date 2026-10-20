package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

// memoryNonces is an in-memory nonce store. It fails with err when err is set.
type memoryNonces struct {
	mu   sync.Mutex
	seen map[string]bool
	err  error
}

func (m *memoryNonces) WriteOne(_ context.Context, item es.RequestNonce, _ es.Op) (es.RequestNonce, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.err != nil {
		return item, m.err
	}

	if m.seen == nil {
		m.seen = map[string]bool{}
	}

	if m.seen[item.KeyID+item.Nonce] {
		return item, es.ErrDuplicate
	}

	m.seen[item.KeyID+item.Nonce] = true

	return item, nil
}

// signedAt returns a request that key signs as a device does, with the creation time at and the given nonce.
func signedAt(key ed25519.PrivateKey, at time.Time, nonce string) es.SignedRequest {
	public := key.Public().(ed25519.PublicKey)
	body := []byte(`{"email":"a@example.com"}`)
	digest := web.ContentDigest(body)
	params := fmt.Sprintf(`("@method" "@path" "content-digest");created=%d;keyid="%s";alg="ed25519";nonce="%s"`, at.Unix(), KeyID(public), nonce)
	base := fmt.Sprintf("\"@method\": POST\n\"@path\": /v1/register\n\"content-digest\": %s\n\"@signature-params\": %s", digest, params)

	return es.SignedRequest{
		Method:         []byte("POST"),
		Path:           []byte("/v1/register"),
		Body:           body,
		ContentDigest:  digest,
		SignatureInput: "sig=" + params,
		Signature:      "sig=:" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(base))) + ":",
		Key:            public,
	}
}

func TestRequestVerifier(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	nonces := &memoryNonces{}
	verifier := &RequestVerifier{
		SystemClock: &clock.FixedClock{Time: now},
		NonceWriter: nonces,
	}

	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, other, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	if _, err := verifier.ReadOne(ctx, signedAt(key, now, "first-nonce-0123456"), 0); err != nil {
		t.Fatalf("a valid request: %v", err)
	}

	cases := map[string]struct {
		request func() es.SignedRequest
		want    error
	}{
		"the same nonce again": {func() es.SignedRequest { return signedAt(key, now, "first-nonce-0123456") }, ErrReplayedRequest},
		"another body": {func() es.SignedRequest {
			r := signedAt(key, now, "n-body")
			r.Body = []byte(`{"email":"b@example.com"}`)
			return r
		}, ErrInvalidSignature},
		"another path": {func() es.SignedRequest {
			r := signedAt(key, now, "n-path")
			r.Path = []byte("/v1/session")
			return r
		}, ErrInvalidSignature},
		"another method": {func() es.SignedRequest {
			r := signedAt(key, now, "n-method")
			r.Method = []byte("GET")
			return r
		}, ErrInvalidSignature},
		"a digest of another body": {func() es.SignedRequest {
			r := signedAt(key, now, "n-digest")
			r.ContentDigest = web.ContentDigest([]byte("other"))
			return r
		}, ErrInvalidSignature},
		"another key signed": {func() es.SignedRequest {
			r := signedAt(other, now, "n-other")
			r.Key = key.Public().(ed25519.PublicKey)
			return r
		}, ErrInvalidSignature},
		"a key ID of another key": {func() es.SignedRequest {
			r := signedAt(key, now, "n-keyid")
			r.Key = other.Public().(ed25519.PublicKey)
			return r
		}, ErrInvalidSignature},
		"a short key": {func() es.SignedRequest {
			r := signedAt(key, now, "n-short")
			r.Key = r.Key[:10]
			return r
		}, ErrInvalidDeviceKey},
		"an old request":    {func() es.SignedRequest { return signedAt(key, now.Add(-2*time.Minute), "n-old") }, ErrStaleRequest},
		"a future request":  {func() es.SignedRequest { return signedAt(key, now.Add(2*time.Minute), "n-future") }, ErrStaleRequest},
		"an empty nonce":    {func() es.SignedRequest { return signedAt(key, now, "") }, ErrInvalidSignature},
		"no signature":      {func() es.SignedRequest { r := signedAt(key, now, "n-none"); r.Signature = ""; return r }, ErrInvalidSignature},
		"a short signature": {func() es.SignedRequest { r := signedAt(key, now, "n-cut"); r.Signature = "sig=:AAAA:"; return r }, ErrInvalidSignature},
		"another covered part": {func() es.SignedRequest {
			r := signedAt(key, now, "n-parts")
			r.SignatureInput = `sig=("@method");created=1;keyid="x";alg="ed25519";nonce="n-parts"`
			return r
		}, ErrInvalidSignature},
		"another algorithm": {func() es.SignedRequest {
			r := signedAt(key, now, "n-alg")
			r.SignatureInput = `sig=("@method" "@path" "content-digest");created=1;keyid="x";alg="rsa-pss-sha512";nonce="n-alg"`
			return r
		}, ErrInvalidSignature},
	}
	for name, c := range cases {
		if _, err := verifier.ReadOne(ctx, c.request(), 0); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}

	// A broken nonce store is a server fault. The verifier must not report it as a bad signature or a replay.
	nonces.err = errors.New("redis is down")

	if _, err := verifier.ReadOne(ctx, signedAt(key, now, "n-store"), 0); err == nil || errors.Is(err, ErrInvalidSignature) || errors.Is(err, ErrReplayedRequest) {
		t.Fatalf("a failing store: %v, want its own error", err)
	}
}

func TestKeyIDIsTheHashOfTheKey(t *testing.T) {
	// The expected value is the SHA-256 of 32 zero bytes in unpadded base64url.
	if got := KeyID(make([]byte, 32)); got != "Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU" {
		t.Fatalf("got %s", got)
	}
}

// TestRequestVerifierTag proves that the verifier accepts the tag parameter of a session request in its place and
// refuses a tag that is too long or placed before another parameter, so a client cannot widen the signed profile.
func TestRequestVerifierTag(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	verifier := &RequestVerifier{
		SystemClock: &clock.FixedClock{Time: now},
		NonceWriter: &memoryNonces{},
	}

	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	public := key.Public().(ed25519.PublicKey)
	body := []byte(`{}`)
	digest := web.ContentDigest(body)

	sign := func(params string) es.SignedRequest {
		base := fmt.Sprintf("\"@method\": POST\n\"@path\": /v1/x\n\"content-digest\": %s\n\"@signature-params\": %s", digest, params)

		return es.SignedRequest{
			Method:         []byte("POST"),
			Path:           []byte("/v1/x"),
			Body:           body,
			ContentDigest:  digest,
			SignatureInput: "sig=" + params,
			Signature:      "sig=:" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(base))) + ":",
			Key:            public,
		}
	}
	head := fmt.Sprintf(`("@method" "@path" "content-digest");created=%d;keyid="%s";alg="ed25519"`, now.Unix(), KeyID(public))

	cases := map[string]struct {
		params string
		want   error
	}{
		"a tag after the nonce":      {head + `;nonce="a";tag="123"`, nil},
		"a tag that is too long":     {head + `;nonce="b";tag="123456789012345678901"`, ErrInvalidSignature},
		"a tag before the nonce":     {head + `;tag="123";nonce="c"`, ErrInvalidSignature},
		"an unknown extra parameter": {head + `;nonce="d";tag="123";x="1"`, ErrInvalidSignature},
	}
	for name, c := range cases {
		if _, err := verifier.ReadOne(context.Background(), sign(c.params), 0); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}
