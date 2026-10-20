package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"slices"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ es.Reader[es.SignedRequest] = &RequestVerifier{}

const (
	// DefaultRequestWindow is how far the time of a signed request may be from the time of the server when
	// [RequestVerifier.Window] is zero.
	DefaultRequestWindow = time.Minute

	// SignatureLabel is the label of the signature in the Signature-Input and Signature fields.
	SignatureLabel = "sig"

	// MaxNonceLength is the longest nonce that a signature may carry, in bytes. MaxTagLength is the same for the tag,
	// which holds the decimal identifier of a session.
	MaxNonceLength = 64
	MaxTagLength   = 20
)

// signedComponents are the components that every request signs, in this order.
var signedComponents = []string{
	"@method",
	"@path",
	"content-digest",
}

// signedParams are the parameters that every signature carries, in this order. A request of a session also carries the
// tag parameter, which names the session. [signedParamsWithTag] lists them.
var signedParams = []string{
	"created",
	"keyid",
	"alg",
	"nonce",
}

// signedParamsWithTag are the parameters of a signature in a request of a session, in this order. The tag holds the
// external identifier of the session, so that one key can hold several sessions, for example in several tabs.
var signedParamsWithTag = []string{
	"created",
	"keyid",
	"alg",
	"nonce",
	"tag",
}

// KeyID returns the ID of a device key: the unpadded base64url encoding of the SHA-256 hash of the 32 raw bytes of the
// key.
func KeyID(key []byte) string {
	sum := sha256.Sum256(key)

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RequestVerifier checks that a device signed a request with its key under RFC 9421. It implements [es.Reader] for
// [es.SignedRequest].
//
// A request signs its method, its path and the digest of its body. The signature carries the time, the key ID, the
// algorithm and a nonce as parameters.
type RequestVerifier struct {
	// Window is how far the time of a request may be from the time of the server. Zero means [DefaultRequestWindow].
	Window time.Duration

	// SystemClock supplies the time of the server.
	SystemClock clock.Clock

	// NonceWriter remembers the nonces, so a signed request works only once.
	NonceWriter es.Writer[es.RequestNonce]
}

// ReadOne implements [es.Reader]. It checks the shape and the signature of the item against its key, the digest
// against its body and the time against the clock. It returns the item when every check passes.
//
// It remembers the nonce as the last step, so a request that fails any check does not use up its nonce.
//
// It returns [ErrInvalidDeviceKey] if the key does not have the size of an Ed25519 public key. It returns
// a [StaleRequestError], which matches [ErrStaleRequest] and carries the time of the server, if the time of the request is
// outside the window, and [ErrReplayedRequest] if the nonce was used
// before. It returns [ErrInvalidSignature] if the fields are malformed, do not have the shape that the service signs,
// or do not verify. It returns an error of NonceWriter as it is.
func (v *RequestVerifier) ReadOne(ctx context.Context, item es.SignedRequest, _ es.Op) (es.SignedRequest, error) {
	input, err := web.ParseInput(item.SignatureInput, SignatureLabel)
	if err != nil {
		return item, errors.Join(ErrInvalidSignature, err)
	}

	if !slices.Equal(input.Components, signedComponents) || (!slices.Equal(input.Params, signedParams) && !slices.Equal(input.Params, signedParamsWithTag)) ||
		len(input.Tag) > MaxTagLength || input.Alg != "ed25519" || input.Nonce == "" || len(input.Nonce) > MaxNonceLength {
		return item, ErrInvalidSignature
	}

	if len(item.Key) != ed25519.PublicKeySize {
		return item, ErrInvalidDeviceKey
	}

	if input.KeyID != KeyID(item.Key) {
		return item, ErrInvalidSignature
	}

	window := v.Window
	if window == 0 {
		window = DefaultRequestWindow
	}

	now := v.SystemClock.Now()
	if time.Unix(input.Created, 0).Sub(now).Abs() > window {
		return item, &StaleRequestError{ServerTime: now}
	}

	if subtle.ConstantTimeCompare([]byte(item.ContentDigest), []byte(web.ContentDigest(item.Body))) != 1 {
		return item, ErrInvalidSignature
	}

	signature, err := web.ParseSignature(item.Signature, SignatureLabel)
	if err != nil {
		return item, errors.Join(ErrInvalidSignature, err)
	}

	base, err := web.Base(input, func(component string) (string, error) {
		switch component {
		case "@method":
			return string(item.Method), nil
		case "@path":
			return string(item.Path), nil
		case "content-digest":
			return item.ContentDigest, nil
		}

		return "", web.ErrComponent
	})
	if err != nil {
		return item, errors.Join(ErrInvalidSignature, err)
	}

	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(item.Key, []byte(base), signature) {
		return item, ErrInvalidSignature
	}

	_, err = v.NonceWriter.WriteOne(ctx, es.RequestNonce{
		KeyID: input.KeyID,
		Nonce: input.Nonce,
	}, es.WriteCreate)
	if errors.Is(err, es.ErrDuplicate) {
		return item, ErrReplayedRequest
	} else if err != nil {
		return item, err
	}

	return item, nil
}
