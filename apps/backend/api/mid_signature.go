package api

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/auth"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

const (
	// HeaderContentDigest, HeaderSignatureInput and HeaderSignature are the names of the fields of a signed request:
	// the digest of the body (RFC 9530), and the parameters and the value of the signature (RFC 9421).
	HeaderContentDigest  = "content-digest"
	HeaderSignatureInput = "signature-input"
	HeaderSignature      = "signature"
)

// requestSessionRef returns the ID of the key that signed the request of ctx and the external identifier of the session
// that the request names, from the keyid and tag parameters of its Signature-Input field.
//
// It returns [ErrNoHeaderRequestSignature] if the field is missing and [ErrInvalidRequestSignature] if it is malformed,
// if its key ID is not the base64url encoding of a SHA-256 hash, or if it names no session.
func requestSessionRef(ctx *fasthttp.RequestCtx) ([]byte, uint64, error) {
	field := ctx.Request.Header.Peek(HeaderSignatureInput)
	if len(field) == 0 {
		return nil, 0, ErrNoHeaderRequestSignature
	}

	input, err := web.ParseInput(string(field), auth.SignatureLabel)
	if err != nil {
		return nil, 0, ErrInvalidRequestSignature.Wrap(err)
	}

	keyID, err := base64.RawURLEncoding.DecodeString(input.KeyID)
	if err != nil || len(keyID) != sha256.Size {
		return nil, 0, ErrInvalidRequestSignature
	}

	sessionXID, err := strconv.ParseUint(input.Tag, 10, 64)
	if err != nil || sessionXID == 0 {
		return nil, 0, ErrInvalidRequestSignature
	}

	return keyID, sessionXID, nil
}

// verifySignature checks that the request was signed with key. The signature covers the method, the path and the digest
// of the body, together with the time, the key ID and a nonce.
//
// It returns [ErrNoHeaderRequestSignature] if a field is missing. It returns [ErrInvalidRequestSignature] if a field is
// malformed, the request has a query string or the signature is wrong. It returns the same error if the nonce was used
// before, and [ErrStaleRequestTime] if the time is outside the window. A failure of the verifier itself is returned wrapped.
func verifySignature(ctx *fasthttp.RequestCtx, verifier es.Reader[es.SignedRequest], key []byte) error {
	digest := ctx.Request.Header.Peek(HeaderContentDigest)
	input := ctx.Request.Header.Peek(HeaderSignatureInput)

	signature := ctx.Request.Header.Peek(HeaderSignature)
	if len(digest) == 0 || len(input) == 0 || len(signature) == 0 {
		return ErrNoHeaderRequestSignature
	}

	// The signature covers the path but not the query string. The service refuses a query, because it could change
	// without breaking the signature.
	if len(ctx.URI().QueryString()) != 0 {
		return ErrInvalidRequestSignature
	}

	_, err := verifier.ReadOne(ctx, es.SignedRequest{
		Method:         ctx.Method(),
		Path:           ctx.Path(),
		Body:           ctx.PostBody(),
		ContentDigest:  string(digest),
		SignatureInput: string(input),
		Signature:      string(signature),
		Key:            key,
	}, 0)

	var stale *auth.StaleRequestError
	if errors.As(err, &stale) {
		return ErrStaleRequestTime.With(web.Params{
			"server_time": stale.ServerTime.Unix(),
		})
	}

	if errors.Is(err, auth.ErrInvalidSignature) || errors.Is(err, auth.ErrStaleRequest) ||
		errors.Is(err, auth.ErrInvalidDeviceKey) || errors.Is(err, auth.ErrReplayedRequest) {
		return ErrInvalidRequestSignature.Wrap(err)
	} else if err != nil {
		return fmt.Errorf("verify the request signature: %w", err)
	}

	return nil
}
