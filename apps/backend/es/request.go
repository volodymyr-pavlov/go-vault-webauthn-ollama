package es

// SignedRequest is an HTTP request that a device signed with its key under RFC 9421, together with the key to check
// it. A [Reader] returns the item if the signature is valid.
//
// The device signs the method, the path, the digest of the body and the signature parameters: the time, the key ID,
// the algorithm and a nonce. So a request cannot be changed, moved to another path, sent much later or sent twice.
type SignedRequest struct {
	// Method is the HTTP method.
	Method []byte

	// Path is the request path without the query.
	Path []byte

	// Body is the request body. It may be empty.
	Body []byte

	// ContentDigest, SignatureInput and Signature hold the values of the request fields with the same names.
	ContentDigest  string
	SignatureInput string
	Signature      string

	// Key is the Ed25519 public key of the device.
	Key []byte
}

// RequestNonce is a nonce that a device used in a signed request. A [Writer] with [WriteCreate] remembers it for the
// time window of the signatures. The writer returns [ErrDuplicate] if the same key ID used the nonce before.
type RequestNonce struct {
	// KeyID is the ID of the key that signed the request.
	KeyID string

	// Nonce is the nonce of the signature.
	Nonce string
}
