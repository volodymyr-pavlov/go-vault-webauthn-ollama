// Package auth proves who a caller is. It does not decide what the caller may do.
//
// [Hasher] hashes passwords with Argon2id and checks them. A hash is a PHC string that carries its own parameters, so
// the parameters can change without a migration.
//
// [RelyingParty] runs the WebAuthn ceremonies: the registration of a passkey and the login with one. It returns the
// state of each ceremony to the caller, who keeps it on the session until the ceremony ends. The attestation
// preference is none, so the package stores the attestation format and checks nothing else about it.
//
// [RequestVerifier] checks that a device signed a request under RFC 9421. The device signs the method, the path and
// the digest of the body with its Ed25519 key. The key identifies the session, so the service issues no token.
// [NonceStore] remembers the nonces in Redis, so a signed request works only once.
//
// The authtest package provides the software authenticator that the tests of this package use.
package auth
