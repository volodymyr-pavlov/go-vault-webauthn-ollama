// Package vault connects the service to HashiCorp Vault.
//
// [Client] uses the Transit engine to encrypt TOTP secrets and to make keyed hashes of values that the service must
// not store in clear, such as recovery codes. [Login] trades an AppRole secret ID for a short-lived token, and the
// returned [Lease] renews the token.
//
// No key material reaches this package. Transit keeps the keys, and the policy of the service allows no export,
// backup or rotation of a key. The tests run the client against the stand-in server of the vaulttest package.
package vault
