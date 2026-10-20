package vault

import "errors"

// ErrDecrypt is returned by [Client.WriteOne] with [es.DecryptTOTPSecret] when the ciphertext does not decrypt with
// the given key and context. The ciphertext was made for another context, was made by a retired key version, or is not
// a ciphertext at all.
var ErrDecrypt = errors.New("the ciphertext does not decrypt with this key and context")

// ErrNoField is wrapped after the name of a field that a response of Vault lacks.
var ErrNoField = errors.New("missing from the response of Vault")

// ErrCiphertextForm is returned by [Split] when the value is not in the "vault:vN:payload" form of a ciphertext, hash
// or signature.
var ErrCiphertextForm = errors.New("not in the vault:vN:... form")

// ErrNoRoleID is returned by [Login] when the role ID is empty.
var ErrNoRoleID = errors.New("the AppRole role ID is required")

// ErrNoSecretID is returned by [Login] when neither a secret ID nor a wrapping token is given.
var ErrNoSecretID = errors.New("an AppRole secret ID or a wrapping token is required")

// ErrNoToken is returned by [Login] when the login response carries no client token.
var ErrNoToken = errors.New("the login response carries no token")
