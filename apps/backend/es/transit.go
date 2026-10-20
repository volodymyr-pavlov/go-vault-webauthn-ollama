package es

// Transit is one operation of the Vault Transit engine on one key. A [Writer] with [WriteCreate] runs the operation
// that the transit option of the [Op] names and returns the item with its output fields set. Key material never
// reaches the item, because Vault keeps the keys.
type Transit struct {
	// Key is the name of the Transit key.
	Key string

	// Context is the derivation context of a derived key. [EncryptTOTPSecret], [DecryptTOTPSecret] and
	// [RewrapTOTPSecret] read it.
	Context []byte

	// Plaintext is the input of [EncryptTOTPSecret] and [HashTheValue], and the output of [DecryptTOTPSecret].
	Plaintext []byte

	// Ciphertext is the input of [DecryptTOTPSecret] and [RewrapTOTPSecret]. It is the output of [EncryptTOTPSecret]
	// and [RewrapTOTPSecret]. It has the form "vault:vN:...".
	Ciphertext string

	// MAC is the output of [HashTheValue]: the HMAC-SHA256 of Plaintext, in the form "vault:vN:...".
	MAC string
}
