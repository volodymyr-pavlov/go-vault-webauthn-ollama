package es

import "time"

// Message is a message to the owner of an account, sent outside the API. A [Writer] with [WriteCreate] sends it. The
// message option of the [Op] selects which message it is, and so which fields the writer reads.
type Message struct {
	// Email is the address the message goes to.
	Email string

	// Name is the name of the passkey that the message is about. Only the passkey messages read it.
	Name string

	// Token is the single-use verification token in hexadecimal. Only [SendRegistryToken] reads it.
	Token string

	// TTL is how long the verification token stays valid. Only [SendRegistryToken] reads it.
	TTL time.Duration
}
