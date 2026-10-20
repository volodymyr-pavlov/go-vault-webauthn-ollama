package smtp

import "errors"

// ErrNoAddr means that the address of the mail server is empty. [NewClient] returns it.
var ErrNoAddr = errors.New("smtp: the address of the mail server is required")

// ErrNoFrom means that the sender address is empty. [NewClient] returns it.
var ErrNoFrom = errors.New("smtp: the sender address is required")

// ErrNoTemplate means that a message has no template or no subject. [NewSender] returns it.
var ErrNoTemplate = errors.New("smtp: the message has no template or no subject")

// ErrNoRecipient means that the message has no usable recipient. [Client.SendMessage] and [Sender.WriteOne] return it.
var ErrNoRecipient = errors.New("smtp: the recipient is required")

// ErrNoToken means that a registry token message has no token. [Sender.WriteOne] returns it.
var ErrNoToken = errors.New("smtp: the token is required")

// ErrTLSConflict means that both STARTTLS and implicit TLS are requested. [NewClient] returns it.
var ErrTLSConflict = errors.New("smtp: STARTTLS and implicit TLS exclude each other")

// ErrAuthWithoutTLS means that the credentials would travel over an unencrypted connection. [NewClient] and
// [Client.SendMessage] return it.
var ErrAuthWithoutTLS = errors.New("smtp: authentication needs TLS")

// ErrNoStartTLS means that STARTTLS is required and the server does not offer it. [Client.SendMessage] returns it.
var ErrNoStartTLS = errors.New("smtp: the mail server does not offer STARTTLS")

// ErrUnexpectedChallenge means that the server sent a challenge that AUTH PLAIN does not expect.
var ErrUnexpectedChallenge = errors.New("smtp: unexpected challenge from the mail server")
