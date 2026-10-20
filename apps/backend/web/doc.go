// Package web provides the HTTP code that every API of the server shares, and the parts of HTTP Message Signatures that
// the server uses.
//
// A [Handler] handles a request and returns an error instead of writing the error response. A [Mux] maps methods and
// paths to handlers and wraps them in [Middleware], such as [Recover]. It turns a returned [Error] into a JSON response
// with the status of the error. The cause of an error is logged and never sent, so the client sees only the message.
//
// [Write] and [WriteError] write a response in the [Response] envelope, with the data as Data or the error as Error.
// [WriteRaw] writes a response without the envelope. [Unmarshal] and the JSON readers decode the body of a request.
//
// An [Error] has an HTTP status, a number and a code that never change, and a message for people. It can also have
// [Params] that explain the refusal. This package defines the errors that every API shares, such as [ErrInternal]. Each
// API defines its own errors, with their numbers in one block so that no two are the same.
//
// The signature code covers RFC 9421. [ParseInput] reads one labeled signature from a Signature-Input field, and
// [ParseSignature] reads the matching value from a Signature field. [Base] builds the signature base that the
// signature covers. The caller gives it a function that returns the value of each component, so the caller decides
// which components it supports. [ContentDigest] builds the Content-Digest field of RFC 9530.
//
// The parser reads only the part of the structured fields of RFC 8941 that a signature needs: an inner list of strings
// followed by parameters. A parameter has the form ;name=value. The value is a quoted string or plain text that ends at
// the next semicolon. The parser does not check that plain text is a valid token or integer, except for the parameter
// created, which must be a decimal integer. It refuses a parameter with no value or with an empty name, and a value
// that starts with a colon, which is a byte sequence.
package web
