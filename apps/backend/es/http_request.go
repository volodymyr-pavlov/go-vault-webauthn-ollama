package es

import (
	"net/netip"
	"time"
)

// HTTPRequest is one row of the log of the requests that the API receives, each with the answer the API gave. The
// request log middleware writes the row after the handler has finished, for every route except the health check. A
// [Writer] with [WriteCreate] saves it.
//
// The log is a trail for support. Nothing in the service reads it back. It holds no body, no header except the ones
// below, and no query, because the bodies of this service carry passwords, codes, tokens and WebAuthn responses.
type HTTPRequest struct {
	// ID is the position of the row in the log. A store sets it when it writes the row.
	ID uint64

	// ResourceCode says which endpoint was called, and Method is the HTTP method.
	ResourceCode ResourceCode
	Method       string

	// StatusCode is the HTTP status that the API answered with. ErrorCode is the number of the API error, from 10000
	// up, if the request failed with a known error, and zero otherwise. DurationMs is the handling time in
	// milliseconds.
	StatusCode uint16
	ErrorCode  uint16
	DurationMs uint32

	// SessionXID and UserXID are the external IDs of the session and the user of the request. They are zero if the
	// request has none.
	SessionXID uint64
	UserXID    uint64

	// IP is the address of the client as the service saw it behind the trusted proxies. It is the zero address if
	// unknown.
	IP netip.Addr

	// Path is the path of the request without a query.
	Path string

	// RequestID, Host, UserAgent and BuildVersion are the request ID of the response, the Host header, the User-Agent
	// header and the version of the service. A store cuts them to the width of their columns.
	RequestID    string
	Host         string
	UserAgent    string
	BuildVersion string

	// Event is the name of the security event that the handler reported for the request, such as "login" or
	// "passkey_enrolled". It is empty if the handler reported none. EventAttrs holds the attributes of the event as the
	// pairs key=value, sorted by key. A store cuts both to the width of their columns.
	Event      Event
	EventAttrs string

	// ErrorText is the text of the error of a request that failed in an unexpected way. It is empty for a known
	// refusal. A store cuts it to the width of its column.
	ErrorText string

	// CreatedAt is the time when the request started. A store writes the time of its own clock if it is zero.
	CreatedAt time.Time
}
