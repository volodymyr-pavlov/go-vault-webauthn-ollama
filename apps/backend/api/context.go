// Package api implements the HTTP API of the service. It holds the handlers of the endpoints, the middleware that
// guards them and the errors they return.
//
// The session middleware authenticates each request by its signature and stores the session and its user in the request
// context. A handler reads them with [Session] and [User].
package api

import (
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

type contextKey string

const (
	keySession = contextKey("session")
	keyUser    = contextKey("user")
	keyEvent   = contextKey("event")
)

// SetSession stores session in the context of the request, so that [Session] returns it for the rest of the request.
func SetSession(ctx *fasthttp.RequestCtx, session es.Session) {
	ctx.SetUserValue(keySession, session)
}

// Session returns the session that [SetSession] stored in the context of the request.
//
// It returns [ErrNoSession] if no session was stored.
func Session(ctx *fasthttp.RequestCtx) (es.Session, error) {
	session, ok := ctx.UserValue(keySession).(es.Session)
	if !ok {
		return es.Session{}, ErrNoSession
	}

	return session, nil
}

// SetUser stores user in the context of the request, so that [User] returns it for the rest of the request.
func SetUser(ctx *fasthttp.RequestCtx, user es.User) {
	ctx.SetUserValue(keyUser, user)
}

// User returns the user that [SetUser] stored in the context of the request.
//
// It returns [ErrNoUser] if no user was stored. This is the case when the session is bound to no account.
func User(ctx *fasthttp.RequestCtx) (es.User, error) {
	user, ok := ctx.UserValue(keyUser).(es.User)
	if !ok {
		return es.User{}, ErrNoUser
	}

	return user, nil
}

// event is a security event that a handler reports for its request.
type event struct {
	name  es.Event
	attrs string
}

// SetEvent names the security event of the request in ctx, such as [es.EventLogin] or [es.EventPasskeyEnrolled], with a few safe
// attributes. [RequestLog] writes the name and the attributes next to the request. A handler reports an event after the
// change was saved, and a request reports at most one: a later call replaces the earlier one.
//
// The attributes must hold identifiers and coarse values only, never a secret, a code or a token.
func SetEvent(ctx *fasthttp.RequestCtx, name es.Event, attrs ...slog.Attr) {
	ctx.SetUserValue(keyEvent, event{
		name:  name,
		attrs: eventAttrs(attrs),
	})
}

// requestEvent returns the name and the attributes that [SetEvent] stored for the request. Both are empty if the
// handler reported no event.
func requestEvent(ctx *fasthttp.RequestCtx) (es.Event, string) {
	reported, ok := ctx.UserValue(keyEvent).(event)
	if !ok {
		return "", ""
	}

	return reported.name, reported.attrs
}

// eventAttrs returns the text of attrs: the pairs key=value in the order of the keys, separated by one space. A key or
// a value that is empty or holds a space, an equals sign, a quote, a backslash or a character that is not printable is
// written as a quoted Go string, so that two different lists never give the same text.
func eventAttrs(attrs []slog.Attr) string {
	sorted := slices.Clone(attrs)
	slices.SortStableFunc(sorted, func(a, b slog.Attr) int {
		return strings.Compare(a.Key, b.Key)
	})

	var text strings.Builder
	for i, attr := range sorted {
		if i > 0 {
			text.WriteByte(' ')
		}

		text.WriteString(eventToken(attr.Key))
		text.WriteByte('=')
		text.WriteString(eventToken(attr.Value.Resolve().String()))
	}

	return text.String()
}

// eventToken returns s as it is, or quoted if it is empty or holds a character that separates tokens.
func eventToken(s string) string {
	if s == "" || strings.IndexFunc(s, func(r rune) bool {
		return r == ' ' || r == '=' || r == '"' || r == '\\' || !unicode.IsPrint(r)
	}) >= 0 {
		return strconv.Quote(s)
	}

	return s
}
