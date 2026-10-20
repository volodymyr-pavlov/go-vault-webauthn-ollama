package api

import (
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/geo"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

// HeaderXRequestID is the name of the header that carries the request ID. A client or proxy may set it to link a
// request to its own logs. [RequestLog] keeps the value if it is a UUID and makes a new one if not. It sets the result
// on the response.
const HeaderXRequestID = "x-request-id"

// RequestLog is the middleware that logs every request after its handler has finished. It writes one structured log
// line and one [es.HTTPRequest] row. The row holds the resource code, the method, the path, the status, the error
// number, the security event that the handler reported, the external IDs of the session and the user, the address, the
// duration, the request ID and a few headers.
//
// It never writes a body, a query or a credential: the bodies of this service carry passwords, codes and tokens. A
// failure to save the row is logged and does not change the answer, because the log is a trail for support.
type RequestLog struct {
	Logger      *slog.Logger
	SystemClock clock.Clock
	Locator     *geo.Locator

	// HTTPRequestWriter saves the row of the request.
	HTTPRequestWriter es.Writer[es.HTTPRequest]

	// BuildVersion is the version of the service. It goes into every row.
	BuildVersion string
}

// Middleware returns the middleware for the endpoint with code. It logs after the handler returns, so the row holds the
// session and the user that the inner middleware stored.
func (m *RequestLog) Middleware(code es.ResourceCode) web.Middleware {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(ctx *fasthttp.RequestCtx) error {
			started := m.SystemClock.Now()

			requestID, err := uuid.Parse(string(ctx.Request.Header.Peek(HeaderXRequestID)))
			if err != nil {
				requestID = uuid.New()
			}

			ctx.Response.Header.Set(HeaderXRequestID, requestID.String())

			address := m.Locator.Address(ctx)

			handlerErr := next(ctx)

			status := ctx.Response.StatusCode()
			var num uint16
			var errorText string

			var refusal *web.Error
			if errors.As(handlerErr, &refusal) {
				status = refusal.Status
				num = refusal.Num
			} else if handlerErr != nil {
				status = fasthttp.StatusInternalServerError

				// Only the first step of the error goes into the log, because a database error repeats the value
				// that it refused, such as an email.
				errorText, _, _ = strings.Cut(handlerErr.Error(), ": ")
			}

			userAgent := string(ctx.UserAgent())
			session, _ := Session(ctx)
			user, _ := User(ctx)

			eventName, eventText := requestEvent(ctx)
			if eventName == es.EventUserDeleted {
				// The user is gone, so the row of this request must not name the user, the session, the address or the
				// user agent.
				session = es.Session{}
				user = es.User{}
				address = netip.Addr{}
				userAgent = ""
			}

			place := m.Locator.Place(address)
			duration := m.SystemClock.Now().Sub(started)

			m.Logger.Info("request",
				slog.String("request_id", requestID.String()),
				slog.Uint64("resource", uint64(code)),
				slog.String("method", string(ctx.Method())),
				slog.String("path", string(ctx.Path())),
				slog.Int("status", status),
				slog.Uint64("error", uint64(num)),
				slog.String("event", string(eventName)),
				slog.String("event_attrs", eventText),
				slog.Uint64("session_xid", session.SessionXID),
				slog.Uint64("user_xid", user.UserXID),
				slog.String("ip", logAddress(address)),
				slog.String("country", place.Country),
				slog.Duration("duration", duration),
				slog.Time("at", started.UTC()),
			)

			if status < 0 || status > math.MaxUint16 {
				status = fasthttp.StatusInternalServerError
			}

			durationMs := duration.Milliseconds()
			if durationMs < 0 || durationMs > math.MaxUint32 {
				durationMs = math.MaxUint32
			}

			_, err = m.HTTPRequestWriter.WriteOne(ctx, es.HTTPRequest{
				ResourceCode: code,
				Method:       string(ctx.Method()),
				StatusCode:   uint16(status),
				ErrorCode:    num,
				DurationMs:   uint32(durationMs),
				SessionXID:   session.SessionXID,
				UserXID:      user.UserXID,
				IP:           address,
				Path:         string(ctx.Path()),
				RequestID:    requestID.String(),
				Host:         string(ctx.Host()),
				UserAgent:    userAgent,
				BuildVersion: m.BuildVersion,
				Event:        eventName,
				EventAttrs:   eventText,
				ErrorText:    errorText,
				CreatedAt:    started,
			}, es.WriteCreate)
			if err != nil {
				m.Logger.Error("save the request log row", slog.String("error", err.Error()))
			}

			return handlerErr
		}
	}
}

// logAddress returns the address for a log line with its host part cleared: the last byte of an IPv4 address and
// everything after the first 48 bits of an IPv6 address. A log line then does not name one device. The request log row
// keeps the full address for the retention time. It returns an empty string for an invalid address.
func logAddress(address netip.Addr) string {
	if !address.IsValid() {
		return ""
	}

	bits := 24
	if address.Is6() && !address.Is4In6() {
		bits = 48
	}

	prefix, err := address.Unmap().Prefix(bits)
	if err != nil {
		return ""
	}

	return prefix.String()
}

// exportAddress returns the address for the export of a user. It returns an empty text for an unknown address.
func exportAddress(address netip.Addr) string {
	if !address.IsValid() {
		return ""
	}

	return address.String()
}
