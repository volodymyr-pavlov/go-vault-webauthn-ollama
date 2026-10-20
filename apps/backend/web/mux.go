package web

import (
	"errors"
	"log/slog"

	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

// Mux maps methods and paths to handlers and turns any error they return into a response. A path can contain a named
// part, as in "/listen/{id}". [ParamString] and [ParamUint] read that part.
type Mux struct {
	router *router.Router
	logger *slog.Logger
	mw     Middleware
}

// NewMux returns a [Mux] in which mw runs outermost for every handler. If logger is nil, it uses [slog.Default]. If mw
// is nil, it uses [Nop].
func NewMux(logger *slog.Logger, mw Middleware) *Mux {
	if logger == nil {
		logger = slog.Default()
	}

	if mw == nil {
		mw = Nop()
	}

	return &Mux{
		router: router.New(),
		logger: logger,
		mw:     mw,
	}
}

// GET serves GET requests to path with handler. The middleware of the [Mux] runs first, then mw in the order given.
// [Mux.POST] and [Mux.DELETE] do the same for their methods.
func (m *Mux) GET(path string, handler Handler, mw ...Middleware) {
	m.Handle(fasthttp.MethodGet, path, handler, mw...)
}

// POST serves POST requests to path with handler. See [Mux.GET].
func (m *Mux) POST(path string, handler Handler, mw ...Middleware) {
	m.Handle(fasthttp.MethodPost, path, handler, mw...)
}

// DELETE serves DELETE requests to path with handler. See [Mux.GET].
func (m *Mux) DELETE(path string, handler Handler, mw ...Middleware) {
	m.Handle(fasthttp.MethodDelete, path, handler, mw...)
}

// Handle serves requests with the given method and path with handler. The middleware of the [Mux] runs first, then mw
// in the order given. A non-nil error of the handler becomes the response.
func (m *Mux) Handle(method, path string, handler Handler, mw ...Middleware) {
	wrapped := Chain(m.mw, mw...)(handler.ServeHTTP)
	m.router.Handle(method, path, func(ctx *fasthttp.RequestCtx) {
		if err := wrapped(ctx); err != nil {
			m.fail(ctx, err)
		}
	})
}

// Preflight serves the OPTIONS requests of the browser with mw, which runs outermost, and then answers with status 204.
// The [Mux] middleware does not run for them. A middleware may answer the request itself, as the origin check of the
// API does for an allowed origin.
func (m *Mux) Preflight(mw Middleware) {
	wrapped := mw(func(ctx *fasthttp.RequestCtx) error {
		ctx.SetStatusCode(fasthttp.StatusNoContent)

		return nil
	})
	m.router.GlobalOPTIONS = func(ctx *fasthttp.RequestCtx) {
		if err := wrapped(ctx); err != nil {
			m.fail(ctx, err)
		}
	}
}

// Plain serves GET requests to path with h. The handler h writes its own response, and no middleware runs for it.
func (m *Mux) Plain(path string, h fasthttp.RequestHandler) {
	m.router.GET(path, h)
}

// NotFound serves the requests that match no route with h. The handler h writes its own response, and no middleware
// runs for it.
func (m *Mux) NotFound(h fasthttp.RequestHandler) {
	m.router.NotFound = h
}

// Handler returns the fasthttp handler of the [Mux].
func (m *Mux) Handler() fasthttp.RequestHandler {
	return m.router.Handler
}

// fail writes the error response for err. It also logs err if the status is a server error.
func (m *Mux) fail(ctx *fasthttp.RequestCtx, err error) {
	e := asError(err)
	if e.Status >= fasthttp.StatusInternalServerError {
		m.logger.Error("request failed", "method", string(ctx.Method()), "path", string(ctx.Path()), "err", err)
	}

	if err := WriteError(ctx, e.Status, e); err != nil {
		m.logger.Error("could not write the error response",
			"method", string(ctx.Method()), "path", string(ctx.Path()), "err", err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
	}
}

// ErrorHandler is the fasthttp error handler for a request that the server cannot read. It responds to a body that is
// too large with [ErrTooLargeBody], to a header that is too large with a plain text status, and to any other failure
// with a plain text 400 status.
func ErrorHandler(ctx *fasthttp.RequestCtx, err error) {
	var smallBuffer *fasthttp.ErrSmallBuffer
	switch {
	case errors.Is(err, fasthttp.ErrBodyTooLarge):
		if err := WriteError(ctx, ErrTooLargeBody.Status, ErrTooLargeBody); err != nil {
			ctx.Logger().Printf("could not write the error response: %v", err)
		}
	case errors.As(err, &smallBuffer):
		ctx.Error("The request header is too large.", fasthttp.StatusRequestHeaderFieldsTooLarge)
	default:
		ctx.Error("The request could not be read.", fasthttp.StatusBadRequest)
	}
}
