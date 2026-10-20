package web

import "github.com/valyala/fasthttp"

var _ Handler = HandlerFunc(nil)

// Handler handles one request and returns an error instead of writing the error response. The [Mux] turns a returned
// error into the response.
type Handler interface {
	ServeHTTP(ctx *fasthttp.RequestCtx) error
}

// HandlerFunc lets a plain function act as a [Handler].
type HandlerFunc func(ctx *fasthttp.RequestCtx) error

// ServeHTTP calls f.
func (f HandlerFunc) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	return f(ctx)
}
