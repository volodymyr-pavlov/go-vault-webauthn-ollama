package web

import (
	"fmt"
	"runtime/debug"
	"slices"

	"github.com/valyala/fasthttp"
)

// Middleware wraps a [HandlerFunc] with behavior that runs before or after it.
type Middleware func(next HandlerFunc) HandlerFunc

// Chain joins first and mw into one [Middleware]. First runs outermost, then the functions of mw in the order given.
func Chain(first Middleware, mw ...Middleware) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		for _, m := range slices.Backward(mw) {
			next = m(next)
		}

		return first(next)
	}
}

// Nop returns a [Middleware] that changes nothing.
func Nop() Middleware {
	return func(next HandlerFunc) HandlerFunc { return next }
}

// Recover returns a [Middleware] that catches a panic in the rest of the chain. It returns the panic and its stack as
// an [ErrInternal] with the panic as the cause.
func Recover() Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *fasthttp.RequestCtx) (err error) {
			defer func() {
				if x := recover(); x != nil {
					err = ErrInternal.Wrap(fmt.Errorf("panic [%v] trace [%s]", x, debug.Stack()))
				}
			}()
			return next(ctx)
		}
	}
}
