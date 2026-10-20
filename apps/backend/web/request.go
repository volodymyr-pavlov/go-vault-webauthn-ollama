package web

import (
	"strconv"

	"github.com/valyala/fasthttp"
)

// Unsigned is the set of unsigned integer types that [ParamUint] can return.
type Unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

// ParamString returns the part of the path that the route names key. It returns an empty string if the route has no
// such part.
func ParamString(ctx *fasthttp.RequestCtx, key string) string {
	value, _ := ctx.UserValue(key).(string)
	return value
}

// ParamUint returns the part of the path that the route names key, as an unsigned integer. It returns 0 if the route
// has no such part, if the part is not a decimal number, or if the number does not fit T. A caller that treats 0 as a
// missing value needs no second check.
func ParamUint[T Unsigned](ctx *fasthttp.RequestCtx, key string) T {
	number, err := strconv.ParseUint(ParamString(ctx, key), 10, 64)
	if err != nil || uint64(T(number)) != number {
		return 0
	}

	return T(number)
}
