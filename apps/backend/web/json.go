package web

import (
	"github.com/valyala/bytebufferpool"
	"github.com/valyala/fasthttp"
)

// Response is the JSON envelope of a response. It holds Data on success and Error on failure, and leaves out an empty
// field.
type Response struct {
	Error error `json:"error,omitempty"`
	Data  any   `json:"data,omitempty"`
}

// Write writes data as the Data of a successful [Response] with the given status.
func Write(ctx *fasthttp.RequestCtx, status int, data any) error {
	return WriteRaw(ctx, status, Response{Data: data})
}

// WriteError writes err as the Error of a failed [Response] with the given status.
func WriteError(ctx *fasthttp.RequestCtx, status int, err error) error {
	return WriteRaw(ctx, status, Response{Error: err})
}

// WriteRaw writes v as a JSON response with the given status, without the [Response] envelope. It encodes v with
// [EncodeJSON] and copies the pooled bytes into the response.
//
// It returns the error of the encoder if v does not encode. Then nothing is written, so the [Mux] can write an error
// response instead.
func WriteRaw(ctx *fasthttp.RequestCtx, status int, v any) error {
	bp, err := EncodeJSON(v)
	if err != nil {
		return err
	}
	defer bytebufferpool.Put(bp)
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(status)
	ctx.SetBody(bp.B)
	return nil
}
