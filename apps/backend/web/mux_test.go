package web

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

var errBadID = &Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     901,
	Code:    "BAD_ID",
	Message: "The listener id is bad.",
}
var errCannot = &Error{
	Status:  fasthttp.StatusInternalServerError,
	Num:     902,
	Code:    "CANNOT",
	Message: "Cannot connect.",
}
var errOther = &Error{
	Status:  fasthttp.StatusInternalServerError,
	Num:     903,
	Code:    "OTHER",
	Message: "Other.",
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// request sends one request through m without a network and returns the response.
func request(m *Mux, method, target, body string) *fasthttp.Response {
	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(method)
	ctx.Request.SetRequestURI(target)
	ctx.Request.SetBodyString(body)
	m.Handler()(&ctx)
	return &ctx.Response
}

func serve(m *Mux, target string) *fasthttp.Response {
	return request(m, fasthttp.MethodGet, target, "")
}

func TestMuxWritesTheResponseOfAnErrorWithAStatus(t *testing.T) {
	m := NewMux(quietLogger(), nil)
	m.GET("/x", HandlerFunc(func(*fasthttp.RequestCtx) error { return errBadID }))

	res := serve(m, "/x")

	if res.StatusCode() != fasthttp.StatusBadRequest || string(res.Body()) != `{"error":{"status":400,"num":901,"code":"BAD_ID","message":"The listener id is bad."}}` {
		t.Fatalf("got %d %q, want 400 and the error in the envelope", res.StatusCode(), res.Body())
	}
}

func TestMuxHidesTheCauseOfAnInternalError(t *testing.T) {
	m := NewMux(quietLogger(), nil)
	m.GET("/x", HandlerFunc(func(*fasthttp.RequestCtx) error {
		return errors.New("secret detail")
	}))

	res := serve(m, "/x")

	if res.StatusCode() != fasthttp.StatusInternalServerError || strings.Contains(string(res.Body()), "secret") {
		t.Fatalf("got %d %q, want 500 without the cause", res.StatusCode(), res.Body())
	}
}

func TestErrorMatchesItsOriginalByNumberAfterWrap(t *testing.T) {
	wrapped := errCannot.Wrap(errors.New("boom"))

	if !errors.Is(wrapped, errCannot) || errors.Is(wrapped, errOther) {
		t.Fatal("a wrapped error must match its own code and no other")
	}
}

func TestRecoverTurnsAPanicIntoAnInternalError(t *testing.T) {
	m := NewMux(quietLogger(), Recover())
	m.GET("/x", HandlerFunc(func(*fasthttp.RequestCtx) error { panic("oops") }))

	res := serve(m, "/x")

	if res.StatusCode() != fasthttp.StatusInternalServerError || strings.Contains(string(res.Body()), "oops") {
		t.Fatalf("got %d %q, want 500 without the panic text", res.StatusCode(), res.Body())
	}
}

func TestChainRunsTheFirstMiddlewareOutermost(t *testing.T) {
	var order []string
	tag := func(name string) Middleware {
		return func(next HandlerFunc) HandlerFunc {
			return func(ctx *fasthttp.RequestCtx) error {
				order = append(order, name)
				return next(ctx)
			}
		}
	}
	m := NewMux(quietLogger(), tag("mux"))
	m.GET("/x", HandlerFunc(func(*fasthttp.RequestCtx) error {
		order = append(order, "handler")
		return nil
	}), tag("a"), tag("b"))

	serve(m, "/x")

	if got := strings.Join(order, ","); got != "mux,a,b,handler" {
		t.Fatalf("got order %s, want mux,a,b,handler", got)
	}
}

func TestMuxServesAPlainHandlerOutsideTheMiddleware(t *testing.T) {
	m := NewMux(quietLogger(), func(HandlerFunc) HandlerFunc {
		return func(*fasthttp.RequestCtx) error { return ErrInternal }
	})
	m.Plain("/plain", func(ctx *fasthttp.RequestCtx) { ctx.SetBodyString("ok") })

	res := serve(m, "/plain")

	if res.StatusCode() != fasthttp.StatusOK || string(res.Body()) != "ok" {
		t.Fatalf("got %d %q, want the plain handler's own response", res.StatusCode(), res.Body())
	}
}

func TestMuxServesWhatMatchesNoRouteWithNotFound(t *testing.T) {
	m := NewMux(quietLogger(), nil)
	m.NotFound(func(ctx *fasthttp.RequestCtx) { ctx.SetBodyString("page") })

	res := serve(m, "/anything")

	if string(res.Body()) != "page" {
		t.Fatalf("got %q, want the response of NotFound", res.Body())
	}
}

func TestWriteWrapsTheDataAndWriteRawDoesNot(t *testing.T) {
	var enveloped, raw fasthttp.RequestCtx

	if err := Write(&enveloped, fasthttp.StatusOK, map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}

	if err := WriteRaw(&raw, fasthttp.StatusOK, map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}

	if string(enveloped.Response.Body()) != `{"data":{"n":1}}` || string(raw.Response.Body()) != `{"n":1}` {
		t.Fatalf("got %q and %q", enveloped.Response.Body(), raw.Response.Body())
	}

	if string(enveloped.Response.Header.ContentType()) != "application/json" {
		t.Fatalf("content type %q", enveloped.Response.Header.ContentType())
	}
}

func TestMuxRoutesByMethodAndReadsThePathPart(t *testing.T) {
	m := NewMux(quietLogger(), nil)
	m.POST("/x/{id}", HandlerFunc(func(ctx *fasthttp.RequestCtx) error {
		return Write(ctx, fasthttp.StatusCreated, ParamString(ctx, "id"))
	}))

	post := request(m, fasthttp.MethodPost, "/x/42", "")
	get := serve(m, "/x/42")

	if post.StatusCode() != fasthttp.StatusCreated || string(post.Body()) != `{"data":"42"}` {
		t.Fatalf("POST gave %d %q, want 201 and the id", post.StatusCode(), post.Body())
	}

	if get.StatusCode() != fasthttp.StatusMethodNotAllowed {
		t.Fatalf("GET gave %d, want 405", get.StatusCode())
	}
}

func TestErrorHandlerRespondsToABodyThatIsTooLarge(t *testing.T) {
	m := NewMux(quietLogger(), nil)
	m.POST("/x", HandlerFunc(func(*fasthttp.RequestCtx) error { return nil }))
	server := &fasthttp.Server{
		Handler:            m.Handler(),
		MaxRequestBodySize: 8,
		ErrorHandler:       ErrorHandler,
		Logger:             discardLogger{},
	}
	listener := fasthttputil.NewInmemoryListener()
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Shutdown() }()

	conn, err := listener.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn, "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\n"+strings.Repeat("x", 100)); err != nil {
		t.Fatal(err)
	}

	var res fasthttp.Response

	if err := res.Read(bufioReader(conn)); err != nil {
		t.Fatal(err)
	}

	if res.StatusCode() != fasthttp.StatusRequestEntityTooLarge || !strings.Contains(string(res.Body()), "TOO_LARGE_BODY") {
		t.Fatalf("got %d %q, want 413 and the code", res.StatusCode(), res.Body())
	}
}

func bufioReader(r io.Reader) *bufio.Reader {
	return bufio.NewReader(r)
}

// discardLogger is a fasthttp logger that drops every message.
type discardLogger struct{}

func (discardLogger) Printf(string, ...any) {}

func TestMuxLogsAnErrorResponseThatCannotBeWrittenAndResponds500(t *testing.T) {
	var logged strings.Builder
	m := NewMux(slog.New(slog.NewTextHandler(&logged, nil)), nil)
	m.GET("/x", HandlerFunc(func(*fasthttp.RequestCtx) error {
		return errBadID.With(Params{"id": make(chan int)})
	}))

	res := serve(m, "/x")

	if res.StatusCode() != fasthttp.StatusInternalServerError || !strings.Contains(logged.String(), "could not write the error response") {
		t.Fatalf("got %d, log %q, want 500 and a log line", res.StatusCode(), logged.String())
	}
}

func TestParamUintReadsADecimalNumberAndGivesZeroForAnythingElse(t *testing.T) {
	for text, want := range map[string]uint64{
		"42":                   42,
		"0":                    0,
		"":                     0,
		"abc":                  0,
		"-1":                   0,
		"4x":                   0,
		"18446744073709551615": 18446744073709551615,
		"18446744073709551616": 0,
	} {
		var ctx fasthttp.RequestCtx
		ctx.SetUserValue("id", text)

		if got := ParamUint[uint64](&ctx, "id"); got != want {
			t.Errorf("ParamUint(%q) = %d, want %d", text, got, want)
		}
	}
}

func TestParamUintGivesZeroForANumberThatDoesNotFitTheType(t *testing.T) {
	var ctx fasthttp.RequestCtx
	ctx.SetUserValue("n", "300")

	if got := ParamUint[uint8](&ctx, "n"); got != 0 {
		t.Fatalf("got %d, want 0, not 300 cut to 44", got)
	}

	if got := ParamUint[uint16](&ctx, "n"); got != 300 {
		t.Fatalf("got %d, want 300", got)
	}

	if got := ParamUint[uint64](&ctx, "missing"); got != 0 {
		t.Fatalf("got %d for a missing part, want 0", got)
	}
}

func TestPreflightRunsItsMiddlewareForOptions(t *testing.T) {
	m := NewMux(quietLogger(), nil)
	m.Handle(fasthttp.MethodGet, "/thing", HandlerFunc(func(ctx *fasthttp.RequestCtx) error { return nil }))

	var seen bool
	m.Preflight(func(next HandlerFunc) HandlerFunc {
		return func(ctx *fasthttp.RequestCtx) error {
			seen = true
			return next(ctx)
		}
	})

	response := request(m, fasthttp.MethodOptions, "/thing", "")
	if !seen || response.StatusCode() != fasthttp.StatusNoContent {
		t.Fatalf("preflight: middleware ran %t, status %d, want true and 204", seen, response.StatusCode())
	}
}
