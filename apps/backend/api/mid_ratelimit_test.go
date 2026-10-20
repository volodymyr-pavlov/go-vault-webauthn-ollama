package api

import (
	"errors"
	"net"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/geo"
)

func TestRateLimitByAddress(t *testing.T) {
	server := miniredis.RunT(t)

	locator, err := geo.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	limit := &RateLimit{
		Limiter: redis_rate.NewLimiter(redis.NewClient(&redis.Options{
			Addr: server.Addr(),
		})),
		Address: redis_rate.PerMinute(2),
		Locator: locator,
	}
	handler := limit.Middleware()(func(*fasthttp.RequestCtx) error {
		return nil
	})
	call := func(ip string) error {
		var ctx fasthttp.RequestCtx
		ctx.Init(&fasthttp.Request{}, &net.TCPAddr{
			IP:   net.ParseIP(ip),
			Port: 1234,
		}, nil)
		err := handler(&ctx)
		if errors.Is(err, ErrTooManyRequests) && string(ctx.Response.Header.Peek(fasthttp.HeaderRetryAfter)) == "" {
			t.Fatal("a refusal must say when to retry")
		}
		return err
	}
	for i := range 2 {
		if err := call("203.0.113.1"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}

	if err := call("203.0.113.1"); !errors.Is(err, ErrTooManyRequests) {
		t.Fatalf("the third request: %v, want ErrTooManyRequests", err)
	}

	if err := call("203.0.113.2"); err != nil {
		t.Fatalf("another address: %v", err)
	}

	account, err := limit.WriteOne(t.Context(), es.RateLimit{Key: "alice"}, es.WriteCreate)
	if err != nil || account.Wait != 0 {
		t.Fatalf("the first request of an account: %v, %v", account.Wait, err)
	}

	if _, err := limit.WriteOne(t.Context(), es.RateLimit{Key: "alice"}, 0); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("a write that does not create: %v, want ErrNoArguments", err)
	}
}

func TestRateLimitByAccount(t *testing.T) {
	server := miniredis.RunT(t)
	limit := &RateLimit{
		Limiter: redis_rate.NewLimiter(redis.NewClient(&redis.Options{
			Addr: server.Addr(),
		})),
		Account: redis_rate.PerMinute(2),
	}
	reached := 0
	handler := limit.AccountMiddleware()(func(*fasthttp.RequestCtx) error {
		reached++
		return nil
	})
	call := func(body string) (string, error) {
		var ctx fasthttp.RequestCtx
		ctx.Init(&fasthttp.Request{}, &net.TCPAddr{
			IP:   net.ParseIP("203.0.113.1"),
			Port: 1234,
		}, nil)
		ctx.Request.SetBodyString(body)
		err := handler(&ctx)
		return string(ctx.Response.Header.Peek(fasthttp.HeaderRetryAfter)), err
	}
	for i := range 2 {
		if _, err := call(`{"email":"alice@example.com"}`); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}

	retryAfter, err := call(`{"email":" Alice@Example.com "}`)
	if !errors.Is(err, ErrTooManyRequests) || retryAfter == "" {
		t.Fatalf("the third request in another case: %v, Retry-After %q, want ErrTooManyRequests with a retry", err, retryAfter)
	}

	if _, err := call(`{"email":"bob@example.com"}`); err != nil {
		t.Fatalf("another account: %v", err)
	}

	if _, err := call(`{"token":"abcd"}`); err != nil {
		t.Fatalf("a body with no email: %v", err)
	}

	if reached != 4 {
		t.Fatalf("the handler ran %d times, want 4", reached)
	}
}
