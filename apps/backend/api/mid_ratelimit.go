package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/geo"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/metrics"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

const (
	// DefaultAddressPerMinute is the number of requests per minute that one address may send. DefaultUserPerMinute
	// is the same for one user. DefaultGlobalPerSecond is the number of requests per second that all callers share.
	// A request over a budget is refused with status 429 and a Retry-After header. The budgets live in Redis, so every
	// instance of the service shares them.
	DefaultAddressPerMinute = 60
	DefaultUserPerMinute    = 20
	DefaultGlobalPerSecond  = 500

	// DefaultSessionPerMinute is the number of sessions per minute that one address may open. A session is a database
	// row that anyone can ask for, so this budget is lower than the one for all requests.
	DefaultSessionPerMinute = 20

	// GlobalKey is the key of the budget that all requests share.
	GlobalKey = "global"
)

var _ es.Writer[es.RateLimit] = &RateLimit{}

// RateLimit limits the rate of requests with the GCRA limiter of redis_rate. [RateLimit.Middleware] limits by address
// and for the whole service. [RateLimit.UserMiddleware] limits by the email in the request body.
type RateLimit struct {
	// Limiter counts the requests in Redis.
	Limiter *redis_rate.Limiter

	// Address, User and Global are the budgets for one address, one user and the whole service. A zero budget
	// means the default.
	Address redis_rate.Limit
	User    redis_rate.Limit
	Global  redis_rate.Limit

	// SessionOpen is the budget of one address for opening sessions. A zero budget means the default.
	SessionOpen redis_rate.Limit

	Locator *geo.Locator

	// Metrics counts the refused requests by scope. It may be nil.
	Metrics *metrics.Metrics
}

// WriteOne implements [es.Writer]. With [es.WriteCreate] it takes one slot of the user budget for the Key of item
// and returns item with Wait set. Wait is how long the caller must wait if the budget is spent, and zero if the request
// may run now.
//
// It returns [es.ErrNoArguments] if op is not a create or the key is empty.
func (m *RateLimit) WriteOne(ctx context.Context, item es.RateLimit, op es.Op) (es.RateLimit, error) {
	if !es.IsCreate(op) || item.Key == "" {
		return item, es.ErrNoArguments
	}

	limit := m.User
	if limit.IsZero() {
		limit = redis_rate.PerMinute(DefaultUserPerMinute)
	}

	result, err := m.Limiter.Allow(ctx, "user:"+item.Key, limit)
	if err != nil {
		return item, fmt.Errorf("rate limit by user: %w", err)
	}

	item.Wait = 0

	if result.Allowed == 0 {
		item.Wait = result.RetryAfter
	}

	return item, nil
}

// UserMiddleware returns the middleware that limits the rate by user. It reads the email from the JSON body and
// takes one slot of the user budget for the SHA-256 hash of the email. A body with no email passes, and the handler
// refuses it.
//
// The middleware returns [ErrTooManyRequests] with a Retry-After header if the budget is spent.
//
// Run it after the session middleware, so that a request without a valid session does not use a slot.
func (m *RateLimit) UserMiddleware() web.Middleware {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(ctx *fasthttp.RequestCtx) error {
			email := strings.ToLower(strings.TrimSpace(gjson.GetBytes(ctx.PostBody(), "email").String()))
			if email == "" {
				return next(ctx)
			}

			key := sha256.Sum256([]byte(email))

			limit, err := m.WriteOne(ctx, es.RateLimit{
				Key: hex.EncodeToString(key[:]),
			}, es.WriteCreate)
			if err != nil {
				return err
			}

			if limit.Wait > 0 {
				m.Metrics.RateLimited(metrics.ScopeUser)

				return tooManyRequests(ctx, limit.Wait)
			}

			return next(ctx)
		}
	}
}

// SessionOpenMiddleware returns the middleware that limits how many sessions one address may open.
//
// The middleware returns [ErrTooManyRequests] with a Retry-After header if the budget is spent.
func (m *RateLimit) SessionOpenMiddleware() web.Middleware {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(ctx *fasthttp.RequestCtx) error {
			limit := m.SessionOpen
			if limit.IsZero() {
				limit = redis_rate.PerMinute(DefaultSessionPerMinute)
			}

			result, err := m.Limiter.Allow(ctx, "session:"+m.Locator.Address(ctx).String(), limit)
			if err != nil {
				return fmt.Errorf("rate limit by address for sessions: %w", err)
			}

			if result.Allowed == 0 {
				m.Metrics.RateLimited(metrics.ScopeSessionOpen)

				return tooManyRequests(ctx, result.RetryAfter)
			}

			return next(ctx)
		}
	}
}

// Middleware returns the middleware that limits the rate by address and for the whole service.
//
// The middleware returns [ErrTooManyRequests] with a Retry-After header if either budget is spent. The header holds the
// longer of the two waits, in whole seconds.
func (m *RateLimit) Middleware() web.Middleware {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(ctx *fasthttp.RequestCtx) error {
			global := m.Global
			if global.IsZero() {
				global = redis_rate.PerSecond(DefaultGlobalPerSecond)
			}

			result, err := m.Limiter.Allow(ctx, GlobalKey, global)
			if err != nil {
				return fmt.Errorf("rate limit globally: %w", err)
			}

			wait := time.Duration(0)
			globalWait := time.Duration(0)
			if result.Allowed == 0 {
				wait = result.RetryAfter
				globalWait = wait
			}

			address := m.Address
			if address.IsZero() {
				address = redis_rate.PerMinute(DefaultAddressPerMinute)
			}

			result, err = m.Limiter.Allow(ctx, "address:"+m.Locator.Address(ctx).String(), address)
			if err != nil {
				return fmt.Errorf("rate limit by address: %w", err)
			}

			addressWait := time.Duration(0)
			if result.Allowed == 0 {
				addressWait = result.RetryAfter
			}

			if addressWait > wait {
				wait = addressWait
			}

			if wait > 0 {
				if globalWait > 0 {
					m.Metrics.RateLimited(metrics.ScopeGlobal)
				}

				if addressWait > 0 {
					m.Metrics.RateLimited(metrics.ScopeAddress)
				}

				return tooManyRequests(ctx, wait)
			}

			return next(ctx)
		}
	}
}

// tooManyRequests sets the Retry-After header to wait, rounded up to whole seconds, and returns [ErrTooManyRequests]
// with the same number.
func tooManyRequests(ctx *fasthttp.RequestCtx, wait time.Duration) error {
	seconds := int64(wait / time.Second)
	if wait%time.Second != 0 {
		seconds++
	}

	ctx.Response.Header.Set(fasthttp.HeaderRetryAfter, strconv.FormatInt(seconds, 10))

	return ErrTooManyRequests.With(web.Params{
		"retry_after": seconds,
	})
}
