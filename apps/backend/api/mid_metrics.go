package api

import (
	"errors"

	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/metrics"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

// authFactors maps the endpoints that check a factor to the factor. A 401 from one of them is a failed authentication.
var authFactors = map[es.ResourceCode]es.Factors{
	AuthorizePassword:        es.FactorPassword,
	AuthorizeTOTP:            es.FactorTOTP,
	CompleteAuthorizePasskey: es.FactorPasskey,
	AuthorizeRecovery:        es.FactorRecoveryCode,
}

// Observe is the middleware that records the metrics of every request: the count by resource and status, the duration,
// the opened sessions, the failed factors and the refused recovery steps.
type Observe struct {
	Metrics     *metrics.Metrics
	SystemClock clock.Clock
}

// Middleware returns the middleware for the endpoint with code. It records after the handler returns, with the status
// that the client gets.
func (m *Observe) Middleware(code es.ResourceCode) web.Middleware {
	name := ResourceName(code)

	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(ctx *fasthttp.RequestCtx) error {
			started := m.SystemClock.Now()
			handlerErr := next(ctx)

			status := ctx.Response.StatusCode()

			var refusal *web.Error
			if errors.As(handlerErr, &refusal) {
				status = refusal.Status
			} else if handlerErr != nil {
				status = fasthttp.StatusInternalServerError
			}

			m.Metrics.Request(name, status, m.SystemClock.Now().Sub(started))

			switch {
			case code == BeginSession && status == fasthttp.StatusCreated:
				m.Metrics.Session(metrics.SessionOpened, 1)
			case status == fasthttp.StatusUnauthorized:
				if factor, ok := authFactors[code]; ok {
					m.Metrics.AuthFailure(factor)
				}

				switch code {
				case ClaimRecovery, GrantRecovery, CancelRecovery:
					m.Metrics.Recovery(metrics.RecoveryRefused)
				}
			}

			return handlerErr
		}
	}
}
