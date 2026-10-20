package api

import (
	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &HealthzHandler{}

// HealthzHandlerResult is the response of GET /healthz.
type HealthzHandlerResult struct {
	Status string `json:"status"`
}

// HealthzHandler handles GET /healthz. It reports that the service is up and checks nothing else, so the response
// reveals nothing about the state of the service.
type HealthzHandler struct{}

// ServeHTTP implements [web.Handler].
func (h *HealthzHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	return web.Write(ctx, fasthttp.StatusOK, HealthzHandlerResult{
		Status: "ok",
	})
}
