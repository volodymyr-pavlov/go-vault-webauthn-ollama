package api

import (
	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

// Origin is the middleware that refuses a request whose Origin header names an origin the service does not allow. It
// also answers the preflight request of the browser.
//
// A browser sends the Origin header on every cross-site request, and a script cannot change it, so the check blocks
// cross-site request forgery. A request with no Origin header, such as one from a native client, passes.
type Origin struct {
	// Origins lists the allowed origins, such as "https://example.com".
	Origins []string
}

// Middleware returns the middleware. For an allowed origin it sets the cross-origin response headers. A preflight
// request ends here with status 204.
//
// The middleware returns [ErrForbiddenOrigin] if the origin is not allowed.
func (m *Origin) Middleware() web.Middleware {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(ctx *fasthttp.RequestCtx) error {
			origin := string(ctx.Request.Header.Peek(fasthttp.HeaderOrigin))
			if origin == "" {
				return next(ctx)
			}

			allowed := false
			for _, candidate := range m.Origins {
				if candidate == origin {
					allowed = true
					break
				}
			}

			if !allowed {
				return ErrForbiddenOrigin
			}

			ctx.Response.Header.Set(fasthttp.HeaderAccessControlAllowOrigin, origin)
			ctx.Response.Header.Set(fasthttp.HeaderVary, fasthttp.HeaderOrigin)

			if ctx.IsOptions() {
				ctx.Response.Header.Set(fasthttp.HeaderAccessControlAllowMethods, "GET, POST, DELETE")
				ctx.Response.Header.Set(fasthttp.HeaderAccessControlAllowHeaders, "Content-Type, Content-Digest, Signature-Input, Signature")
				ctx.Response.Header.Set(fasthttp.HeaderAccessControlMaxAge, "600")
				ctx.SetStatusCode(fasthttp.StatusNoContent)
				return nil
			}

			return next(ctx)
		}
	}
}

// SecurityHeaders returns the middleware that sets the security headers on every response. They turn off caching,
// content type sniffing, framing and the Referer header, require HTTPS and set a content security policy that allows no
// content.
func SecurityHeaders() web.Middleware {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(ctx *fasthttp.RequestCtx) error {
			ctx.Response.Header.Set(fasthttp.HeaderCacheControl, "no-store")
			ctx.Response.Header.Set(fasthttp.HeaderXContentTypeOptions, "nosniff")
			ctx.Response.Header.Set(fasthttp.HeaderXFrameOptions, "DENY")
			ctx.Response.Header.Set(fasthttp.HeaderStrictTransportSecurity, "max-age=31536000; includeSubDomains")
			ctx.Response.Header.Set(fasthttp.HeaderContentSecurityPolicy, "default-src 'none'; frame-ancestors 'none'")
			ctx.Response.Header.Set(fasthttp.HeaderReferrerPolicy, "no-referrer")
			return next(ctx)
		}
	}
}
