package handlers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/plugins/governance"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// CorsMiddleware handles CORS headers for localhost and configured allowed origins
func CorsMiddleware(config *lib.Config) lib.BifrostHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			origin := string(ctx.Request.Header.Peek("Origin"))
			allowed := IsOriginAllowed(origin, config.ClientConfig.AllowedOrigins)
			// Check if origin is allowed (localhost always allowed + configured origins)
			if allowed {
				ctx.Response.Header.Set("Access-Control-Allow-Origin", origin)
				ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				ctx.Response.Header.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
				ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
				ctx.Response.Header.Set("Access-Control-Max-Age", "86400")
			}
			// Handle preflight OPTIONS requests
			if string(ctx.Method()) == "OPTIONS" {
				if allowed {
					ctx.SetStatusCode(fasthttp.StatusOK)
				} else {
					ctx.SetStatusCode(fasthttp.StatusForbidden)
				}
				return
			}
			next(ctx)
		}
	}
}

func TransportInterceptorMiddleware(config *lib.Config) lib.BifrostHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			// Get plugins from config - lock-free read
			plugins := config.GetLoadedPlugins()
			if len(plugins) == 0 {
				next(ctx)
				return
			}

			// If governance plugin is not loaded, skip interception
			hasGovernance := false
			for _, p := range plugins {
				if p.GetName() == governance.PluginName {
					hasGovernance = true
					break
				}
			}
			if !hasGovernance {
				next(ctx)
				return
			}

			// Parse headers
			headers := make(map[string]string)
			originalHeaderNames := make([]string, 0, 16)
			ctx.Request.Header.All()(func(key, value []byte) bool {
				name := string(key)
				headers[name] = string(value)
				originalHeaderNames = append(originalHeaderNames, name)

				return true
			})

			// Unmarshal request body
			requestBody := make(map[string]any)
			bodyBytes := ctx.Request.Body()
			if len(bodyBytes) > 0 {
				if err := json.Unmarshal(bodyBytes, &requestBody); err != nil {
					// If body is not valid JSON, log warning and continue without interception
					logger.Warn(fmt.Sprintf("TransportInterceptor: Failed to unmarshal request body: %v", err))
					next(ctx)
					return
				}
			}

			// Call TransportInterceptor on all plugins
			for _, plugin := range plugins {
				modifiedHeaders, modifiedBody, err := plugin.TransportInterceptor(string(ctx.Request.URI().RequestURI()), headers, requestBody)
				if err != nil {
					logger.Warn(fmt.Sprintf("TransportInterceptor: Plugin '%s' returned error: %v", plugin.GetName(), err))
					// Continue with unmodified headers/body
					continue
				}
				// Update headers and body with modifications
				if modifiedHeaders != nil {
					headers = modifiedHeaders
				}
				if modifiedBody != nil {
					requestBody = modifiedBody
				}
			}

			// Marshal the body back to JSON
			updatedBody, err := json.Marshal(requestBody)
			if err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("TransportInterceptor: Failed to marshal request body: %v", err), logger)
				return
			}
			ctx.Request.SetBody(updatedBody)

			// Remove headers that were present originally but removed by plugins
			for _, name := range originalHeaderNames {
				if _, exists := headers[name]; !exists {
					ctx.Request.Header.Del(name)
				}
			}

			// Set modified headers back on the request
			for key, value := range headers {
				ctx.Request.Header.Set(key, value)
			}

			next(ctx)
		}
	}
}

// ChainMiddlewares chains multiple middlewares together
// Middlewares are applied in order: the first middleware wraps the second, etc.
// This allows earlier middlewares to short-circuit by not calling next(ctx)
func ChainMiddlewares(handler fasthttp.RequestHandler, middlewares ...lib.BifrostHTTPMiddleware) fasthttp.RequestHandler {
	// If no middlewares, return the original handler
	if len(middlewares) == 0 {
		return handler
	}
	// Build the chain from right to left (last middleware wraps the handler)
	// This ensures execution order is left to right (first middleware executes first)
	chained := handler
	for i := len(middlewares) - 1; i >= 0; i-- {
		chained = middlewares[i](chained)
	}
	return chained
}

// AdminAuthMiddleware protects management APIs and the UI when Bifrost is public.
// Auth is satisfied if any of the following is true:
// - Authorization: Bearer <secret> matches configured AdminSecret
// - Cookie <AdminCookieName> equals the AdminSecret
//
// Public endpoints (always allowed):
// - GET /metrics
// - POST /v1/* (OpenAI-compatible inference APIs)
// - POST /openai/* and /openai/v1/* (OpenAI-compatible inference APIs)
// - GET /openai/models and /openai/v1/models
// - Static UI assets under /ui/_next/ and /ui/assets/ if login page needs them (we keep UI behind auth except /login)
// - GET/POST /admin/login (login form)
// - GET /api/version (safe)
//
// On unauthorized browser requests for HTML, this middleware redirects to /admin/login?next=<path>.
// On API requests (Accept: application/json or X-Requested-With), it returns 401 JSON.
func AdminAuthMiddleware(config *lib.Config, logger schemas.Logger) lib.BifrostHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			// If no admin secret configured, allow all
			if strings.TrimSpace(config.AdminSecret) == "" {
				next(ctx)
				return
			}

			method := string(ctx.Method())
			path := string(ctx.Path())

			// Allowlist public paths
			if isPublicPath(method, path) {
				next(ctx)
				return
			}

			// Check Authorization header: Bearer <secret>
			if auth := string(ctx.Request.Header.Peek("Authorization")); auth != "" {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(auth)), "bearer ") {
					token := strings.TrimSpace(auth[len("Bearer "):])
					if token == config.AdminSecret {
						next(ctx)
						return
					}
				}
			}

			// Check cookie
			if c := string(ctx.Request.Header.Cookie(config.AdminCookieName)); c != "" && c == config.AdminSecret {
				next(ctx)
				return
			}

			// Unauthorized: decide redirect vs JSON
			accepts := string(ctx.Request.Header.Peek("Accept"))
			xrw := string(ctx.Request.Header.Peek("X-Requested-With"))
			wantsJSON := strings.Contains(strings.ToLower(accepts), "application/json") || strings.EqualFold(xrw, "XMLHttpRequest") || strings.HasPrefix(path, "/api/")

			if wantsJSON || strings.HasPrefix(path, "/v1/") || strings.HasPrefix(path, "/api/") {
				SendError(ctx, fasthttp.StatusUnauthorized, "admin authentication required", logger)
				return
			}

			// Redirect to login with next parameter
			nextParam := url.QueryEscape(path)
			ctx.Response.Header.Set("Location", "/admin/login?next="+nextParam)
			ctx.SetStatusCode(fasthttp.StatusFound)
		}
	}
}

func isPublicPath(method, path string) bool {
	if path == "/metrics" && method == fasthttp.MethodGet {
		return true
	}
	if strings.HasPrefix(path, "/v1/") && method == fasthttp.MethodPost {
		return true
	}
	// OpenAI-compatible routes under /openai and /openai/v1 should be public for inference
	if (strings.HasPrefix(path, "/openai/") || strings.HasPrefix(path, "/openai/v1/")) && method == fasthttp.MethodPost {
		return true
	}
	if (path == "/openai/models" || path == "/openai/v1/models") && method == fasthttp.MethodGet {
		return true
	}
	if strings.HasPrefix(path, "/admin/login") { // GET or POST
		return true
	}
	if path == "/api/version" && method == fasthttp.MethodGet {
		return true
	}
	return false
}
