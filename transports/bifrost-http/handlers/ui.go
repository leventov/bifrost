package handlers

import (
	"embed"
	"fmt"
	"mime"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// UIHandler handles UI routes.
type UIHandler struct {
	uiContent embed.FS
	config    *lib.Config
	logger    schemas.Logger
}

// NewUIHandler creates a new UIHandler instance.
func NewUIHandler(uiContent embed.FS) *UIHandler {
	return &UIHandler{
		uiContent: uiContent,
	}
}

// NewUIHandlerWithDeps constructs UIHandler with config and logger dependencies.
func NewUIHandlerWithDeps(uiContent embed.FS, config *lib.Config, logger schemas.Logger) *UIHandler {
	return &UIHandler{uiContent: uiContent, config: config, logger: logger}
}

// RegisterRoutes registers the UI routes with the provided router.
func (h *UIHandler) RegisterRoutes(router *router.Router, middlewares ...lib.BifrostHTTPMiddleware) {
	// Admin login/logout endpoints (public)
	router.GET("/admin/login", h.loginPage)
	router.POST("/admin/login", h.loginSubmit)
	router.GET("/admin/logout", h.logout)
	// UI routes (protected via AdminAuthMiddleware when wired globally)
	router.GET("/", lib.ChainMiddlewares(h.serveDashboard, middlewares...))
	router.GET("/{filepath:*}", lib.ChainMiddlewares(h.serveDashboard, middlewares...))
}

// ServeDashboard serves the dashboard UI.
func (h *UIHandler) serveDashboard(ctx *fasthttp.RequestCtx) {
	// Get the request path
	requestPath := string(ctx.Path())

	// Clean the path to prevent directory traversal
	cleanPath := path.Clean(requestPath)

	// Handle .txt files (Next.js RSC payload files) - map from /{page}.txt to /{page}/index.txt
	if strings.HasSuffix(cleanPath, ".txt") {
		// Remove .txt extension and add /index.txt
		basePath := strings.TrimSuffix(cleanPath, ".txt")
		if basePath == "/" || basePath == "" {
			basePath = "/index"
		}
		cleanPath = basePath + "/index.txt"
	}

	// Remove leading slash and add ui prefix
	if cleanPath == "/" {
		cleanPath = "ui/index.html"
	} else {
		cleanPath = "ui" + cleanPath
	}

	// Check if this is a static asset request (has file extension)
	hasExtension := strings.Contains(filepath.Base(cleanPath), ".")

	// Try to read the file from embedded filesystem
	data, err := h.uiContent.ReadFile(cleanPath)
	if err != nil {

		// If it's a static asset (has extension) and not found, return 404
		if hasExtension {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString("404 - Static asset not found: " + requestPath)
			return
		}

		// For routes without extensions (SPA routing), try {path}/index.html first
		if !hasExtension {
			indexPath := cleanPath + "/index.html"
			data, err = h.uiContent.ReadFile(indexPath)
			if err == nil {
				cleanPath = indexPath
			} else {
				// If that fails, serve root index.html as fallback
				data, err = h.uiContent.ReadFile("ui/index.html")
				if err != nil {
					ctx.SetStatusCode(fasthttp.StatusNotFound)
					ctx.SetBodyString("404 - File not found")
					return
				}
				cleanPath = "ui/index.html"
			}
		} else {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString("404 - File not found")
			return
		}
	}

	// Set content type based on file extension
	ext := filepath.Ext(cleanPath)
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	ctx.SetContentType(contentType)

	// Set cache headers for static assets
	if strings.HasPrefix(cleanPath, "ui/_next/static/") {
		ctx.Response.Header.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else if ext == ".html" {
		ctx.Response.Header.Set("Cache-Control", "no-cache")
	} else {
		ctx.Response.Header.Set("Cache-Control", "public, max-age=3600")
	}

	// Send the file content
	ctx.SetBody(data)
}

// loginPage renders a simple password form with instructions.
func (h *UIHandler) loginPage(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("text/html; charset=utf-8")
	next := string(ctx.QueryArgs().Peek("next"))
	if next == "" {
		next = "/"
	}
	body := fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><title>Bifrost Admin Login</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;max-width:420px;margin:10vh auto;padding:24px}form{display:flex;flex-direction:column;gap:12px}input[type=password]{padding:10px;font-size:16px}button{padding:10px 14px;font-size:16px;cursor:pointer}</style>
</head><body>
<h2>Admin Login</h2>
<p>To obtain the admin password, run <code>operator bifrost password</code> locally.</p>
<form method="post" action="/admin/login">
  <input type="hidden" name="next" value="%s" />
  <label>Password</label>
  <input type="password" name="password" autofocus required />
  <button type="submit">Sign in</button>
</form>
</body></html>`, next)
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString(body)
}

// loginSubmit validates password and sets admin cookie.
func (h *UIHandler) loginSubmit(ctx *fasthttp.RequestCtx) {
	if h.config == nil || strings.TrimSpace(h.config.AdminSecret) == "" {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "admin auth not configured", h.logger)
		return
	}
	// Read form-encoded body
	password := string(ctx.PostArgs().Peek("password"))
	next := string(ctx.PostArgs().Peek("next"))
	if password == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "password is required", h.logger)
		return
	}
	if password != h.config.AdminSecret {
		// Re-render with error
		ctx.SetContentType("text/html; charset=utf-8")
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString(`<html><body><p>Invalid password</p><a href="/admin/login">Try again</a></body></html>`)
		return
	}
	// Set cookie; HttpOnly; Path=/; no explicit Max-Age (session cookie)
	cookieName := h.config.AdminCookieName
	if cookieName == "" {
		cookieName = "bf_admin"
	}
	var c fasthttp.Cookie
	c.SetKey(cookieName)
	c.SetValue(h.config.AdminSecret)
	c.SetPath("/")
	c.SetHTTPOnly(true)
	ctx.Response.Header.SetCookie(&c)
	// Redirect to next
	if next == "" || strings.Contains(next, "://") {
		next = "/"
	}
	ctx.Response.Header.Set("Location", next)
	ctx.SetStatusCode(fasthttp.StatusFound)
}

// logout clears the admin cookie.
func (h *UIHandler) logout(ctx *fasthttp.RequestCtx) {
	cookieName := "bf_admin"
	if h.config != nil && strings.TrimSpace(h.config.AdminCookieName) != "" {
		cookieName = h.config.AdminCookieName
	}
	// Expire cookie
	var c fasthttp.Cookie
	c.SetKey(cookieName)
	c.SetValue("")
	c.SetPath("/")
	c.SetExpire(time.Unix(0, 0))
	c.SetMaxAge(-1)
	ctx.Response.Header.SetCookie(&c)
	ctx.Response.Header.Set("Location", "/admin/login")
	ctx.SetStatusCode(fasthttp.StatusFound)
}
