package handlers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// AdminAuthMiddleware protects management APIs and UI when AdminSecret is set.
// Applied only to protected routes by the server bootstrap.
// Bypasses only the admin login/logout endpoints.
func AdminAuthMiddleware(config *lib.Config) lib.BifrostHTTPMiddleware {
	// If admin secret not configured, no-op
	if config == nil || config.AdminPassword == "" {
		return nil
	}
	cookieName := "bf_admin"
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			path := string(ctx.Path())

			// Allow admin auth endpoints
			if path == "/admin/login" || path == "/admin/logout" {
				next(ctx)
				return
			}

			// Authorization header (Bearer secret)
			if auth := string(ctx.Request.Header.Peek("Authorization")); auth != "" {
				if scheme, token, ok := strings.Cut(auth, " "); ok && strings.EqualFold(scheme, "Bearer") && token == config.AdminPassword {
					next(ctx)
					return
				}
			}
			// Cookie check
			if c := string(ctx.Request.Header.Cookie(cookieName)); c != "" && c == config.AdminPassword {
				next(ctx)
				return
			}

			// Not authorized
			accept := strings.ToLower(string(ctx.Request.Header.Peek("Accept")))
			if strings.Contains(accept, "application/json") || strings.HasPrefix(path, "/api/") {
				SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
				return
			}
			// Redirect to login for HTML
			nextURL := url.QueryEscape(path)
			ctx.Response.Header.Set("Location", "/admin/login?next="+nextURL)
			ctx.SetStatusCode(fasthttp.StatusFound)
		}
	}
}

const adminCSS = `<style>
:root{color-scheme:light dark}
body{font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,Helvetica Neue,Arial,"Apple Color Emoji","Segoe UI Emoji";margin:0;background:var(--background,#fff);color:var(--foreground,#111)}
.container{display:flex;min-height:100vh;align-items:center;justify-content:center;padding:2rem}
.card{width:100%;max-width:380px;background:var(--card-bg,rgba(255,255,255,.9));border-radius:12px;padding:24px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:1.25rem;margin:0 0 12px 0}
label{display:block;font-size:.9rem;margin:.25rem 0}
input{width:100%;padding:.6rem .7rem;border:1px solid rgba(0,0,0,.15);border-radius:8px;background:var(--input-bg,#fff)}
button{width:100%;padding:.6rem .7rem;border:0;border-radius:8px;background:#111;color:#fff;cursor:pointer}
.error{color:#b00020;margin:.5rem 0}
</style>`

const adminLoginHTML = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Admin Login</title>
%s
</head><body>
<div class="container">
  <div class="card">
    <h1>Admin Login</h1>
    %s
    <form method="post" action="/admin/login">
      <input type="hidden" name="next" value="%s" />
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password" required />
      <div style="height:.5rem"></div>
      <button type="submit">Sign in</button>
    </form>
  </div>
</div>
</body></html>`

// RegisterAdminAuthRoutes registers GET/POST /admin/login and GET /admin/logout
func RegisterAdminAuthRoutes(r *router.Router, config *lib.Config) {
	if r == nil {
		return
	}
	cookieName := "bf_admin"

	// GET /admin/login - styled HTML form
	r.GET("/admin/login", func(ctx *fasthttp.RequestCtx) {
		ctx.SetContentType("text/html; charset=utf-8")
		msg := string(ctx.QueryArgs().Peek("msg"))
		next := string(ctx.QueryArgs().Peek("next"))
		if next == "" {
			next = "/"
		}
		msgHTML := func() string {
			if msg != "" {
				return "<div class='error'>" + msg + "</div>"
			}
			return ""
		}()
		_, _ = fmt.Fprintf(ctx, adminLoginHTML, adminCSS, msgHTML, next)
	})

	// POST /admin/login - validate and set cookie
	r.POST("/admin/login", func(ctx *fasthttp.RequestCtx) {
		passwordConfigured := ""
		if config != nil {
			passwordConfigured = config.AdminPassword
		}
		if passwordConfigured == "" {
			SendError(ctx, fasthttp.StatusUnauthorized, "Admin auth not enabled")
			return
		}
		// Prefer form field, fallback to JSON
		password := string(ctx.PostArgs().Peek("password"))
		if password == "" {
			var payload struct {
				Password string `json:"password"`
			}
			if err := json.Unmarshal(ctx.PostBody(), &payload); err == nil {
				password = payload.Password
			}
		}
		if password != passwordConfigured {
			accept := strings.ToLower(string(ctx.Request.Header.Peek("Accept")))
			if strings.Contains(accept, "application/json") {
				SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
				return
			}
			next := url.QueryEscape(string(ctx.PostArgs().Peek("next")))
			if next == "" {
				next = "%2F"
			}
			ctx.Response.Header.Set("Location", "/admin/login?msg="+url.QueryEscape("Invalid password")+"&next="+next)
			ctx.SetStatusCode(fasthttp.StatusFound)
			return
		}
		// Set cookie
		cookie := fasthttp.AcquireCookie()
		defer fasthttp.ReleaseCookie(cookie)
		cookie.SetKey(cookieName)
		cookie.SetValue(passwordConfigured)
		cookie.SetPath("/")
		cookie.SetHTTPOnly(true)
		cookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
		cookie.SetExpire(time.Now().Add(30 * 24 * time.Hour))
		if string(ctx.Request.Header.Peek("X-Forwarded-Proto")) == "https" {
			cookie.SetSecure(true)
		}
		ctx.Response.Header.SetCookie(cookie)
		// Redirect to next or /
		next := string(ctx.PostArgs().Peek("next"))
		if next == "" {
			next = "/"
		}
		ctx.Response.Header.Set("Location", next)
		ctx.SetStatusCode(fasthttp.StatusFound)
	})

	// GET /admin/logout - clear cookie
	r.GET("/admin/logout", func(ctx *fasthttp.RequestCtx) {
		cookie := fasthttp.AcquireCookie()
		defer fasthttp.ReleaseCookie(cookie)
		cookie.SetKey(cookieName)
		cookie.SetValue("")
		cookie.SetPath("/")
		cookie.SetHTTPOnly(true)
		cookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
		cookie.SetExpire(time.Now().Add(-1 * time.Hour))
		if string(ctx.Request.Header.Peek("X-Forwarded-Proto")) == "https" {
			cookie.SetSecure(true)
		}
		ctx.Response.Header.SetCookie(cookie)
		ctx.Response.Header.Set("Location", "/admin/login")
		ctx.SetStatusCode(fasthttp.StatusFound)
	})
}
