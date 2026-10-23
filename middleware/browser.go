package middleware

import (
	"auth-proxy/config"
	"auth-proxy/utils"
	"golang.org/x/net/xsrftoken"
	"net/http"
	"os"
	"time"
)

// BrowserSecurity binds CSRF tokens and ceremonies to an unguessable, HttpOnly
// browser cookie. The configured public origin is never inferred from Host.
func BrowserSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "Cross-site request denied", http.StatusForbidden)
			return
		}
		cookie, err := r.Cookie("browser_id")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("Origin") != config.Paths.PublicOrigin || config.Paths.PublicOrigin == "" || err != nil ||
				!xsrftoken.ValidFor(r.Header.Get(xsrfHeaderName), os.Getenv("SESSION_SECRET"), cookie.Value, "browser-api", 15*time.Minute) {
				http.Error(w, "Invalid origin or CSRF token", http.StatusForbidden)
				return
			}
		} else if err != nil {
			id, genErr := utils.RandomToken()
			if genErr != nil {
				http.Error(w, "Could not initialize browser session", http.StatusInternalServerError)
				return
			}
			cookie = &http.Cookie{Name: "browser_id", Value: id, Path: "/", HttpOnly: true, Secure: config.Paths.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: 86400}
			http.SetCookie(w, cookie)
			r.AddCookie(cookie)
		}
		next.ServeHTTP(w, r)
	})
}
func BrowserCSRFToken(r *http.Request) string {
	cookie, err := r.Cookie("browser_id")
	if err != nil {
		return ""
	}
	return xsrftoken.Generate(os.Getenv("SESSION_SECRET"), cookie.Value, "browser-api")
}

// CookieAPISecurity protects existing admin endpoints while preserving bearer clients.
func CookieAPISecurity(next http.Handler) http.Handler {
	browser := BrowserSecurity(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			next.ServeHTTP(w, r)
			return
		}
		browser.ServeHTTP(w, r)
	})
}
