package middleware

import (
	"auth-proxy/config"
	"auth-proxy/types"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserSecurity(t *testing.T) {
	original := config.Paths
	t.Cleanup(func() { config.Paths = original })
	config.Paths = types.PathConfig{PublicOrigin: "https://auth.example.com", CookieSecure: true}
	t.Setenv("SESSION_SECRET", "browser-test-secret-at-least-32-bytes")
	var token string
	handler := BrowserSecurity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { token = BrowserCSRFToken(r); w.WriteHeader(204) }))
	initial := httptest.NewRecorder()
	handler.ServeHTTP(initial, httptest.NewRequest("GET", "https://auth.example.com/api/auth/browser", nil))
	cookies := initial.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || token == "" {
		t.Fatal("unsafe browser binding cookie")
	}
	validToken := token
	for _, tc := range []struct {
		name, origin, csrf, fetch string
		cookie                    bool
		status                    int
	}{
		{"valid", "https://auth.example.com", validToken, "same-origin", true, 204},
		{"missing origin", "", validToken, "", true, 403},
		{"wrong origin", "https://evil.example", validToken, "", true, 403},
		{"missing csrf", "https://auth.example.com", "", "", true, 403},
		{"cross-site", "https://auth.example.com", validToken, "cross-site", true, 403},
		{"missing binding", "https://auth.example.com", validToken, "", false, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "https://attacker-supplied-host.example/api/auth/passkeys/login/begin", nil)
			if tc.cookie {
				request.AddCookie(cookies[0])
			}
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("X-XSRF-Token", tc.csrf)
			request.Header.Set("Sec-Fetch-Site", tc.fetch)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, request)
			if rec.Code != tc.status {
				t.Fatalf("status=%d want=%d", rec.Code, tc.status)
			}
		})
	}
	other := httptest.NewRequest("POST", "https://auth.example.com/api/auth/passkeys/login/begin", nil)
	other.AddCookie(&http.Cookie{Name: "browser_id", Value: "another-browser"})
	other.Header.Set("Origin", config.Paths.PublicOrigin)
	other.Header.Set("X-XSRF-Token", validToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, other)
	if rec.Code != 403 {
		t.Fatal("CSRF token crossed browsers")
	}
}
