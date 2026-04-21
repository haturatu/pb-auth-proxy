package middleware

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/xsrftoken"
)

const (
	xsrfHeaderName = "X-XSRF-Token"
	xsrfFormField  = "xsrf_token"
)

type xsrfContextKey string

const xsrfTokenKey = xsrfContextKey("xsrfToken")

// XSRF is a middleware that provides Cross-Site Request Forgery protection.
func XSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xsrfSecretBase64 := os.Getenv("XSRF_SECRET_KEY")
		xsrfSecret, err := base64.StdEncoding.DecodeString(xsrfSecretBase64)
		if err != nil {
			http.Error(w, "XSRF configuration error: invalid base64 key", http.StatusInternalServerError)
			return
		}
		if len(xsrfSecret) != 32 {
			http.Error(w, "XSRF configuration error: key must be 32 bytes", http.StatusInternalServerError)
			return
		}

		sessionID := getSessionID(r)

		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			clientToken := r.Header.Get(xsrfHeaderName)
			if clientToken == "" {
				clientToken = r.FormValue(xsrfFormField)
			}

			if !xsrftoken.ValidFor(clientToken, string(xsrfSecret), sessionID, r.URL.Path, 15*time.Minute) {
				http.Error(w, "Invalid XSRF token", http.StatusForbidden)
				return
			}
		}

		token := xsrftoken.Generate(string(xsrfSecret), sessionID, r.URL.Path)
		ctx := context.WithValue(r.Context(), xsrfTokenKey, token)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// GetXSRFToken retrieves the XSRF token from the request context.
func GetXSRFToken(r *http.Request) string {
	if token, ok := r.Context().Value(xsrfTokenKey).(string); ok {
		return token
	}
	return ""
}

func getSessionID(r *http.Request) string {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}
