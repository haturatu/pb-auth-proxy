package middleware

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/models"
	"auth-proxy/types"
	"context"
	"database/sql"
	"net/http"
	"strings"
)

// AuthMiddleware checks for a valid Bearer token, suitable for API endpoints.
// If the token is valid, it adds the user info to the context and proceeds.
// If not, it returns a 401 Unauthorized error.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := logging.GetClientIP(r)
		cookie, err := r.Cookie("auth_token")

		// If the cookie is not found
		if err != nil {
			if err == http.ErrNoCookie {
				// If it's an API request, return 401.
				if strings.HasPrefix(r.URL.Path, "/api/") {
					logging.AppLog.Info("API access denied (no token)", "path", r.URL.Path, "ip", ip)
					http.Error(w, "Unauthorized: A valid token is required", http.StatusUnauthorized)
					return
				}
				// Otherwise, it's a page navigation, so redirect to login.
				logging.AppLog.Info("Redirecting to login (no token)", "path", r.URL.Path, "ip", ip)
				http.Redirect(w, r, config.Paths.Login, http.StatusFound)
				return
			}
			// For any other error retrieving the cookie
			logging.AppLog.Error("Error reading auth cookie", "error", err, "path", r.URL.Path, "ip", ip)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		tokenStr := cookie.Value
		user, err := models.GetUserByToken(tokenStr)
		// Check for database errors first
		if err != nil && err != sql.ErrNoRows {
			logging.AppLog.Error("Error validating token", "error", err, "path", r.URL.Path, "ip", ip)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if user == nil {
			// Token was provided but is invalid or expired. Clear the bad cookie.
			http.SetCookie(w, &http.Cookie{
				Name:   "auth_token",
				Value:  "",
				Path:   "/",
				MaxAge: -1,
			})
			logging.SecurityLog.Warn("ACCESS DENIED", "reason", "invalid or expired token", "path", r.URL.Path, "ip", ip)
			// Redirect to login, as the user needs to re-authenticate.
			http.Redirect(w, r, config.Paths.Login, http.StatusFound)
			return
		}

		// User is authenticated, proceed
		ctx := context.WithValue(r.Context(), types.SessionDataContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminMiddleware checks if the user has the 'admin' role.
// This middleware should be used after AuthMiddleware.
func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := logging.GetClientIP(r)
		// Get user from context
		user, ok := r.Context().Value(types.SessionDataContextKey).(*models.User)
		if !ok || user == nil {
			logging.SecurityLog.Warn("ADMIN ACCESS DENIED", "reason", "no user data in context", "path", r.URL.Path, "ip", ip)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if user.Role != "admin" {
			logging.SecurityLog.Warn("ADMIN ACCESS DENIED", "reason", "insufficient permissions", "user", user.Username, "role", user.Role, "path", r.URL.Path, "ip", ip)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		logging.SecurityLog.Info("ADMIN ACCESS GRANTED", "user", user.Username, "path", r.URL.Path, "ip", ip)
		next.ServeHTTP(w, r)
	})
}
