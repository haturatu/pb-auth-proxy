package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/models"
	"net/http"
	"time"
)

// LogoutHandler invalidates the user's token by expiring the cookie.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if err := templates.ExecuteTemplate(w, "logout.html", map[string]any{"Paths": config.Paths, "XSRFToken": middleware.GetXSRFToken(r)}); err != nil {
			logging.AppLog.Error("Failed to render logout", "error", err)
		}
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := logging.GetClientIP(r)
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		// No cookie, nothing to do.
		http.Redirect(w, r, config.Paths.Login, http.StatusFound)
		return
	}

	err = models.DeleteAuthToken(cookie.Value)
	if err != nil {
		// Fail closed if server-side revocation could not be persisted.
		logging.AppLog.Error("Failed to delete token on logout", "error", err, "ip", ip)
		if err != models.ErrInvalidToken {
			http.Error(w, "Could not revoke session", http.StatusServiceUnavailable)
			return
		}
	}

	// Expire the cookie by setting its max age to a negative number.
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   config.Paths.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	logging.SecurityLog.Info("LOGOUT SUCCESS", "ip", ip)
	http.Redirect(w, r, config.Paths.Login, http.StatusFound)
}
