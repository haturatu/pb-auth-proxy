package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/models"
	"auth-proxy/utils"
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"time"
)

var templates = template.Must(template.ParseGlob("templates/*.html"))

func renderLoginWithError(w http.ResponseWriter, message string) {
	data := map[string]interface{}{
		"Paths": config.Paths,
		"Error": message,
	}
	w.WriteHeader(http.StatusUnauthorized) // Set status to indicate failure
	templates.ExecuteTemplate(w, "login.html", data)
}

// LoginHandler handles displaying the login form and processing login requests.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)
	data := map[string]interface{}{
		"Paths": config.Paths,
	}

	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "login.html", data)
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := models.GetUserByUsername(username)
		if err != nil {
			logging.AppLog.Error("Database error during login", "error", err, "username", username, "ip", ip)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "An internal error occurred."})
			return
		}

		// Check for lockout and user status first
		if user != nil {
			lockoutMinutes, _ := strconv.Atoi(os.Getenv("LOCKOUT_DURATION_MINUTES"))

			if !user.IsActive {
				lockoutDuration := time.Duration(lockoutMinutes) * time.Minute
				if time.Since(user.UpdatedAt) < lockoutDuration {
					logging.SecurityLog.Warn("LOGIN FAIL", "username", username, "ip", ip, "reason", "account locked")
					renderLoginWithError(w, "Account is temporarily locked.")
					return
				} else {
					// If lockout expired, re-activate account and reset attempts
					models.SetUserActiveStatus(user.ID, true)
					models.RecordLoginSuccess(user.ID) // Resets failed_logins
				}
			}
		}

		// Validate user credentials
		if user == nil || !models.CheckPasswordHash(password, user.PasswordHash) {
			if user != nil {
				models.RecordLoginFailure(user.ID)
				// Re-fetch user to get updated failed_logins count
				updatedUser, _ := models.GetUserByID(user.ID)
				maxAttempts, _ := strconv.Atoi(os.Getenv("MAX_LOGIN_ATTEMPTS"))
				if updatedUser.FailedLogins >= maxAttempts {
					models.SetUserActiveStatus(user.ID, false)
					logging.SecurityLog.Warn("ACCOUNT LOCKED", "username", username, "ip", ip)
				}
			}
			logging.SecurityLog.Warn("LOGIN FAIL", "username", username, "ip", ip, "reason", "invalid credentials")
			renderLoginWithError(w, "Invalid username or password.")
			return
		}

		// Login successful
		models.RecordLoginSuccess(user.ID)
		logging.SecurityLog.Info("LOGIN SUCCESS", "username", user.Username, "ip", ip)

		tokenDurationHours, err := strconv.Atoi(os.Getenv("TOKEN_DURATION_HOURS"))
		if err != nil || tokenDurationHours <= 0 {
			tokenDurationHours = 24 // Default to 24 hours
		}
		duration := time.Duration(tokenDurationHours) * time.Hour

		token, err := models.CreateAuthToken(user.ID, duration)
		if err != nil {
			logging.AppLog.Error("Failed to create auth token", "error", err, "username", user.Username, "ip", ip)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Could not create session."})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token.Token,
			Expires:  token.ExpiresAt,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil, // Use Secure flag if on HTTPS
			SameSite: http.SameSiteLaxMode,
		})

		// Redirect to the root path, which is the proxied application.
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}
// LogoutHandler invalidates the user's token by expiring the cookie.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		// No cookie, nothing to do.
		http.Redirect(w, r, config.Paths.Login, http.StatusFound)
		return
	}

	err = models.DeleteAuthToken(cookie.Value)
	if err != nil {
		// Log the error but still proceed with logging the user out client-side.
		logging.AppLog.Error("Failed to delete token on logout", "error", err, "ip", ip)
	}

	// Expire the cookie by setting its max age to a negative number.
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	logging.SecurityLog.Info("LOGOUT SUCCESS", "ip", ip)
	http.Redirect(w, r, config.Paths.Login, http.StatusFound)
}

func renderRegisterWithError(w http.ResponseWriter, message string) {
	data := map[string]interface{}{
		"Paths": config.Paths,
		"Error": message,
	}
	w.WriteHeader(http.StatusBadRequest) // Set status to indicate failure
	templates.ExecuteTemplate(w, "register.html", data)
}

// RegisterHandler handles displaying and processing the user registration form.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)
	data := map[string]interface{}{
		"Paths": config.Paths,
	}

	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "register.html", data)
		return
	}

			if r.Method == http.MethodPost {
				r.ParseForm()
				username := r.FormValue("username")
				password := r.FormValue("password")
				confirmPassword := r.FormValue("confirm_password")
	
				// Validate password policy
				if ok, message := utils.ValidatePassword(password); !ok {
					renderRegisterWithError(w, message)
					return
				}
	
				if password != confirmPassword {
					logging.AppLog.Warn("User registration failed", "reason", "passwords do not match", "ip", ip)
					renderRegisterWithError(w, "Passwords do not match")
					return
				}
	
				existingUser, err := models.GetUserByUsername(username)
				if err != nil {
					logging.AppLog.Error("Error checking username during registration", "error", err, "ip", ip)
					renderRegisterWithError(w, "An internal error occurred while checking the username.")
					return
				}
				if existingUser != nil {
					logging.AppLog.Warn("User registration failed", "reason", "username is already taken", "username", username, "ip", ip)
					renderRegisterWithError(w, "Username is already taken")
					return
				}
	
				user, err := models.CreateUser(username, password, "user")
				if err != nil {
					logging.AppLog.Error("Failed to create user", "error", err, "username", username, "ip", ip)
					renderRegisterWithError(w, "Failed to create user due to an internal error.")
					return
				}
		logging.SecurityLog.Info("USER CREATED", "username", user.Username, "ip", ip)

		// Redirect to the login page so the user can sign in.
		http.Redirect(w, r, config.Paths.Login, http.StatusFound)
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}
