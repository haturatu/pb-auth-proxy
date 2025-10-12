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
	if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
		logging.AppLog.Error("Failed to execute login template with error", "error", err)
	}
}

// LoginHandler handles displaying the login form and processing login requests.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)
	data := map[string]interface{}{
		"Paths": config.Paths,
	}

	if r.Method == http.MethodGet {
		if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
			logging.AppLog.Error("Failed to execute login template", "error", err, "ip", ip)
		}
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			logging.AppLog.Error("Failed to parse login form", "error", err, "ip", ip)
			renderLoginWithError(w, "An internal error occurred. Please try again.")
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := models.GetUserByUsername(username)
		if err != nil {
			logging.AppLog.Error("Database error during login", "error", err, "username", username, "ip", ip)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "An internal error occurred."}); err != nil {
				logging.AppLog.Error("Failed to encode json error response", "error", err, "ip", ip)
			}
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
					if err := models.SetUserActiveStatus(user.ID, true); err != nil {
						logging.AppLog.Error("Failed to reactivate user", "error", err, "user_id", user.ID, "ip", ip)
						renderLoginWithError(w, "An internal error occurred. Please try again.")
						return
					}
					if err := models.RecordLoginSuccess(user.ID); err != nil {
						logging.AppLog.Error("Failed to reset failed login attempts", "error", err, "user_id", user.ID, "ip", ip)
						// Don't block login, but log the failure to reset attempts
					}
				}
			}
		}

		// Validate user credentials
		if user == nil || !models.CheckPasswordHash(password, user.PasswordHash) {
			if user != nil {
				if err := models.RecordLoginFailure(user.ID); err != nil {
					logging.AppLog.Error("Failed to record login failure", "error", err, "user_id", user.ID, "ip", ip)
				}
				// Re-fetch user to get updated failed_logins count
				updatedUser, _ := models.GetUserByID(user.ID)
				maxAttempts, _ := strconv.Atoi(os.Getenv("MAX_LOGIN_ATTEMPTS"))
				if updatedUser.FailedLogins >= maxAttempts {
					if err := models.SetUserActiveStatus(user.ID, false); err != nil {
						logging.AppLog.Error("Failed to lock account", "error", err, "user_id", user.ID, "ip", ip)
					}
					logging.SecurityLog.Warn("ACCOUNT LOCKED", "username", username, "ip", ip)
				}
			}
			logging.SecurityLog.Warn("LOGIN FAIL", "username", username, "ip", ip, "reason", "invalid credentials")
			renderLoginWithError(w, "Invalid username or password.")
			return
		}

		// Login successful
		if err := models.RecordLoginSuccess(user.ID); err != nil {
			logging.AppLog.Error("Failed to record login success", "error", err, "user_id", user.ID, "ip", ip)
		}
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
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "Could not create session."}); err != nil {
				logging.AppLog.Error("Failed to encode json error response", "error", err, "username", user.Username, "ip", ip)
			}
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
	if err := templates.ExecuteTemplate(w, "register.html", data); err != nil {
		logging.AppLog.Error("Failed to execute register template with error", "error", err)
	}
}

// RegisterHandler handles displaying and processing the user registration form.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)
	data := map[string]interface{}{
		"Paths": config.Paths,
	}

	if r.Method == http.MethodGet {
		if err := templates.ExecuteTemplate(w, "register.html", data); err != nil {
			logging.AppLog.Error("Failed to execute register template", "error", err, "ip", ip)
		}
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			logging.AppLog.Error("Failed to parse registration form", "error", err, "ip", ip)
			renderRegisterWithError(w, "An internal error occurred. Please try again.")
			return
		}
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

// RefreshTokenHandler handles exchanging a valid refresh token for a new access token.
func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)

	// 1. Parse request body
	var reqBody struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if reqBody.RefreshToken == "" {
		http.Error(w, "Missing refresh_token", http.StatusBadRequest)
		return
	}

	// 2. Validate the refresh token in DB
	refreshToken, err := models.GetRefreshTokenByToken(reqBody.RefreshToken)
	if err != nil {
		logging.AppLog.Error("Error getting refresh token from DB", "error", err, "ip", ip)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if refreshToken == nil || refreshToken.IsRevoked || time.Now().After(refreshToken.ExpiresAt) {
		logging.SecurityLog.Warn("REFRESH TOKEN FAIL", "reason", "token not found, revoked, or expired", "ip", ip)
		http.Error(w, "Unauthorized: Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// 3. Get user info
	user, err := models.GetUserByID(refreshToken.UserID)
	if err != nil || user == nil {
		logging.AppLog.Error("Failed to get user from refresh token", "error", err, "user_id", refreshToken.UserID, "ip", ip)
		http.Error(w, "Unauthorized: User not found", http.StatusUnauthorized)
		return
	}

	// 4. Issue a new access token
	accessTokenDurationMinutes, _ := strconv.Atoi(os.Getenv("ACCESS_TOKEN_DURATION_MINUTES"))
	if accessTokenDurationMinutes <= 0 {
		accessTokenDurationMinutes = 15
	}
	newAccessToken, err := utils.GenerateJWT(user, time.Duration(accessTokenDurationMinutes)*time.Minute)
	if err != nil {
		logging.AppLog.Error("Failed to generate new access token", "error", err, "username", user.Username, "ip", ip)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// --- Optional: Token Rotation ---
	// 5. Delete the old refresh token
	if err := models.DeleteRefreshTokenByToken(refreshToken.Token); err != nil {
		logging.AppLog.Error("Failed to delete old refresh token", "error", err, "ip", ip)
		// Continue, but log the error
	}

	// 6. Issue a new refresh token
	refreshTokenDurationDays, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_DURATION_DAYS"))
	if refreshTokenDurationDays <= 0 {
		refreshTokenDurationDays = 7
	}
	newRefreshToken, err := models.CreateRefreshToken(user.ID, time.Duration(refreshTokenDurationDays)*24*time.Hour)
	if err != nil {
		logging.AppLog.Error("Failed to create new refresh token", "error", err, "username", user.Username, "ip", ip)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// --- End Token Rotation ---

	// 7. Respond with new tokens
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken.Token,
	}); err != nil {
		logging.AppLog.Error("Failed to encode token response", "error", err, "ip", ip)
	}
}

// TokenHandler handles issuing JWT tokens for API clients.
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// --- User Authentication Logic (similar to LoginHandler) ---
	user, err := models.GetUserByUsername(creds.Username)
	if err != nil {
		logging.AppLog.Error("Database error during token issuance", "error", err, "username", creds.Username, "ip", ip)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// NOTE: We are not performing lockout checks here for simplicity,
	// but in a production system, you'd want to protect this endpoint
	// against brute-force attacks as well.
	if user == nil || !user.IsActive || !models.CheckPasswordHash(creds.Password, user.PasswordHash) {
		logging.SecurityLog.Warn("TOKEN ISSUANCE FAIL", "username", creds.Username, "ip", ip, "reason", "invalid credentials or inactive user")
		http.Error(w, "Unauthorized: Invalid credentials", http.StatusUnauthorized)
		return
	}
	// --- End Authentication ---

	// --- Issue Tokens ---
	// Access Token
	accessTokenDurationMinutes, _ := strconv.Atoi(os.Getenv("ACCESS_TOKEN_DURATION_MINUTES"))
	if accessTokenDurationMinutes <= 0 {
		accessTokenDurationMinutes = 15
	}
	accessToken, err := utils.GenerateJWT(user, time.Duration(accessTokenDurationMinutes)*time.Minute)
	if err != nil {
		logging.AppLog.Error("Failed to generate access token", "error", err, "username", user.Username, "ip", ip)
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Refresh Token
	refreshTokenDurationDays, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_DURATION_DAYS"))
	if refreshTokenDurationDays <= 0 {
		refreshTokenDurationDays = 7
	}
	refreshToken, err := models.CreateRefreshToken(user.ID, time.Duration(refreshTokenDurationDays)*24*time.Hour)
	if err != nil {
		logging.AppLog.Error("Failed to create refresh token", "error", err, "username", user.Username, "ip", ip)
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}
	// --- End Issue Tokens ---

	logging.SecurityLog.Info("TOKEN ISSUANCE SUCCESS", "username", user.Username, "ip", ip)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken.Token,
	}); err != nil {
		logging.AppLog.Error("Failed to encode token response", "error", err, "ip", ip)
	}
}
