package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/models"
	"auth-proxy/types"
	"auth-proxy/utils"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/csrf"
)

var templates = template.Must(template.ParseGlob("templates/*.html"))

// authenticateUser handles the core logic for authenticating a user, including brute-force protection.
// It returns the authenticated user or an error if authentication fails.
func authenticateUser(username, password, ip string) (*types.User, error) {
	user, err := models.GetUserByUsername(username)
	if err != nil {
		logging.AppLog.Error("Database error during authentication", "error", err, "username", username, "ip", ip)
		return nil, errors.New("internal server error")
	}

	if user == nil {
		logging.SecurityLog.Warn("AUTH FAIL", "username", username, "ip", ip, "reason", "user not found")
		return nil, errors.New("invalid username or password")
	}

	// Step 1: Check if the account is locked.
	if !user.IsActive {
		lockoutMinutes, _ := strconv.Atoi(os.Getenv("LOCKOUT_DURATION_MINUTES"))
		lockoutDuration := time.Duration(lockoutMinutes) * time.Minute

		// Check if the lockout period has expired.
		if time.Since(user.UpdatedAt) < lockoutDuration {
			logging.SecurityLog.Warn("AUTH FAIL", "username", username, "ip", ip, "reason", "account locked")
			return nil, errors.New("account is temporarily locked")
		} else {
			// Lockout has expired. Reactivate the account but do not log the user in on this attempt.
			if err := models.SetUserActiveStatus(user.ID, true); err != nil {
				logging.AppLog.Error("Failed to reactivate user", "error", err, "user_id", user.ID, "ip", ip)
				return nil, errors.New("internal server error")
			}
			if err := models.RecordLoginSuccess(user.ID); err != nil {
				logging.AppLog.Error("Failed to reset failed login attempts on reactivation", "error", err, "user_id", user.ID, "ip", ip)
			}
			logging.SecurityLog.Info("ACCOUNT UNLOCKED", "username", username, "ip", ip)
			return nil, errors.New("account has been unlocked, please try again")
		}
	}

	// Step 2: If the account is active, validate credentials.
	if !models.CheckPasswordHash(password, user.PasswordHash) {
		// Record the failure
		if err := models.RecordLoginFailure(user.ID); err != nil {
			logging.AppLog.Error("Failed to record login failure", "error", err, "user_id", user.ID, "ip", ip)
		}

		// Re-fetch user to get updated failed_logins count
		updatedUser, _ := models.GetUserByID(user.ID)
		maxAttempts, _ := strconv.Atoi(os.Getenv("MAX_LOGIN_ATTEMPTS"))

		// Lock the account if max attempts are exceeded
		if maxAttempts > 0 && updatedUser.FailedLogins >= maxAttempts {
			if err := models.SetUserActiveStatus(user.ID, false); err != nil {
				logging.AppLog.Error("Failed to lock account", "error", err, "user_id", user.ID, "ip", ip)
			}
			logging.SecurityLog.Warn("ACCOUNT LOCKED", "username", username, "ip", ip)
		}

		logging.SecurityLog.Warn("AUTH FAIL", "username", username, "ip", ip, "reason", "invalid credentials")
		return nil, errors.New("invalid username or password")
	}

	// Step 3: Login successful.
	if err := models.RecordLoginSuccess(user.ID); err != nil {
		logging.AppLog.Error("Failed to record login success", "error", err, "user_id", user.ID, "ip", ip)
	}
	logging.SecurityLog.Info("AUTH SUCCESS", "username", user.Username, "ip", ip)

	return user, nil
}

func renderLoginWithError(w http.ResponseWriter, r *http.Request, message string) {
	data := map[string]interface{}{
		"Paths":           config.Paths,
		"Error":           message,
		"RegisterEnabled": config.Paths.RegisterEnabled,
		"CSRFToken":       csrf.Token(r),
	}
	w.WriteHeader(http.StatusUnauthorized) // Set status to indicate failure
	if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
		logging.AppLog.Error("Failed to execute login template with error", "error", err)
	}
}

// LoginHandler handles displaying the login form and processing login requests.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)

	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"Paths":           config.Paths,
			"RegisterEnabled": config.Paths.RegisterEnabled,
			"CSRFToken":       csrf.Token(r),
		}
		if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
			logging.AppLog.Error("Failed to execute login template", "error", err, "ip", ip)
		}
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			logging.AppLog.Error("Failed to parse login form", "error", err, "ip", ip)
			renderLoginWithError(w, r, "An internal error occurred. Please try again.")
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := authenticateUser(username, password, ip)
		if err != nil {
			// Map authentication error to user-facing message
			errMsg := "Invalid username or password."
			if err.Error() == "account is temporarily locked" {
				errMsg = "Account is temporarily locked."
			} else if err.Error() == "internal server error" {
				errMsg = "An internal error occurred. Please try again."
			}
			renderLoginWithError(w, r, errMsg)
			return
		}

		// --- Create Session Cookie ---
		tokenDurationHours, err := strconv.Atoi(os.Getenv("TOKEN_DURATION_HOURS"))
		if err != nil || tokenDurationHours <= 0 {
			tokenDurationHours = 24 // Default to 24 hours
		}
		duration := time.Duration(tokenDurationHours) * time.Hour

		token, err := models.CreateAuthToken(user.ID, duration)
		if err != nil {
			logging.AppLog.Error("Failed to create auth token", "error", err, "username", user.Username, "ip", ip)
			renderLoginWithError(w, r, "Could not create session.")
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

func renderRegisterWithError(w http.ResponseWriter, r *http.Request, message string) {
	data := map[string]interface{}{
		"Paths":     config.Paths,
		"Error":     message,
		"CSRFToken": csrf.Token(r),
	}
	w.WriteHeader(http.StatusBadRequest) // Set status to indicate failure
	if err := templates.ExecuteTemplate(w, "register.html", data); err != nil {
		logging.AppLog.Error("Failed to execute register template with error", "error", err)
	}
}

// RegisterHandler handles displaying and processing the user registration form.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if !config.Paths.RegisterEnabled {
		http.Error(w, "User registration is disabled.", http.StatusForbidden)
		return
	}
	ip := logging.GetClientIP(r)
	data := map[string]interface{}{
		"Paths":     config.Paths,
		"CSRFToken": csrf.Token(r),
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
			renderRegisterWithError(w, r, "An internal error occurred. Please try again.")
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		// Validate password policy
		if ok, message := utils.ValidatePassword(password); !ok {
			renderRegisterWithError(w, r, message)
			return
		}

		if password != confirmPassword {
			logging.AppLog.Warn("User registration failed", "reason", "passwords do not match", "ip", ip)
			renderRegisterWithError(w, r, "Passwords do not match")
			return
		}

		existingUser, err := models.GetUserByUsername(username)
		if err != nil {
			logging.AppLog.Error("Error checking username during registration", "error", err, "ip", ip)
			renderRegisterWithError(w, r, "An internal error occurred while checking the username.")
			return
		}
		if existingUser != nil {
			logging.AppLog.Warn("User registration failed", "reason", "username is already taken", "username", username, "ip", ip)
			renderRegisterWithError(w, r, "Username is already taken")
			return
		}

		user, err := models.CreateUser(username, password, "user")
		if err != nil {
			logging.AppLog.Error("Failed to create user", "error", err, "username", username, "ip", ip)
			renderRegisterWithError(w, r, "Failed to create user due to an internal error.")
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

	// Use the shared authentication logic
	user, err := authenticateUser(creds.Username, creds.Password, ip)
	if err != nil {
		// Return a generic error to the API client
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken.Token,
	}); err != nil {
		logging.AppLog.Error("Failed to encode token response", "error", err, "ip", ip)
	}
}
