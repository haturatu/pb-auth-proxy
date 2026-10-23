package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/models"
	"encoding/json"
	"net/http"
	"time"
)

// RefreshTokenHandler handles exchanging a valid refresh token for a new access token.
func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

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

	user, err := models.ConsumeRefreshToken(reqBody.RefreshToken)
	if err != nil || user == nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}
	// 4. Issue a new access token
	newAccessToken, err := models.CreateToken(user, time.Duration(config.Paths.AccessTokenDurationMinutes)*time.Minute, "access")
	if err != nil {
		logging.AppLog.Error("Failed to generate new access token", "error", err, "username", user.Username, "ip", ip)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 6. Issue a new refresh token
	newRefreshToken, err := models.CreateRefreshToken(user, time.Duration(config.Paths.RefreshTokenDurationDays)*24*time.Hour)
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
	w.Header().Set("Cache-Control", "no-store")
	// Access Token
	accessToken, err := models.CreateToken(user, time.Duration(config.Paths.AccessTokenDurationMinutes)*time.Minute, "access")
	if err != nil {
		logging.AppLog.Error("Failed to generate access token", "error", err, "username", user.Username, "ip", ip)
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Refresh Token
	refreshToken, err := models.CreateRefreshToken(user, time.Duration(config.Paths.RefreshTokenDurationDays)*24*time.Hour)
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
