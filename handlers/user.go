package handlers

import (
	"auth-proxy/config"
	"auth-proxy/models"
	"auth-proxy/types"
	"auth-proxy/utils"
	"encoding/json"
	"net/http"
)

// AccountPageHandler serves the account page, passing user data to the template.
func AccountPageHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(types.SessionDataContextKey).(*models.User)
	if !ok || user == nil {
		// This should ideally not happen if AuthMiddleware is working correctly.
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	data := map[string]interface{}{
		"Paths": config.Paths,
		"User":  user,
	}
	templates.ExecuteTemplate(w, "account.html", data)
}

// ChangePasswordHandler handles both displaying the page (GET) and processing the update (POST).
func ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	// For GET request, just serve the page.
	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"Paths": config.Paths,
		}
		templates.ExecuteTemplate(w, "account_password.html", data)
		return
	}

	// POST request logic (API call)
	if r.Method == http.MethodPost {
		// This is a protected route, so AuthMiddleware should have put the user in the context.
		user, ok := r.Context().Value(types.SessionDataContextKey).(*models.User)
		if !ok || user == nil {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
		}

		w.Header().Set("Content-Type", "application/json")

		r.ParseForm()
		currentPassword := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		confirmNewPassword := r.FormValue("confirm_new_password")

		if ok, message := utils.ValidatePassword(newPassword); !ok {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": message})
			return
		}

		if newPassword != confirmNewPassword {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "New passwords do not match."})
			return
		}

		dbUser, err := models.GetUserByID(user.ID)
		if err != nil || dbUser == nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Could not retrieve user data."})
			return
		}

		if !models.CheckPasswordHash(currentPassword, dbUser.PasswordHash) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Current password is incorrect."})
			return
		}

		newPasswordHash, err := models.HashPassword(newPassword)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to process new password."})
			return
		}

		if err := models.UpdateUserPassword(dbUser.ID, newPasswordHash); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update password."})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Password updated successfully."})
		return
	}

	// Handle other methods
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}