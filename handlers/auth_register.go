package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/models"
	"auth-proxy/utils"
	"net/http"
)

func renderRegisterWithError(w http.ResponseWriter, r *http.Request, message string) {
	data := map[string]interface{}{
		"Paths":     config.Paths,
		"Error":     message,
		"XSRFToken": middleware.GetXSRFToken(r),
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
		"XSRFToken": middleware.GetXSRFToken(r),
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
