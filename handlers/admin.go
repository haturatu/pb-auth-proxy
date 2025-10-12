package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/models"
	"auth-proxy/types"
	"encoding/json"
	"net/http"
	"strconv"
)

// AdminPageHandler serves the admin dashboard page.
func AdminPageHandler(w http.ResponseWriter, r *http.Request) {
	// Fetch all users to render on the page
	users, err := models.GetAllUsers()
	if err != nil {
		logging.AppLog.Error("Failed to retrieve users for admin page", "error", err)
		http.Error(w, "Could not load user data.", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Paths": config.Paths,
		"Users": users,
	}
		if err := templates.ExecuteTemplate(w, "admin.html", data); err != nil {
		logging.AppLog.Error("Failed to execute admin template", "error", err)
	}
}

// GetUsersHandler returns a list of all users.
func GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)
	users, err := models.GetAllUsers()
	if err != nil {
		logging.AppLog.Error("Failed to retrieve users", "error", err, "ip", ip)
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(users); err != nil {
		logging.AppLog.Error("Failed to encode users to JSON", "error", err, "ip", ip)
	}
}

// UpdateUserRoleHandler updates a user's role.
func UpdateUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)
	// Get admin user from context
	adminUser, ok := r.Context().Value(types.SessionDataContextKey).(*types.User)
	if !ok || adminUser == nil {
		logging.AppLog.Error("Failed to get user from context for admin action", "ip", ip)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	adminUsername := adminUser.Username

	id, err := strconv.ParseInt(r.URL.Path[len(config.Paths.AdminUsersAPI+"/"):len(r.URL.Path)-len("/role")], 10, 64)
	if err != nil {
		logging.AppLog.Warn("Invalid user ID in request", "path", r.URL.Path, "ip", ip)
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Role string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logging.AppLog.Warn("Invalid request body for role update", "error", err, "ip", ip)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Role != "admin" && req.Role != "user" {
		logging.AppLog.Warn("Invalid role provided for update", "role", req.Role, "ip", ip)
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	if err := models.UpdateUserRole(id, req.Role); err != nil {
		logging.AppLog.Error("Failed to update user role in database", "error", err, "target_user_id", id, "ip", ip)
		http.Error(w, "Failed to update role", http.StatusInternalServerError)
		return
	}

	logging.SecurityLog.Info("ADMIN ACTION", "action", "update_role", "performed_by", adminUsername, "target_user_id", id, "new_role", req.Role, "ip", ip)
	w.WriteHeader(http.StatusOK)
}

// DeleteUserHandler deletes a user.
func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)
	// Get admin user from context
	adminUser, ok := r.Context().Value(types.SessionDataContextKey).(*types.User)
	if !ok || adminUser == nil {
		logging.AppLog.Error("Failed to get user from context for admin action", "ip", ip)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	adminUsername := adminUser.Username

	id, err := strconv.ParseInt(r.URL.Path[len(config.Paths.AdminUsersAPI+"/"):], 10, 64)
	if err != nil {
		logging.AppLog.Warn("Invalid user ID in request", "path", r.URL.Path, "ip", ip)
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	if err := models.DeleteUser(id); err != nil {
		logging.AppLog.Error("Failed to delete user from database", "error", err, "target_user_id", id, "ip", ip)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	logging.SecurityLog.Info("ADMIN ACTION", "action", "delete_user", "performed_by", adminUsername, "target_user_id", id, "ip", ip)
	w.WriteHeader(http.StatusOK)
}

// SetUserActiveStatusHandler updates a user's active status.
func SetUserActiveStatusHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)
	// Get admin user from context
	adminUser, ok := r.Context().Value(types.SessionDataContextKey).(*types.User)
	if !ok || adminUser == nil {
		logging.AppLog.Error("Failed to get user from context for admin action", "ip", ip)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	adminUsername := adminUser.Username

	id, err := strconv.ParseInt(r.URL.Path[len(config.Paths.AdminUsersAPI+"/"):len(r.URL.Path)-len("/status")], 10, 64)
	if err != nil {
		logging.AppLog.Warn("Invalid user ID in request", "path", r.URL.Path, "ip", ip)
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req struct {
		IsActive bool `json:"is_active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logging.AppLog.Warn("Invalid request body for status update", "error", err, "ip", ip)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := models.SetUserActiveStatus(id, req.IsActive); err != nil {
		logging.AppLog.Error("Failed to update user status in database", "error", err, "target_user_id", id, "ip", ip)
		http.Error(w, "Failed to update status", http.StatusInternalServerError)
		return
	}

	logging.SecurityLog.Info("ADMIN ACTION", "action", "set_active_status", "performed_by", adminUsername, "target_user_id", id, "new_status", req.IsActive, "ip", ip)
	w.WriteHeader(http.StatusOK)
}
