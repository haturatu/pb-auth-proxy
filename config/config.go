package config

import (
	"auth-proxy/types"
	"os"
)

// Paths holds the global configuration values.
var Paths types.PathConfig

// getEnv reads an environment variable or returns a fallback value.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// Init loads path configurations from environment variables.
func Init() {
	Paths = types.PathConfig{
		Login:           getEnv("AUTH_PATH_LOGIN", "/login"),
		Register:        getEnv("AUTH_PATH_REGISTER", "/register"),
		Logout:          getEnv("AUTH_PATH_LOGOUT", "/logout"),
		Account:         getEnv("AUTH_PATH_ACCOUNT", "/account"),
		AccountPassword: getEnv("AUTH_PATH_ACCOUNT_PASSWORD", "/account/password"),
		Admin:           getEnv("AUTH_PATH_ADMIN", "/admin"),
		AdminUsersAPI:   getEnv("AUTH_PATH_ADMIN_USERS_API", "/api/admin/users"),
		Assets:          getEnv("AUTH_ASSETS_PATH", "/auth-proxy-assets"),
	}
}
