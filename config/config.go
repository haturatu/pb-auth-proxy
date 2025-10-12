package config

import (
	"auth-proxy/types"
	"os"
	"strconv"

	"github.com/joho/godotenv"
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

// getEnvAsBool reads an environment variable as a boolean or returns a fallback value.
func getEnvAsBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return fallback
}

// Init loads path configurations from environment variables.
func Init() {
	// Load .env file. Errors are ignored, so variables from the environment can still be used.
	_ = godotenv.Load()

	Paths = types.PathConfig{
		Login:           getEnv("AUTH_PATH_LOGIN", "/login"),
		Register:        getEnv("AUTH_PATH_REGISTER", "/register"),
		Logout:          getEnv("AUTH_PATH_LOGOUT", "/logout"),
		Account:         getEnv("AUTH_PATH_ACCOUNT", "/account"),
		AccountPassword: getEnv("AUTH_PATH_ACCOUNT_PASSWORD", "/account/password"),
		Admin:           getEnv("AUTH_PATH_ADMIN", "/admin"),
		AdminUsersAPI:   getEnv("AUTH_PATH_ADMIN_USERS_API", "/api/admin/users"),
		Assets:          getEnv("AUTH_ASSETS_PATH", "/assets"),
		ProtectFrontend: getEnvAsBool("PROTECT_FRONTEND", false),
		ProtectAPI:      getEnvAsBool("PROTECT_API", false),
		FrontPath:       getEnv("FRONT_PATH", "/"),
		APIPath:         getEnv("API_PATH", "/api/"),
	}
}
