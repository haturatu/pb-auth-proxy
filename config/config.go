package config

import (
	"auth-proxy/types"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

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

// getEnvAsInt reads an environment variable as an integer or returns a fallback value.
func getEnvAsInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return fallback
}

// Init loads path configurations from environment variables.
func Init() {
	// Load .env file. Errors are ignored, so variables from the environment can still be used.
	_ = godotenv.Load()

	Paths = types.PathConfig{
		// Paths
		Login:           getEnv("AUTH_PATH_LOGIN", "/login"),
		Register:        getEnv("AUTH_PATH_REGISTER", "/register"),
		Logout:          getEnv("AUTH_PATH_LOGOUT", "/logout"),
		Account:         getEnv("AUTH_PATH_ACCOUNT", "/account"),
		AccountPassword: getEnv("AUTH_PATH_ACCOUNT_PASSWORD", "/account/password"),
		Admin:           getEnv("AUTH_PATH_ADMIN", "/admin"),
		AdminUsersAPI:   getEnv("AUTH_PATH_ADMIN_USERS_API", "/api/admin/users"),
		Assets:          getEnv("AUTH_ASSETS_PATH", "/assets"),
		FrontPath:       getEnv("FRONT_PATH", "/"),
		APIPath:         getEnv("API_PATH", "/api/"),

		PublicOrigin:    getEnv("PUBLIC_ORIGIN", getEnv("WEBAUTHN_ORIGIN", "")),
		CookieSecure:    getEnvAsBool("COOKIE_SECURE", true),
		WebAuthnEnabled: getEnvAsBool("WEBAUTHN_ENABLED", false),
		WebAuthnRPID:    getEnv("WEBAUTHN_RP_ID", ""),
		WebAuthnRPName:  getEnv("WEBAUTHN_RP_NAME", "PB Auth Proxy"),
		WebAuthnOrigin:  getEnv("WEBAUTHN_ORIGIN", ""),

		// Booleans
		ProtectFrontend: getEnvAsBool("PROTECT_FRONTEND", false),
		ProtectAPI:      getEnvAsBool("PROTECT_API", false),
		RegisterEnabled: getEnvAsBool("REGISTER", true),

		// Security Policies
		MaxLoginAttempts:       getEnvAsInt("MAX_LOGIN_ATTEMPTS", 5),
		LockoutDurationMinutes: getEnvAsInt("LOCKOUT_DURATION_MINUTES", 10),
		RateLimitMaxRequests:   getEnvAsInt("USER_CREATION_RATE_LIMIT_MAX_REQUESTS", 5),
		RateLimitWindowSeconds: getEnvAsInt("USER_CREATION_RATE_LIMIT_WINDOW_SECONDS", 3600),
		PasswordPolicy:         getEnv("PASSWORD_POLICY", "standard"),

		// Token Durations
		TokenDurationHours:         getEnvAsInt("TOKEN_DURATION_HOURS", 24),
		AccessTokenDurationMinutes: getEnvAsInt("ACCESS_TOKEN_DURATION_MINUTES", 15),
		RefreshTokenDurationDays:   getEnvAsInt("REFRESH_TOKEN_DURATION_DAYS", 7),
	}
}

// Validate rejects unsafe public origins instead of trusting request Host/forwarded headers.
func Validate() error {
	u, err := url.Parse(Paths.PublicOrigin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("PUBLIC_ORIGIN must be an explicit http(s) origin without path")
	}
	local := u.Hostname() == "localhost" || net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback()
	if (u.Scheme != "https" || !Paths.CookieSecure) && !local {
		return fmt.Errorf("HTTPS and COOKIE_SECURE=true are required outside localhost")
	}
	if Paths.WebAuthnEnabled {
		if Paths.WebAuthnOrigin != Paths.PublicOrigin || Paths.WebAuthnRPID == "" {
			return fmt.Errorf("WEBAUTHN_ORIGIN must equal PUBLIC_ORIGIN and WEBAUTHN_RP_ID is required")
		}
		host := u.Hostname()
		if host != Paths.WebAuthnRPID && !strings.HasSuffix(host, "."+Paths.WebAuthnRPID) {
			return fmt.Errorf("WEBAUTHN_RP_ID must be the origin host or its parent domain")
		}
		if uv := getEnv("WEBAUTHN_USER_VERIFICATION", "required"); uv != "required" {
			return fmt.Errorf("WEBAUTHN_USER_VERIFICATION must be required")
		}
	}
	return nil
}
