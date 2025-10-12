package main

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/handlers"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

func main() {
	// Initialize loggers
	logging.InitLoggers()

	// Load .env file
	if err := godotenv.Load(); err != nil {
		logging.AppLog.Info("No .env file found, using environment variables")
	}

	// Initialize path configurations
	config.Init()

	// Initialize database
	database.InitDB()
	defer database.CloseDB()

	// Get target URL for proxy
	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		logging.AppLog.Error("TARGET_URL environment variable not set")
		os.Exit(1)
	}

	// --- Create router and define routes ---
	mux := http.NewServeMux()

	// --- Static file serving ---
	assetsPath := strings.TrimRight(config.Paths.Assets, "/") + "/"
	assetsFS := http.FileServer(http.Dir("templates"))
	mux.Handle(assetsPath, http.StripPrefix(assetsPath, assetsFS))

	// --- Frontend selection and routing ---
	frontendType := os.Getenv("FRONTEND_TYPE")
	rateLimiter := middleware.NewRateLimiter()

	// Helper to switch handler based on HTTP method
	methodSwitch := func(get, post http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				post.ServeHTTP(w, r)
			} else {
				get.ServeHTTP(w, r)
			}
		})
	}

	if frontendType == "php" {
		// Create specific handlers for each PHP page
		loginPageHandler := handlers.NewPhpProxyHandler("login.php")
		registerPageHandler := handlers.NewPhpProxyHandler("register.php")
		accountPageHandler := handlers.NewPhpProxyHandler("account.php")
		accountPasswordPageHandler := handlers.NewPhpProxyHandler("account_password.php")

		// For /login, GET goes to PHP, POST goes to Go's login logic
		loginHandler := methodSwitch(loginPageHandler, http.HandlerFunc(handlers.LoginHandler))
		mux.Handle(config.Paths.Login, loginHandler)

		// For /register, GET goes to PHP, POST goes to Go's register logic
		registerPostHandler := middleware.RateLimitMiddleware(rateLimiter)(http.HandlerFunc(handlers.RegisterHandler))
		registerHandler := methodSwitch(registerPageHandler, registerPostHandler)
		mux.Handle(config.Paths.Register, registerHandler)

		// For account pages, GET goes to PHP, POST (for password change) goes to Go
		accountPasswordPostHandler := http.HandlerFunc(handlers.ChangePasswordHandler)
		accountPasswordHandler := methodSwitch(accountPasswordPageHandler, accountPasswordPostHandler)
		mux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(accountPasswordHandler))
		mux.Handle(config.Paths.Account, middleware.SessionAuth(accountPageHandler)) // This page is GET only

		// Admin page still uses Go templates
		mux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
	} else {
		// --- Public Auth Routes (Go templates) ---
		mux.HandleFunc(config.Paths.Login, handlers.LoginHandler)
		mux.Handle(config.Paths.Register, middleware.RateLimitMiddleware(rateLimiter)(http.HandlerFunc(handlers.RegisterHandler)))
		// --- Auth HTML pages (Protected by SessionAuth, Go templates) ---
		mux.Handle(config.Paths.Account, middleware.SessionAuth(http.HandlerFunc(handlers.AccountPageHandler)))
		mux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
		mux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(http.HandlerFunc(handlers.ChangePasswordHandler)))
	}

	// --- Common Routes ---
	mux.HandleFunc(config.Paths.Logout, handlers.LogoutHandler)
	mux.HandleFunc("/auth/refresh", handlers.RefreshTokenHandler)
	mux.HandleFunc("/api/auth/token", handlers.TokenHandler)

	// --- Protected API Endpoints (for Admin UI, protected by SessionAuth) ---
	adminUsersAPI := http.HandlerFunc(handlers.GetUsersHandler)
	adminUpdateRoleAPI := http.HandlerFunc(handlers.UpdateUserRoleHandler)
	adminDeleteUserAPI := http.HandlerFunc(handlers.DeleteUserHandler)
	adminSetStatusAPI := http.HandlerFunc(handlers.SetUserActiveStatusHandler)

	mux.Handle(config.Paths.AdminUsersAPI, middleware.SessionAuth(middleware.AdminMiddleware(adminUsersAPI)))
	mux.Handle(config.Paths.AdminUsersAPI+"/", middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/role") && r.Method == http.MethodPost:
			adminUpdateRoleAPI.ServeHTTP(w, r)
		case strings.HasSuffix(path, "/status") && r.Method == http.MethodPost:
			adminSetStatusAPI.ServeHTTP(w, r)
		case r.Method == http.MethodDelete:
			adminDeleteUserAPI.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))))

	// --- Main Application Proxy ---
	proxyHandler := handlers.NewProxy(targetURL)

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		if pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}

		path := r.URL.Path

		// API Protection with Bearer Token
		if config.Paths.ProtectAPI && strings.HasPrefix(path, config.Paths.APIPath) {
			middleware.BearerAuth(proxyHandler).ServeHTTP(w, r)
			return
		}

		// Frontend Protection with Session Cookie
		if config.Paths.ProtectFrontend {
			middleware.SessionAuth(proxyHandler).ServeHTTP(w, r)
			return
		}

		// No protection
		proxyHandler.ServeHTTP(w, r)
	})

	// --- Start Server ---
	logging.AppLog.Info("Server starting on :8080")
	if err := http.ListenAndServe(":8080", finalHandler); err != nil {
		logging.AppLog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
