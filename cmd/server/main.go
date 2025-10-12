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
	// The assets path must end with a slash for http.StripPrefix to work correctly.
	assetsPath := config.Paths.Assets + "/"
	assetsFS := http.FileServer(http.Dir("templates"))
	mux.Handle(assetsPath, http.StripPrefix(assetsPath, assetsFS))

	// --- Public Auth Routes ---
	rateLimiter := middleware.NewRateLimiter()
	// Auth API endpoints
	mux.HandleFunc(config.Paths.Login, handlers.LoginHandler) // GET serves HTML, POST handles login
	mux.Handle(config.Paths.Register, rateLimiter.RateLimitMiddleware(http.HandlerFunc(handlers.RegisterHandler))) // GET serves HTML, POST handles registration
	mux.HandleFunc(config.Paths.Logout, handlers.LogoutHandler)

	// Auth HTML pages
	mux.Handle(config.Paths.Account, middleware.AuthMiddleware(http.HandlerFunc(handlers.AccountPageHandler)))
	mux.Handle(config.Paths.Admin, middleware.AuthMiddleware(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
	mux.Handle(config.Paths.AccountPassword, middleware.AuthMiddleware(http.HandlerFunc(handlers.ChangePasswordHandler))) // GET serves HTML, POST handles password change

	// --- Protected API Endpoints ---
	adminUsersAPI := http.HandlerFunc(handlers.GetUsersHandler)
	adminUpdateRoleAPI := http.HandlerFunc(handlers.UpdateUserRoleHandler)
	adminDeleteUserAPI := http.HandlerFunc(handlers.DeleteUserHandler)
	adminSetStatusAPI := http.HandlerFunc(handlers.SetUserActiveStatusHandler)

	mux.Handle(config.Paths.AdminUsersAPI, middleware.AuthMiddleware(middleware.AdminMiddleware(adminUsersAPI)))
	mux.Handle(config.Paths.AdminUsersAPI+"/", middleware.AuthMiddleware(middleware.AdminMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	// All other requests are sent to the proxy. The final handler below will wrap them
	// with the authentication middleware.
	proxyHandler := handlers.NewProxy(targetURL)
	authedProxy := middleware.AuthMiddleware(proxyHandler)

	// finalHandler wraps the mux. If a route is not explicitly defined in the mux,
	// it falls through to the authenticated proxy. This prevents the login page
	// from being caught by the authentication middleware, fixing the redirect loop.
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if a handler is registered for the path in the mux.
		// The returned pattern will be empty if no handler matches.
		_, pattern := mux.Handler(r)
		if pattern != "" {
			// A specific route was matched (e.g., /login, /admin, /assets/). Serve it.
			mux.ServeHTTP(w, r)
		} else {
			// No specific route was matched. Use the authenticated proxy.
			authedProxy.ServeHTTP(w, r)
		}
	})

	// --- Start Server ---
	logging.AppLog.Info("Server starting on :8081")
	if err := http.ListenAndServe(":8081", finalHandler); err != nil {
		logging.AppLog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
