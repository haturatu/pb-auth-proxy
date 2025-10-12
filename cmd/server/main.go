package main

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/handlers"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/models"
	"auth-proxy/types"
	"auth-proxy/worker"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/gorilla/csrf"
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

	// Initialize and start the worker pool
	pool := worker.NewWorkerPool()
	defer worker.Close(pool)
	handlers.SetWorkerPool(pool)

	// Get target URL for proxy
	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		logging.AppLog.Error("TARGET_URL environment variable not set")
		os.Exit(1)
	}

	// --- Create routers for Web and API ---
	webMux := http.NewServeMux()
	apiMux := http.NewServeMux()

	// --- Static file serving (Web) ---
	assetsPath := strings.TrimRight(config.Paths.Assets, "/") + "/"
	assetsFS := http.FileServer(http.Dir("templates"))
	webMux.Handle(assetsPath, http.StripPrefix(assetsPath, assetsFS))

	// --- Rate Limiter ---
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

	// --- Web UI Routes (CSRF-protected) ---
	if frontendType := os.Getenv("FRONTEND_TYPE"); frontendType == "php" {
		// PHP frontend routes
		loginPageHandler := handlers.NewPhpProxyHandler("login.php")
		registerPageHandler := handlers.NewPhpProxyHandler("register.php")
		accountPageHandler := handlers.NewPhpProxyHandler("account.php")
		accountPasswordPageHandler := handlers.NewPhpProxyHandler("account_password.php")

		loginHandler := methodSwitch(loginPageHandler, http.HandlerFunc(handlers.LoginHandler))
		webMux.Handle(config.Paths.Login, loginHandler)

		if config.Paths.RegisterEnabled {
			registerPostHandler := middleware.RateLimitMiddleware(rateLimiter)(http.HandlerFunc(handlers.RegisterHandler))
			registerHandler := methodSwitch(registerPageHandler, registerPostHandler)
			webMux.Handle(config.Paths.Register, registerHandler)
		}

		accountPasswordPostHandler := http.HandlerFunc(handlers.ChangePasswordHandler)
		accountPasswordHandler := methodSwitch(accountPasswordPageHandler, accountPasswordPostHandler)
		webMux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(accountPasswordHandler))
		webMux.Handle(config.Paths.Account, middleware.SessionAuth(accountPageHandler))
		webMux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
	} else {
		// Go template frontend routes
		webMux.HandleFunc(config.Paths.Login, handlers.LoginHandler)
		if config.Paths.RegisterEnabled {
			webMux.Handle(config.Paths.Register, middleware.RateLimitMiddleware(rateLimiter)(http.HandlerFunc(handlers.RegisterHandler)))
		}
		webMux.Handle(config.Paths.Account, middleware.SessionAuth(http.HandlerFunc(handlers.AccountPageHandler)))
		webMux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
		webMux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(http.HandlerFunc(handlers.ChangePasswordHandler)))
	}
	webMux.HandleFunc(config.Paths.Logout, handlers.LogoutHandler)

	// --- API Routes (No CSRF) ---
	apiMux.HandleFunc("/api/auth/token", handlers.TokenHandler)
	apiMux.HandleFunc("/auth/refresh", handlers.RefreshTokenHandler)

	// Admin API endpoints
	adminCreateUserAPI := http.HandlerFunc(handlers.CreateUserHandler)
	getUsersHandler := http.HandlerFunc(handlers.GetUsersHandler)
	adminUsersAPI := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminCreateUserAPI.ServeHTTP(w, r)
		} else {
			getUsersHandler.ServeHTTP(w, r)
		}
	})
	adminUpdateRoleAPI := http.HandlerFunc(handlers.UpdateUserRoleHandler)
	adminDeleteUserAPI := http.HandlerFunc(handlers.DeleteUserHandler)
	adminSetStatusAPI := http.HandlerFunc(handlers.SetUserActiveStatusHandler)

	apiMux.Handle(config.Paths.AdminUsersAPI, middleware.BearerAuth(middleware.AdminMiddleware(adminUsersAPI)))
	apiMux.Handle(config.Paths.AdminUsersAPI+"/", middleware.BearerAuth(middleware.AdminMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	// --- CSRF Protection (for Web UI) ---
	csrfSecret := os.Getenv("CSRF_SECRET_KEY")
	if csrfSecret == "" {
		logging.AppLog.Error("CSRF_SECRET_KEY environment variable not set")
		os.Exit(1)
	}
	csrfOptions := []csrf.Option{
		csrf.Secure(os.Getenv("ENV") == "production"),
		csrf.Path("/"),
	}
	sameSiteMode := csrf.SameSiteLaxMode
	switch strings.ToLower(os.Getenv("CSRF_SAME_SITE")) {
	case "strict":
		sameSiteMode = csrf.SameSiteStrictMode
	case "none":
		sameSiteMode = csrf.SameSiteNoneMode
	}
	csrfOptions = append(csrfOptions, csrf.SameSite(sameSiteMode))
	trustedOrigins := os.Getenv("CSRF_TRUSTED_ORIGINS")
	if trustedOrigins != "" {
		origins := strings.Split(trustedOrigins, ",")
		csrfOptions = append(csrfOptions, csrf.TrustedOrigins(origins))
	}
	csrfMiddleware := csrf.Protect([]byte(csrfSecret), csrfOptions...)
	csrfProtectedWebMux := middleware.HandleOptions(csrfMiddleware(webMux))

	// --- Final Handler ---
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Handle API paths
		if strings.HasPrefix(r.URL.Path, config.Paths.APIPath) {
			// Check if a specific handler exists in the API mux
			_, pattern := apiMux.Handler(r)

			// If a specific pattern is found, let the API mux handle it internally.
			if pattern != "" {
				apiMux.ServeHTTP(w, r)
				return
			}

			// If no specific handler is found, it's a request to be proxied.
			// Protect it with Bearer/Cookie auth if PROTECT_API is enabled.
			if config.Paths.ProtectAPI {
				middleware.BearerAuth(proxyHandler).ServeHTTP(w, r)
			} else {
				proxyHandler.ServeHTTP(w, r)
			}
			return
		}

		// Check if the path is a web UI path and apply CSRF protection
		_, webPattern := webMux.Handler(r)
		if webPattern != "" {
			csrfProtectedWebMux.ServeHTTP(w, r)
			return
		}

		// Fallback to proxy for all other paths
		if config.Paths.ProtectFrontend {
			middleware.SessionAuth(proxyHandler).ServeHTTP(w, r)
		} else {
			proxyHandler.ServeHTTP(w, r)
		}
	})

	// Get server port
	port := os.Getenv("LISTEN_PORT")
	if port == "" {
		port = "8080"
	}
	listenAddr := ":" + port

	// --- Start Server ---
	logging.AppLog.Info("Server starting on " + listenAddr)

	// Start periodic background tasks
	go startBackgroundTasks(pool, rateLimiter)

	if err := http.ListenAndServe(listenAddr, finalHandler); err != nil {
		logging.AppLog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}

	

	// startBackgroundTasks launches periodic jobs in the background.

	func startBackgroundTasks(pool *types.WorkerPool, limiter *types.RateLimiter) {

		// Ticker for expired token cleanup (every hour)

		tokenTicker := time.NewTicker(1 * time.Hour)

		defer tokenTicker.Stop()

	

		// Ticker for rate limiter cleanup (every 10 minutes)

		rateLimiterTicker := time.NewTicker(24 * time.Hour)

		defer rateLimiterTicker.Stop()

	

		logging.AppLog.Info("Background task scheduler started")

	

		// Run initial cleanup tasks at startup

		submitTokenCleanup(pool)

		submitRateLimiterCleanup(pool, limiter)

	

		// Run tasks on their respective tickers

		for {

			select {

			case <-tokenTicker.C:

				submitTokenCleanup(pool)

			case <-rateLimiterTicker.C:

				submitRateLimiterCleanup(pool, limiter)

			}

		}

	}

	

	// submitTokenCleanup submits the expired token deletion task to the worker pool.

	func submitTokenCleanup(pool *types.WorkerPool) {

		worker.Submit(pool, func() {

			logging.AppLog.Info("Running background task: deleting expired tokens")

			rowsAffected, err := models.DeleteExpiredTokens()

			if err != nil {

				logging.AppLog.Error("Failed to delete expired tokens", "error", err)

			} else {

				if rowsAffected > 0 {

					logging.AppLog.Info("Finished deleting expired tokens", "deleted_count", rowsAffected)

				}

			}

		})

	}

	

	// submitRateLimiterCleanup submits the rate limiter cleanup task to the worker pool.

	func submitRateLimiterCleanup(pool *types.WorkerPool, limiter *types.RateLimiter) {

		worker.Submit(pool, func() {

			logging.AppLog.Info("Running background task: cleaning up rate limiter")

			middleware.Cleanup(limiter)

		})

	}
