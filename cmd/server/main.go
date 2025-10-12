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

	// --- Create routers: one for CSRF-protected routes, one for non-protected ---
	csrfMux := http.NewServeMux()
	mainMux := http.NewServeMux()

	// --- Static file serving (non-protected) ---
	assetsPath := strings.TrimRight(config.Paths.Assets, "/") + "/"
	assetsFS := http.FileServer(http.Dir("templates"))
	mainMux.Handle(assetsPath, http.StripPrefix(assetsPath, assetsFS))

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

	// --- Route configuration based on frontend type ---
	frontendType := os.Getenv("FRONTEND_TYPE")
	if frontendType == "php" {
		// --- PHP Frontend Routes ---
		loginPageHandler := handlers.NewPhpProxyHandler("login.php")
		registerPageHandler := handlers.NewPhpProxyHandler("register.php")
		accountPageHandler := handlers.NewPhpProxyHandler("account.php")
		accountPasswordPageHandler := handlers.NewPhpProxyHandler("account_password.php")

		// POST actions go to csrfMux, GET pages go to mainMux
		csrfMux.HandleFunc(config.Paths.Login, handlers.LoginHandler)
		mainMux.Handle(config.Paths.Login, loginPageHandler)

		if config.Paths.RegisterEnabled {
			registerPostHandler := middleware.RateLimitMiddleware(rateLimiter)(http.HandlerFunc(handlers.RegisterHandler))
			csrfMux.Handle(config.Paths.Register, registerPostHandler)
			mainMux.Handle(config.Paths.Register, registerPageHandler)
		}

		accountPasswordPostHandler := http.HandlerFunc(handlers.ChangePasswordHandler)
		csrfMux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(accountPasswordPostHandler))
		mainMux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(accountPasswordPageHandler)) // GET is the same page

		mainMux.Handle(config.Paths.Account, middleware.SessionAuth(accountPageHandler))
		csrfMux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
		mainMux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))

	} else {
		// --- Go Template Frontend Routes ---
		// POST actions go to csrfMux, GET pages go to mainMux
		csrfMux.HandleFunc(config.Paths.Login, handlers.LoginHandler)
		mainMux.HandleFunc(config.Paths.Login, handlers.LoginHandler) // Handles GET

		if config.Paths.RegisterEnabled {
			registerHandler := middleware.RateLimitMiddleware(rateLimiter)(http.HandlerFunc(handlers.RegisterHandler))
			csrfMux.Handle(config.Paths.Register, registerHandler)
			mainMux.Handle(config.Paths.Register, registerHandler) // Handles GET
		}

		// Protected pages
		accountHandler := http.HandlerFunc(handlers.AccountPageHandler)
		adminHandler := middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))
		passwordHandler := http.HandlerFunc(handlers.ChangePasswordHandler)

		mainMux.Handle(config.Paths.Account, middleware.SessionAuth(accountHandler))
		csrfMux.Handle(config.Paths.Account, middleware.SessionAuth(accountHandler))

		mainMux.Handle(config.Paths.Admin, middleware.SessionAuth(adminHandler))
		csrfMux.Handle(config.Paths.Admin, middleware.SessionAuth(adminHandler))

		mainMux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(passwordHandler))
		csrfMux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(passwordHandler))
	}

	// --- Common Routes (non-CSRF) ---
	mainMux.HandleFunc(config.Paths.Logout, handlers.LogoutHandler)
	mainMux.HandleFunc("/auth/refresh", handlers.RefreshTokenHandler)
	mainMux.HandleFunc("/api/auth/token", handlers.TokenHandler)

	// --- Protected API Endpoints (for Admin UI, protected by Bearer/Session, CSRF applied) ---
	adminCreateUserAPI := http.HandlerFunc(handlers.CreateUserHandler)
	getUsersHandler := http.HandlerFunc(handlers.GetUsersHandler)
	adminUsersAPI := methodSwitch(getUsersHandler, adminCreateUserAPI) // GET and POST

	adminUpdateRoleAPI := http.HandlerFunc(handlers.UpdateUserRoleHandler)
	adminDeleteUserAPI := http.HandlerFunc(handlers.DeleteUserHandler)
	adminSetStatusAPI := http.HandlerFunc(handlers.SetUserActiveStatusHandler)

	// Apply CSRF protection to state-changing admin API endpoints
	csrfMux.Handle(config.Paths.AdminUsersAPI, middleware.BearerAuth(middleware.AdminMiddleware(adminUsersAPI)))
	mainMux.Handle(config.Paths.AdminUsersAPI, middleware.BearerAuth(middleware.AdminMiddleware(getUsersHandler))) // GET is safe

	csrfMux.Handle(config.Paths.AdminUsersAPI+"/", middleware.BearerAuth(middleware.AdminMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	// --- Main Application Proxy (not CSRF protected) ---
	proxyHandler := handlers.NewProxy(targetURL)

	// --- CSRF Middleware Configuration ---
	csrfSecret := os.Getenv("CSRF_SECRET_KEY")
	if csrfSecret == "" {
		logging.AppLog.Error("CSRF_SECRET_KEY environment variable not set")
		os.Exit(1)
	}
	csrfOptions := []csrf.Option{
		csrf.Secure(os.Getenv("ENV") == "production"),
		csrf.Path("/"),
		csrf.HttpOnly(true),
	}
	trustedOrigins := os.Getenv("CSRF_TRUSTED_ORIGINS")
	if trustedOrigins != "" {
		origins := strings.Split(trustedOrigins, ",")
		csrfOptions = append(csrfOptions, csrf.TrustedOrigins(origins))
	}
	csrfMiddleware := csrf.Protect([]byte(csrfSecret), csrfOptions...)
	csrfProtectedHandler := csrfMiddleware(csrfMux)

	// --- Final Handler: Delegates to CSRF mux, main mux, or proxy ---
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check CSRF-protected routes first
		_, csrfPattern := csrfMux.Handler(r)
		if csrfPattern != "" {
			csrfProtectedHandler.ServeHTTP(w, r)
			return
		}

		// Check non-CSRF routes next
		_, mainPattern := mainMux.Handler(r)
		if mainPattern != "" {
			mainMux.ServeHTTP(w, r)
			return
		}

		// Fallback to the proxy
		path := r.URL.Path
		if config.Paths.ProtectAPI && strings.HasPrefix(path, config.Paths.APIPath) {
			middleware.BearerAuth(proxyHandler).ServeHTTP(w, r)
		} else if config.Paths.ProtectFrontend {
			middleware.SessionAuth(proxyHandler).ServeHTTP(w, r)
		} else {
			proxyHandler.ServeHTTP(w, r)
		}
	})

	// --- Start Server ---
	port := os.Getenv("LISTEN_PORT")
	if port == "" {
		port = "8080"
	}
	listenAddr := ":" + port
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

	
