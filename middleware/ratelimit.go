package middleware

import (
	"auth-proxy/types"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

func NewRateLimiter() *types.RateLimiter {
	maxRequests, err := strconv.Atoi(os.Getenv("USER_CREATION_RATE_LIMIT_MAX_REQUESTS"))
	if err != nil || maxRequests <= 0 {
		maxRequests = 5 // Default value
	}

	windowSeconds, err := strconv.Atoi(os.Getenv("USER_CREATION_RATE_LIMIT_WINDOW_SECONDS"))
	if err != nil || windowSeconds <= 0 {
		windowSeconds = 3600 // Default value (1 hour)
	}

	return &types.RateLimiter{
		Requests: make(map[string][]int64),
		Max:      maxRequests,
		Window:   time.Duration(windowSeconds) * time.Second,
	}
}

func RateLimitMiddleware(l *types.RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l.Mutex.Lock()
			defer l.Mutex.Unlock()

			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			now := time.Now().Unix()
			if _, ok := l.Requests[ip]; !ok {
				l.Requests[ip] = []int64{}
			}

			// Filter out old timestamps
			var recentRequests []int64
			for _, ts := range l.Requests[ip] {
				if now-ts < int64(l.Window.Seconds()) {
					recentRequests = append(recentRequests, ts)
				}
			}
			l.Requests[ip] = recentRequests

			if len(l.Requests[ip]) >= l.Max {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			// Only add a timestamp for POST requests (actual registration attempts)
			if r.Method == http.MethodPost {
				l.Requests[ip] = append(l.Requests[ip], now)
			}

			next.ServeHTTP(w, r)
		})
	}
}
