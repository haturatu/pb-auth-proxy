package middleware

import (
	"auth-proxy/config"
	"auth-proxy/types"
	"net"
	"net/http"
	"time"
)

func NewRateLimiter() *types.RateLimiter {
	return &types.RateLimiter{
		Requests: make(map[string][]int64),
		Max:      config.Paths.RateLimitMaxRequests,
		Window:   time.Duration(config.Paths.RateLimitWindowSeconds) * time.Second,
	}
}

func RateLimitMiddleware(l *types.RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l.Mutex.Lock()

			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				l.Mutex.Unlock()
				http.Error(w, "Invalid client address", http.StatusBadRequest)
				return
			}

			now := time.Now().Unix()
			// Bound memory and discard expired clients on every request.
			for key, values := range l.Requests {
				if len(values) == 0 || now-values[len(values)-1] >= int64(l.Window.Seconds()) {
					delete(l.Requests, key)
				}
			}
			if len(l.Requests) >= 10000 && l.Requests[ip] == nil {
				l.Mutex.Unlock()
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
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
				l.Mutex.Unlock()
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			// Count authentication and account mutations; reads do not consume the budget.
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				l.Requests[ip] = append(l.Requests[ip], now)
			}

			l.Mutex.Unlock()
			next.ServeHTTP(w, r)
		})
	}
}

// Cleanup iterates through the rate limiter's request map and removes entries
// for IPs that have no recent requests.
func Cleanup(l *types.RateLimiter) {
	l.Mutex.Lock()
	defer l.Mutex.Unlock()

	for ip, requests := range l.Requests {
		if len(requests) == 0 {
			delete(l.Requests, ip)
		}
	}
}
