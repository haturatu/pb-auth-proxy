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
