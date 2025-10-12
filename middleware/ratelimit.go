package middleware

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type RateLimiter struct {
	requests map[string][]int64
	mutex    sync.Mutex
	max      int
	window   time.Duration
}

func NewRateLimiter() *RateLimiter {
	maxRequests, err := strconv.Atoi(os.Getenv("USER_CREATION_RATE_LIMIT_MAX_REQUESTS"))
	if err != nil || maxRequests <= 0 {
		maxRequests = 5 // Default value
	}

	windowSeconds, err := strconv.Atoi(os.Getenv("USER_CREATION_RATE_LIMIT_WINDOW_SECONDS"))
	if err != nil || windowSeconds <= 0 {
		windowSeconds = 3600 // Default value (1 hour)
	}

	return &RateLimiter{
		requests: make(map[string][]int64),
		max:      maxRequests,
		window:   time.Duration(windowSeconds) * time.Second,
	}
}

func (l *RateLimiter) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mutex.Lock()
		defer l.mutex.Unlock()

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		now := time.Now().Unix()
		if _, ok := l.requests[ip]; !ok {
			l.requests[ip] = []int64{}
		}

		// Filter out old timestamps
		var recentRequests []int64
		for _, ts := range l.requests[ip] {
			if now-ts < int64(l.window.Seconds()) {
				recentRequests = append(recentRequests, ts)
			}
		}
		l.requests[ip] = recentRequests

		if len(l.requests[ip]) >= l.max {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// Only add a timestamp for POST requests (actual registration attempts)
		if r.Method == http.MethodPost {
			l.requests[ip] = append(l.requests[ip], now)
		}

		next.ServeHTTP(w, r)
	})
}
