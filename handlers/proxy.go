package handlers

import (
	"auth-proxy/logging"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// NewProxy creates a new reverse proxy handler using httputil.ReverseProxy.
func NewProxy(targetURL string) http.Handler {
	target, err := url.Parse(targetURL)
	if err != nil {
		panic("Invalid target URL: " + err.Error())
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// The default director is mostly fine, but we want to log and ensure the Host header is correct.
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)          // Run the default director
		req.Host = target.Host // Set the Host header to the target's host

		// Log the proxying action
		ip := logging.GetClientIP(req)
		logging.AppLog.Info("Proxying request", "url", req.URL.String(), "ip", ip)
	}

	// Custom error handler for logging
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		ip := logging.GetClientIP(r)
		logging.AppLog.Error("Proxy error", "error", err, "ip", ip)
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}

	return proxy
}
