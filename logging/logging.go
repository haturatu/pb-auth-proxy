package logging

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
)

var (
	AppLog      *slog.Logger
	SecurityLog *slog.Logger
)

// InitLoggers initializes the application and security loggers.
func InitLoggers() {
	// For now, both loggers write to stdout.
	// This could be configured to write to different files (e.g., app.log, security.log)
	appWriter := os.Stdout
	securityWriter := os.Stdout

	AppLog = slog.New(slog.NewTextHandler(appWriter, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: false, // Include source file and line number for app logs
	}))

	SecurityLog = slog.New(slog.NewTextHandler(securityWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		// The default TextHandler format is `time=... level=... msg=... key=value`.
		// This is structured and easily parsable, so we'll stick with it.
	}))
}

// GetClientIP extracts the client IP address from the request.
// It prioritizes the X-Forwarded-For header to work behind a reverse proxy.
func GetClientIP(r *http.Request) string {
	// Check the X-Forwarded-For header first.
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		// The header can contain a comma-separated list of IPs. The client IP is the first one.
		ips := strings.Split(forwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}

	// If the header is not present, fall back to RemoteAddr.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If parsing fails (e.g., no port), return the raw RemoteAddr.
		return r.RemoteAddr
	}
	return ip
}
