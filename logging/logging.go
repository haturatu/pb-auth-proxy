package logging

import (
	"context"
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

	var logLevel slog.Level
	switch strings.ToUpper(os.Getenv("LOG_LEVEL")) {
	case "DEBUG":
		logLevel = slog.LevelDebug
	case "INFO":
		logLevel = slog.LevelInfo
	case "WARN":
		logLevel = slog.LevelWarn
	case "ERROR":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo // Default to INFO
	}

	handler := splitHandler{out: slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}), err: slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})}
	AppLog = slog.New(handler)
	SecurityLog = slog.New(handler)
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

type splitHandler struct{ out, err slog.Handler }

func (h splitHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.out.Enabled(ctx, level)
}
func (h splitHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level >= slog.LevelWarn {
		return h.err.Handle(ctx, record)
	}
	return h.out.Handle(ctx, record)
}
func (h splitHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return splitHandler{h.out.WithAttrs(attrs), h.err.WithAttrs(attrs)}
}
func (h splitHandler) WithGroup(name string) slog.Handler {
	return splitHandler{h.out.WithGroup(name), h.err.WithGroup(name)}
}
