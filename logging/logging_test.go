package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLevelStreams(t *testing.T) {
	var stdout, stderr bytes.Buffer
	options := &slog.HandlerOptions{Level: slog.LevelDebug}
	logger := slog.New(splitHandler{slog.NewTextHandler(&stdout, options), slog.NewTextHandler(&stderr, options)}).With("service", "auth").WithGroup("request")
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warning message")
	logger.Error("error message")
	for _, message := range []string{"debug message", "info message"} {
		if !strings.Contains(stdout.String(), message) || strings.Contains(stderr.String(), message) {
			t.Fatalf("%s must only go to stdout", message)
		}
	}
	for _, message := range []string{"warning message", "error message"} {
		if !strings.Contains(stderr.String(), message) || strings.Contains(stdout.String(), message) {
			t.Fatalf("%s must only go to stderr", message)
		}
	}
}
