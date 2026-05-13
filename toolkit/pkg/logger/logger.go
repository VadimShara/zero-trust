package logger

import (
	"log/slog"
	"os"
)

func NewLogger(level string) *slog.Logger {
	if level == "" {
		level = os.Getenv("LOG_LEVEL")
	}

	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}
