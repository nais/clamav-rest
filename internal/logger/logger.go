package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

func New(logLevel string) *zerolog.Logger {
	// Set the log level based on the environment variable
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil || logLevel == "" {
		level = zerolog.InfoLevel
	}

	zerolog.DurationFieldUnit = time.Millisecond
	//logger := log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	logger := zerolog.New(os.Stdout).With().Timestamp().Logger().Level(level)

	return &logger
}
