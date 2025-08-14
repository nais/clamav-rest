package logger

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name          string
		logLevel      string
		expectedLevel zerolog.Level
	}{
		{"Valid log level - info", "info", zerolog.InfoLevel},
		{"Valid log level - debug", "debug", zerolog.DebugLevel},
		{"Invalid log level", "invalid", zerolog.InfoLevel}, // Default to info
		{"Empty log level", "", zerolog.InfoLevel},          // Default to info
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := New(tt.logLevel)
			assert.Equal(t, tt.expectedLevel, logger.GetLevel())
		})
	}
}

func TestLoggerOutput(t *testing.T) {
	var buf bytes.Buffer
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	// Create a logger that writes to a buffer
	log := zerolog.New(&buf).With().Timestamp().Logger()
	log.Debug().Msg("test debug message")

	output := buf.String()
	assert.Contains(t, output, "test debug message", "Expected log message not found in output")
}
