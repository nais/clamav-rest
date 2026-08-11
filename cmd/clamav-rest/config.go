package main

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	BindAddress             string        `json:"bind_address"`
	ServerMaxRequestSize    int64         `json:"server_max_request_size"`
	LogLevel                string        `json:"log_level"`
	DaemonEndpoint          string        `json:"daemon_endpoint"`
	Timeout                 time.Duration `json:"timeout"`
	Keepalive               time.Duration `json:"keepalive"`
	ServerReadTimeout       time.Duration `json:"serverReadTimeout"`
	ServerReadHeaderTimeout time.Duration `json:"serverReadheaderTimeout"`
	ServerWriteTimeout      time.Duration `json:"serverWriteTimeout"`
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	cfg.BindAddress = ":8080"
	cfg.LogLevel = "info"
	cfg.Timeout = 3 * time.Second
	cfg.Keepalive = 3 * time.Second
	cfg.ServerReadTimeout = 120 * time.Second
	cfg.ServerReadHeaderTimeout = 10 * time.Second
	cfg.ServerWriteTimeout = 120 * time.Second
	maxFileSize := "400Mi"

	if val, ok := os.LookupEnv("DAEMON_ENDPOINT"); ok {
		cfg.DaemonEndpoint = val
	}
	if val, ok := os.LookupEnv("MAX_FILE_SIZE"); ok {
		maxFileSize = val
	}

	// Override with flags
	flag.StringVar(&cfg.BindAddress, "bind-address", cfg.BindAddress, "Bind address")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level")
	flag.StringVar(&cfg.DaemonEndpoint, "daemon-endpoint", cfg.DaemonEndpoint, "ClamAV daemon endpoint")
	flag.StringVar(&maxFileSize, "max-file-size", maxFileSize, "Maximum file size accepted by /scan (e.g. 400Mi, 400M)")
	timeout := flag.Int("timeout", int(cfg.Timeout.Seconds()), "Timeout in seconds")
	keepalive := flag.Int("keepalive", int(cfg.Keepalive.Seconds()), "Keepalive in seconds")
	flag.Parse()

	cfg.Timeout = time.Duration(*timeout) * time.Second
	cfg.Keepalive = time.Duration(*keepalive) * time.Second
	var err error
	cfg.ServerMaxRequestSize, err = parseByteSize(maxFileSize)
	if err != nil {
		return nil, fmt.Errorf("invalid max file size %q: %w", maxFileSize, err)
	}

	if cfg.DaemonEndpoint == "" {
		return nil, errors.New("daemon endpoint is required")
	}

	return cfg, nil
}

func parseByteSize(value string) (int64, error) {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if normalized == "" {
		return 0, errors.New("value cannot be empty")
	}
	normalized = strings.TrimSuffix(normalized, "B")

	multiplier := int64(1)
	for _, unit := range []struct {
		suffix     string
		multiplier int64
	}{
		{suffix: "TI", multiplier: 1024 * 1024 * 1024 * 1024},
		{suffix: "GI", multiplier: 1024 * 1024 * 1024},
		{suffix: "MI", multiplier: 1024 * 1024},
		{suffix: "KI", multiplier: 1024},
		{suffix: "T", multiplier: 1000 * 1000 * 1000 * 1000},
		{suffix: "G", multiplier: 1000 * 1000 * 1000},
		{suffix: "M", multiplier: 1000 * 1000},
		{suffix: "K", multiplier: 1000},
	} {
		if strings.HasSuffix(normalized, unit.suffix) {
			multiplier = unit.multiplier
			normalized = strings.TrimSuffix(normalized, unit.suffix)
			break
		}
	}

	size, err := strconv.ParseInt(normalized, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value %q", normalized)
	}
	if size < 0 {
		return 0, errors.New("value cannot be negative")
	}
	if size > math.MaxInt64/multiplier {
		return 0, errors.New("value is too large")
	}

	return size * multiplier, nil
}
