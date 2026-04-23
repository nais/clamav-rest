package main

import (
	"errors"
	"flag"
	"os"
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
	cfg.ServerMaxRequestSize = int64(400 * 1024 * 1024)

	if val, ok := os.LookupEnv("DAEMON_ENDPOINT"); ok {
		cfg.DaemonEndpoint = val
	}

	// Override with flags
	flag.StringVar(&cfg.BindAddress, "bind-address", cfg.BindAddress, "Bind address")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level")
	flag.StringVar(&cfg.DaemonEndpoint, "daemon-endpoint", cfg.DaemonEndpoint, "ClamAV daemon endpoint")
	timeout := flag.Int("timeout", int(cfg.Timeout.Seconds()), "Timeout in seconds")
	keepalive := flag.Int("keepalive", int(cfg.Keepalive.Seconds()), "Keepalive in seconds")
	flag.Parse()

	cfg.Timeout = time.Duration(*timeout) * time.Second
	cfg.Keepalive = time.Duration(*keepalive) * time.Second

	if cfg.DaemonEndpoint == "" {
		return nil, errors.New("daemon endpoint is required")
	}

	return cfg, nil
}
