package main

import (
	"clamav-rest/internal/metrics"
	"context"
	"errors"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"clamav-rest/internal/clamav"
	"clamav-rest/internal/handlers"
	"clamav-rest/internal/logger"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		panic(err)
	}

	log := logger.New(cfg.LogLevel)
	log.Info().Msg("starting clamav-rest service")

	ctx := context.Background()

	metrics.Init()

	clamClient := clamav.NewClamClient(cfg.DaemonEndpoint, cfg.Timeout, cfg.Keepalive)
	if _, err := clamClient.Ping(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to ping ClamAV daemon")
	}

	r := chi.NewMux()
	h := handlers.NewHandler(log, clamClient)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("This is the Clam AV service")); err != nil {
			log.Error().Err(err).Msg("failed to write response")
		}
	})
	r.Get("/version", h.Version)
	r.Get("/ping", h.Ping)
	r.Handle("/metrics", promhttp.Handler())
	r.Post("/scan", h.InStream(cfg.ServerMaxRequestSize))

	sContext, sCancel := context.WithCancel(ctx)
	s := &http.Server{
		Addr:              cfg.BindAddress,
		BaseContext:       func(net.Listener) context.Context { return sContext },
		Handler:           r,
		ReadTimeout:       cfg.ServerReadTimeout,
		ReadHeaderTimeout: cfg.ServerReadHeaderTimeout,
		WriteTimeout:      cfg.ServerWriteTimeout,
	}

	go func() {
		log.Info().Msgf("starting http server on %s", s.Addr)
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("failed starting http server")
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()
	<-ctx.Done()
	sCancel()
	log.Info().Msg("Shutting down")

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Shutdown(timeoutCtx); err != nil {
		log.Info().Msg("shutting down server")
	}
}
