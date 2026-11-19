package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/foonly/foonblob-api/internal/api"
	"github.com/foonly/foonblob-api/internal/config"
	"github.com/foonly/foonblob-api/internal/store"
)

// Version is set during build time via ldflags
var Version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	slog.Info("configuration loaded", "file", cfg.File, "dsn", cfg.DSN, "history_limit", cfg.HistoryLimit, "trust_proxy_headers", cfg.TrustProxyHeaders)
	if cfg.SecretEncryptionKey == "" {
		slog.Warn("secret_encryption_key is not set; signing secrets are stored in plaintext")
	}
	if cfg.StatsToken == "" {
		slog.Warn("stats_token is not set; /api/v1/stats is disabled")
	}

	s, err := store.NewSQLiteStore(cfg.DSN, cfg.HistoryLimit, cfg.SecretEncryptionKey)
	if err != nil {
		return err
	}
	defer s.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		runCleanup(ctx, s)
	}()

	hub := api.NewHub()
	handler := api.NewHandler(s, cfg.StatsToken, hub)
	router, stopLimiter := api.NewRouter(handler, cfg.TrustProxyHeaders)
	defer stopLimiter()

	srv := &http.Server{
		Addr:              net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second, // allows a 1MB upload on a slow link
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("starting server", "addr", srv.Addr, "version", Version)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	slog.Info("server stopping")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown does not track hijacked (WebSocket) connections; close them explicitly.
	hub.Close()
	shutdownErr := srv.Shutdown(shutdownCtx)
	stop()
	<-cleanupDone

	if shutdownErr != nil {
		return shutdownErr
	}
	slog.Info("server exited properly")
	return nil
}

// runCleanup removes stale identities on startup and then every 24 hours until
// ctx is cancelled.
func runCleanup(ctx context.Context, s store.Store) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		if deleted, err := s.CleanupOldIdentities(ctx); err != nil {
			if ctx.Err() == nil {
				slog.Error("cleanup error", "error", err)
			}
		} else {
			slog.Info("cleanup successful", "deleted_identities", deleted)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
