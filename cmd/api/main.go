package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/foonly/foonblob-api/internal/api"
	"github.com/foonly/foonblob-api/internal/config"
	"github.com/foonly/foonblob-api/internal/store"
)

// Version is set during build time via ldflags
var Version = "dev"

func main() {
	// Initialize structured logging (slog) with JSON output
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load configuration using Viper
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Initialize the persistence layer
	s, err := store.NewSQLiteStore(cfg.DSN, cfg.HistoryLimit, cfg.SecretEncryptionKey)
	if err != nil {
		slog.Error("failed to initialize storage", "error", err)
		os.Exit(1)
	}
	defer s.Close()

	// Start background cleanup worker
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		// Run once on startup
		slog.Info("Running initial database cleanup...")
		if deleted, err := s.CleanupOldIdentities(context.Background()); err != nil {
			slog.Error("cleanup error", "error", err)
		} else {
			slog.Info("cleanup successful", "deleted_identities", deleted)
		}

		for range ticker.C {
			slog.Info("Running scheduled database cleanup...")
			if deleted, err := s.CleanupOldIdentities(context.Background()); err != nil {
				slog.Error("cleanup error", "error", err)
			} else {
				slog.Info("cleanup successful", "deleted_identities", deleted)
			}
		}
	}()

	// Initialize handlers and router
	handler := api.NewHandler(s, cfg.StatsToken)
	router := api.NewRouter(handler)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Channel to listen for interrupt signals to gracefully shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("Starting server", "port", cfg.Port, "version", Version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen failure", "error", err)
			os.Exit(1)
		}
	}()

	<-done
	slog.Info("Server stopping...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server Shutdown Failed", "error", err)
		os.Exit(1)
	}
	slog.Info("Server exited properly")
}
