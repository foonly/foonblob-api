package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/foonly/foonblob-api/internal/api"
	"github.com/foonly/foonblob-api/internal/store"
)

func main() {
	var (
		port         = flag.Int("port", 8080, "HTTP port to listen on")
		dsn          = flag.String("dsn", "sync.db", "SQLite database connection string")
		historyLimit = flag.Int("history-limit", 10, "Maximum number of historical versions to keep per ID")
	)
	flag.Parse()

	// Initialize the persistence layer
	s, err := store.NewSQLiteStore(*dsn, *historyLimit)
	if err != nil {
		log.Fatalf("failed to initialize storage: %v", err)
	}
	defer s.Close()

	// Start background cleanup worker
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		// Run once on startup
		log.Println("Running initial database cleanup...")
		if deleted, err := s.CleanupOldIdentities(context.Background()); err != nil {
			log.Printf("cleanup error: %v", err)
		} else {
			log.Printf("cleanup successful: removed %d identities", deleted)
		}

		for range ticker.C {
			log.Println("Running scheduled database cleanup...")
			if deleted, err := s.CleanupOldIdentities(context.Background()); err != nil {
				log.Printf("cleanup error: %v", err)
			} else {
				log.Printf("cleanup successful: removed %d identities", deleted)
			}
		}
	}()

	// Initialize handlers and router
	handler := api.NewHandler(s)
	router := api.NewRouter(handler)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Channel to listen for interrupt signals to gracefully shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("Starting server on port %d...", *port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	<-done
	log.Print("Server stopping...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}
	log.Print("Server exited properly")
}
