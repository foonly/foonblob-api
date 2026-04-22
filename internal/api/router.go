package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// SlogLogger is a middleware that logs requests using slog.
func SlogLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		slog.Info("request processed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"duration", time.Since(start),
			"remote_ip", r.RemoteAddr,
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}

// NewRouter initializes the chi router with common middleware and sync routes.
func NewRouter(h *Handler) http.Handler {
	r := chi.NewRouter()

	// Initialize rate limiter: 5 POSTs/min, 30 GETs/min per ID
	limiter := NewRateLimiter(5, 30)

	// Standard middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(SlogLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// API Routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public Stats with standard CORS
		r.Group(func(r chi.Router) {
			r.Use(cors.Handler(cors.Options{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "OPTIONS"},
				AllowedHeaders: []string{"Accept", "Content-Type"},
			}))
			r.Get("/stats", h.GetStats)
		})

		r.Route("/sync", func(r chi.Router) {
			r.Route("/{id}", func(r chi.Router) {
				r.Use(h.DynamicCORS) // Handles CORS dynamically based on ID
				r.Use(limiter.Limit)
				r.Get("/", h.GetLatest)
				r.Post("/", h.Upload)
				r.Get("/history", h.GetHistory)
				r.Get("/{timestamp}", h.GetVersion)
			})
		})
	})

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	return r
}
