package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// RateLimiter implements a simple in-memory token bucket rate limiter
// specifically designed to limit actions per sync ID.
type RateLimiter struct {
	mu          sync.Mutex
	limits      map[string]*bucket
	postsPerMin int
	getsPerMin  int
	done        chan struct{}
	stopOnce    sync.Once
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

// NewRateLimiter creates a new rate limiter with the specified limits and starts a cleanup worker.
func NewRateLimiter(postsPerMin, getsPerMin int) *RateLimiter {
	rl := &RateLimiter{
		limits:      make(map[string]*bucket),
		postsPerMin: postsPerMin,
		getsPerMin:  getsPerMin,
		done:        make(chan struct{}),
	}
	go rl.cleanupWorker()
	return rl
}

// Stop shuts down the background cleanup goroutine and releases the ticker.
// It is safe to call Stop more than once.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.done) })
}

func (rl *RateLimiter) cleanupWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.done:
			return
		}
	}
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, b := range rl.limits {
		// If the bucket hasn't been accessed in 1 hour, remove it
		if now.Sub(b.lastCheck) > 1*time.Hour {
			delete(rl.limits, key)
		}
	}
}

// Limit middleware restricts requests based on the sync ID in the URL.
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if id == "" {
			next.ServeHTTP(w, r)
			return
		}

		limit := rl.getsPerMin
		if r.Method == http.MethodPost {
			limit = rl.postsPerMin
		}

		// Use a unique key for ID + Method to have separate buckets for GET/POST
		key := id + ":" + r.Method

		if !rl.allow(key, limit) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(key string, limitPerMin int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.limits[key]
	if !exists {
		rl.limits[key] = &bucket{
			tokens:    float64(limitPerMin) - 1,
			lastCheck: now,
		}
		return true
	}

	// Calculate how many tokens to add since last check
	duration := now.Sub(b.lastCheck)
	refill := duration.Seconds() * (float64(limitPerMin) / 60.0)
	b.tokens += refill
	b.lastCheck = now

	if b.tokens > float64(limitPerMin) {
		b.tokens = float64(limitPerMin)
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}

	return false
}
