package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/foonly/foonblob-api/internal/models"
	"github.com/foonly/foonblob-api/internal/store"
	"github.com/go-chi/chi/v5"
)

const (
	// MaxPayloadSize defines the maximum allowed size for the encrypted blob (1MB)
	MaxPayloadSize = 1024 * 1024
)

type Handler struct {
	store      store.Store
	statsToken string
}

func NewHandler(s store.Store, statsToken string) *Handler {
	return &Handler{
		store:      s,
		statsToken: statsToken,
	}
}

// DynamicCORS is a middleware that sets the Access-Control-Allow-Origin header
// based on the allowed_origin stored for the given sync ID.
func (h *Handler) DynamicCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if id != "" {
			identity, err := h.store.GetIdentity(r.Context(), id)
			if err == nil && identity.AllowedOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", identity.AllowedOrigin)
				w.Header().Set("Vary", "Origin")
			} else {
				// Fallback to allow all if no specific origin is registered
				// or during registration phase.
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
		}

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization, X-Sync-Timestamp, X-Sync-Signature")
			w.Header().Set("Access-Control-Max-Age", "300")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// verifySignature handles the common signature verification logic for all sync endpoints.
// For POST requests, it hashes the body. For GET requests, it hashes the URL path.
func (h *Handler) verifySignature(r *http.Request, identity *models.SyncIdentity, bodyBytes []byte) (int64, error) {
	// 1. Validate Timestamp Header
	tsHeader := r.Header.Get("X-Sync-Timestamp")
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return 0, errors.New("invalid or missing X-Sync-Timestamp")
	}

	// 2. Check Timestamp Window (5 minutes)
	now := time.Now().Unix()
	if math.Abs(float64(now-ts)) > 300 {
		return 0, errors.New("timestamp expired or invalid")
	}

	// 3. Replay Protection
	if ts <= identity.LastTimestamp {
		return 0, errors.New("timestamp must be newer than previous request")
	}

	// 4. Signature Verification
	sigHeader := r.Header.Get("X-Sync-Signature")
	if sigHeader == "" {
		return 0, errors.New("missing X-Sync-Signature")
	}

	var contentToSign string
	if r.Method == http.MethodPost && bodyBytes != nil {
		hasher := sha256.New()
		hasher.Write(bodyBytes)
		bodyHash := hex.EncodeToString(hasher.Sum(nil))
		contentToSign = fmt.Sprintf("%d%s", ts, bodyHash)
	} else {
		// For GET (or body-less requests), sign the path to tie the signature to the resource
		contentToSign = fmt.Sprintf("%d%s", ts, r.URL.Path)
	}

	mac := hmac.New(sha256.New, []byte(identity.SigningSecret))
	mac.Write([]byte(contentToSign))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sigHeader), []byte(expectedSig)) {
		return 0, errors.New("invalid signature")
	}

	return ts, nil
}

// GetLatest handles GET /api/v1/sync/:id
func (h *Handler) GetLatest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing sync id", http.StatusBadRequest)
		return
	}

	identity, err := h.store.GetIdentity(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "sync id not found", http.StatusNotFound)
			return
		}
		slog.Error("GetLatest: failed to get identity", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	ts, err := h.verifySignature(r, identity, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	blob, err := h.store.GetLatestBlob(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "blob not found", http.StatusNotFound)
			return
		}
		slog.Error("GetLatest: failed to get blob", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Update identity timestamp for replay protection and access tracking
	_ = h.store.UpdateIdentityTimestamp(r.Context(), id, ts)
	_ = h.store.UpdateLastAccessed(r.Context(), id)

	h.respondWithJSON(w, http.StatusOK, blob)
}

// Upload handles POST /api/v1/sync/:id
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing sync id", http.StatusBadRequest)
		return
	}

	// Limit request body size and read it for hashing
	r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadSize)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body or payload too large", http.StatusBadRequest)
		return
	}

	var req models.SyncRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Data == "" {
		http.Error(w, "data blob is required", http.StatusBadRequest)
		return
	}

	// Retrieve Identity
	identity, err := h.store.GetIdentity(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Registration Path
			if req.RegistrationSecret == "" {
				http.Error(w, "registration secret required for new ID", http.StatusUnauthorized)
				return
			}

			origin := req.AllowedOrigin
			if origin == "" {
				origin = r.Header.Get("Origin")
			}

			if err := h.store.CreateIdentity(r.Context(), id, req.RegistrationSecret, origin); err != nil {
				slog.Error("Upload: failed to create identity", "id", id, "error", err)
				http.Error(w, "failed to create identity", http.StatusInternalServerError)
				return
			}
			identity = &models.SyncIdentity{
				ID:            id,
				SigningSecret: req.RegistrationSecret,
				AllowedOrigin: origin,
				LastTimestamp: 0,
			}
		} else {
			slog.Error("Upload: failed to get identity", "id", id, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	ts, err := h.verifySignature(r, identity, bodyBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Save Data (this also updates identity timestamp for replay protection)
	if err := h.store.SaveBlob(r.Context(), id, req.Data, ts); err != nil {
		slog.Error("Upload: failed to save blob", "id", id, "error", err)
		http.Error(w, "failed to save sync data", http.StatusInternalServerError)
		return
	}

	_ = h.store.UpdateLastAccessed(r.Context(), id)
	w.WriteHeader(http.StatusCreated)
}

// GetHistory handles GET /api/v1/sync/:id/history
func (h *Handler) GetHistory(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing sync id", http.StatusBadRequest)
		return
	}

	identity, err := h.store.GetIdentity(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "sync id not found", http.StatusNotFound)
			return
		}
		slog.Error("GetHistory: failed to get identity", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	ts, err := h.verifySignature(r, identity, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	history, err := h.store.GetHistory(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "no history found", http.StatusNotFound)
			return
		}
		slog.Error("GetHistory: failed to get history", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Update identity timestamp for replay protection
	_ = h.store.UpdateIdentityTimestamp(r.Context(), id, ts)
	_ = h.store.UpdateLastAccessed(r.Context(), id)

	h.respondWithJSON(w, http.StatusOK, history)
}

// GetVersion handles GET /api/v1/sync/:id/:timestamp
func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tsStr := chi.URLParam(r, "timestamp")

	requestedTs, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid timestamp format", http.StatusBadRequest)
		return
	}

	identity, err := h.store.GetIdentity(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "sync id not found", http.StatusNotFound)
			return
		}
		slog.Error("GetVersion: failed to get identity", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	authTs, err := h.verifySignature(r, identity, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	blob, err := h.store.GetBlobAtTimestamp(r.Context(), id, requestedTs)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "version not found", http.StatusNotFound)
			return
		}
		slog.Error("GetVersion: failed to get version", "id", id, "ts", requestedTs, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Update identity timestamp for replay protection
	_ = h.store.UpdateIdentityTimestamp(r.Context(), id, authTs)
	_ = h.store.UpdateLastAccessed(r.Context(), id)

	h.respondWithJSON(w, http.StatusOK, blob)
}

// GetStats handles GET /api/v1/stats
func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	if h.statsToken == "" {
		slog.Warn("GetStats: access denied because stats_token is not configured")
		http.Error(w, "unauthorized: stats token not configured", http.StatusUnauthorized)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader != "Bearer "+h.statsToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	stats, err := h.store.GetStats(r.Context())
	if err != nil {
		slog.Error("GetStats failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.respondWithJSON(w, http.StatusOK, stats)
}

func (h *Handler) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		slog.Error("failed to encode JSON response", "error", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
