package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	store store.Store
}

func NewHandler(s store.Store) *Handler {
	return &Handler{store: s}
}

// GetLatest handles GET /api/v1/sync/:id
func (h *Handler) GetLatest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing sync id", http.StatusBadRequest)
		return
	}

	blob, err := h.store.GetLatestBlob(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "sync id not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

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

	// 1. Validate Timestamp Header
	tsHeader := r.Header.Get("X-Sync-Timestamp")
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		http.Error(w, "invalid or missing X-Sync-Timestamp", http.StatusUnauthorized)
		return
	}

	// 2. Check Timestamp Window (5 minutes)
	now := time.Now().Unix()
	if math.Abs(float64(now-ts)) > 300 {
		http.Error(w, "timestamp expired or invalid", http.StatusUnauthorized)
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

	// 3. Retrieve Identity
	identity, err := h.store.GetIdentity(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// 4. Registration Path
			if req.RegistrationSecret == "" {
				http.Error(w, "registration secret required for new ID", http.StatusUnauthorized)
				return
			}

			if err := h.store.CreateIdentity(r.Context(), id, req.RegistrationSecret); err != nil {
				http.Error(w, "failed to create identity", http.StatusInternalServerError)
				return
			}
			identity = &models.SyncIdentity{
				ID:            id,
				SigningSecret: req.RegistrationSecret,
				LastTimestamp: 0,
			}
		} else {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	// 5. Replay Protection
	if ts <= identity.LastTimestamp {
		http.Error(w, "timestamp must be newer than previous request", http.StatusUnauthorized)
		return
	}

	// 6. Signature Verification
	sigHeader := r.Header.Get("X-Sync-Signature")
	if sigHeader == "" {
		http.Error(w, "missing X-Sync-Signature", http.StatusUnauthorized)
		return
	}

	hasher := sha256.New()
	hasher.Write(bodyBytes)
	bodyHash := hex.EncodeToString(hasher.Sum(nil))

	mac := hmac.New(sha256.New, []byte(identity.SigningSecret))
	mac.Write([]byte(fmt.Sprintf("%d%s", ts, bodyHash)))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sigHeader), []byte(expectedSig)) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// 7. Save Data (this also updates identity timestamp for replay protection)
	if err := h.store.SaveBlob(r.Context(), id, req.Data, ts); err != nil {
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

	history, err := h.store.GetHistory(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "no history found for this id", http.StatusNotFound)
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	_ = h.store.UpdateLastAccessed(r.Context(), id)

	h.respondWithJSON(w, http.StatusOK, history)
}

// GetVersion handles GET /api/v1/sync/:id/:timestamp
func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tsStr := chi.URLParam(r, "timestamp")

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid timestamp format", http.StatusBadRequest)
		return
	}

	blob, err := h.store.GetBlobAtTimestamp(r.Context(), id, ts)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "version not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	_ = h.store.UpdateLastAccessed(r.Context(), id)

	h.respondWithJSON(w, http.StatusOK, blob)
}

// GetStats handles GET /api/v1/stats
func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetStats(r.Context())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.respondWithJSON(w, http.StatusOK, stats)
}

func (h *Handler) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
