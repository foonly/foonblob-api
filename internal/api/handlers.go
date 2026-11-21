package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/foonly/foonblob-api/internal/models"
	"github.com/foonly/foonblob-api/internal/store"
	"github.com/go-chi/chi/v5"
)

const (
	// MaxPayloadSize defines the maximum allowed size for the request body (1MB).
	MaxPayloadSize = 1024 * 1024

	// MaxIDLength bounds the length of newly registered sync IDs.
	MaxIDLength = 256
)

type Handler struct {
	store      store.Store
	statsToken string
	hub        *Hub
}

func NewHandler(s store.Store, statsToken string, hub *Hub) *Handler {
	return &Handler{
		store:      s,
		statsToken: statsToken,
		hub:        hub,
	}
}

// DynamicCORS is a middleware that sets the Access-Control-Allow-Origin header
// based on the allowed_origin stored for the given sync ID, and enforces
// server-side origin checking when an origin restriction is registered.
func (h *Handler) DynamicCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let browser clients read the server time, so they can detect and
		// correct for a device clock outside the timestamp window.
		w.Header().Set("Access-Control-Expose-Headers", "Date")

		id := chi.URLParam(r, "id")
		if id != "" {
			identity, err := h.store.GetIdentity(r.Context(), id)
			if err == nil && identity.AllowedOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", identity.AllowedOrigin)
				w.Header().Add("Vary", "Origin")

				// Server-side enforcement: CORS headers alone only prevent browsers
				// from reading responses; they do not stop the request from being made.
				if !originAllowed(r.Header.Get("Origin"), identity.AllowedOrigin) {
					http.Error(w, "origin not allowed", http.StatusForbidden)
					return
				}
			} else {
				// No origin restriction registered (or the ID does not exist yet,
				// i.e. the registration request itself).
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

// verifySignature authenticates a sync request against an identity.
// For POST requests the signature covers the SHA-256 of the body; for GET
// requests it covers the URL path.
func verifySignature(r *http.Request, identity *models.SyncIdentity, body []byte) (int64, store.Signature, error) {
	ts, err := strconv.ParseInt(r.Header.Get("X-Sync-Timestamp"), 10, 64)
	if err != nil {
		return 0, store.Signature{}, errors.New("invalid or missing X-Sync-Timestamp")
	}

	content := r.URL.Path
	if r.Method == http.MethodPost {
		content = sha256Hex(body)
	}

	sig, err := authenticate(identity.SigningSecret, ts, content, r.Header.Get("X-Sync-Signature"))
	if err != nil {
		if errors.Is(err, errMissingSig) {
			return 0, store.Signature{}, errors.New("missing X-Sync-Signature")
		}
		return 0, store.Signature{}, err
	}
	return ts, sig, nil
}

// authorizeRead looks up the identity, verifies the request signature and atomically
// consumes the request timestamp. It writes an error response and returns false on
// failure.
func (h *Handler) authorizeRead(w http.ResponseWriter, r *http.Request, id, op string) bool {
	identity, err := h.store.GetIdentity(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "sync id not found", http.StatusNotFound)
			return false
		}
		slog.Error(op+": failed to get identity", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return false
	}

	_, sig, err := verifySignature(r, identity, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return false
	}

	if err := h.store.Consume(r.Context(), id, sig); err != nil {
		if errors.Is(err, store.ErrReplay) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return false
		}
		slog.Error(op+": failed to update identity timestamp", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return false
	}
	return true
}

// GetLatest handles GET /api/v1/sync/:id
func (h *Handler) GetLatest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.authorizeRead(w, r, id, "GetLatest") {
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

	h.respondWithJSON(w, http.StatusOK, blob)
}

// Upload handles POST /api/v1/sync/:id
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Limit request body size and read it for hashing
	r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadSize)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read body", http.StatusBadRequest)
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

	identity, err := h.store.GetIdentity(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		h.register(w, r, id, &req, bodyBytes)
		return
	case err != nil:
		slog.Error("Upload: failed to get identity", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	ts, sig, err := verifySignature(r, identity, bodyBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Atomically consumes the signature, stores the blob and prunes history.
	version, err := h.store.SaveBlob(r.Context(), id, req.Data, ts, sig)
	if err != nil {
		if errors.Is(err, store.ErrReplay) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		slog.Error("Upload: failed to save blob", "id", id, "error", err)
		http.Error(w, "failed to save sync data", http.StatusInternalServerError)
		return
	}

	if h.hub != nil {
		h.hub.BroadcastUpdate(id, req.Data, version)
	}
	w.WriteHeader(http.StatusCreated)
}

// register handles the first upload for a previously unknown sync ID. The request
// is verified against the secret it carries before anything is written, and the
// identity and its first blob are stored in a single transaction.
func (h *Handler) register(w http.ResponseWriter, r *http.Request, id string, req *models.SyncRequest, body []byte) {
	if req.RegistrationSecret == "" {
		http.Error(w, "registration secret required for new ID", http.StatusUnauthorized)
		return
	}
	if len(id) > MaxIDLength {
		http.Error(w, "sync id too long", http.StatusBadRequest)
		return
	}

	origin := req.AllowedOrigin
	if origin == "" {
		origin = r.Header.Get("Origin")
	}
	if origin != "" {
		normalized, err := normalizeOrigin(origin)
		if err != nil {
			http.Error(w, "invalid allowed_origin: "+err.Error(), http.StatusBadRequest)
			return
		}
		origin = normalized
	}

	ts, _, err := verifySignature(r, &models.SyncIdentity{SigningSecret: req.RegistrationSecret}, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := h.store.Register(r.Context(), id, req.RegistrationSecret, origin, req.Data, ts); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			// Lost a race with a concurrent registration for the same ID.
			http.Error(w, "sync id already registered", http.StatusConflict)
			return
		}
		slog.Error("Upload: failed to register identity", "id", id, "error", err)
		http.Error(w, "failed to create identity", http.StatusInternalServerError)
		return
	}

	if h.hub != nil {
		h.hub.BroadcastUpdate(id, req.Data, ts)
	}
	w.WriteHeader(http.StatusCreated)
}

// GetHistory handles GET /api/v1/sync/:id/history
func (h *Handler) GetHistory(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.authorizeRead(w, r, id, "GetHistory") {
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

	h.respondWithJSON(w, http.StatusOK, history)
}

// GetVersion handles GET /api/v1/sync/:id/:timestamp
func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	requestedTs, err := strconv.ParseInt(chi.URLParam(r, "timestamp"), 10, 64)
	if err != nil {
		http.Error(w, "invalid timestamp format", http.StatusBadRequest)
		return
	}

	if !h.authorizeRead(w, r, id, "GetVersion") {
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

	h.respondWithJSON(w, http.StatusOK, blob)
}

// GetStats handles GET /api/v1/stats
func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	if h.statsToken == "" {
		slog.Warn("GetStats: access denied because stats_token is not configured")
		http.Error(w, "unauthorized: stats token not configured", http.StatusUnauthorized)
		return
	}

	expected := []byte("Bearer " + h.statsToken)
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), expected) != 1 {
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

// ServeWS handles WebSocket connection upgrades
func (h *Handler) ServeWS(w http.ResponseWriter, r *http.Request) {
	if h.hub == nil {
		http.Error(w, "websocket hub not initialized", http.StatusServiceUnavailable)
		return
	}

	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}

	if !h.hub.reserveIP(ip) {
		slog.Warn("WS: IP connection limit exceeded", "ip", ip)
		http.Error(w, "too many connections from this IP", http.StatusTooManyRequests)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.hub.releaseIP(ip)
		slog.Warn("WS: failed to upgrade connection", "error", err)
		return
	}

	client := newClient(h, conn, ip, r.Header.Get("Origin"))
	h.hub.register(client)

	go client.writePump()
	go client.readPump()
}

func (h *Handler) respondWithJSON(w http.ResponseWriter, code int, payload any) {
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
