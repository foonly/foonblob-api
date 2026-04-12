package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/foonly/foonblob-api/internal/models"
	"github.com/foonly/foonblob-api/internal/store"
)

// setupTest initializes a router with an in-memory SQLite store for testing.
func setupTest(t *testing.T) (http.Handler, store.Store) {
	// Use :memory: for SQLite testing to ensure a clean slate and speed
	s, err := store.NewSQLiteStore(":memory:", 10)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	h := NewHandler(s)
	r := NewRouter(h)
	return r, s
}

func signRequest(t *testing.T, secret string, ts int64, body []byte) string {
	hasher := sha256.New()
	hasher.Write(body)
	bodyHash := hex.EncodeToString(hasher.Sum(nil))

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d%s", ts, bodyHash)))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestSyncAPI(t *testing.T) {
	router, _ := setupTest(t)
	syncID := "test-user-123"
	signingSecret := "super-secret"
	blobV1 := "encrypted-payload-v1"
	blobV2 := "encrypted-payload-v2"

	t.Run("GetNonExistentBlob", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/sync/"+syncID, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", rr.Code)
		}
	})

	t.Run("UploadV1", func(t *testing.T) {
		body, _ := json.Marshal(models.SyncRequest{
			Data:               blobV1,
			RegistrationSecret: signingSecret,
		})
		ts := time.Now().Unix()
		sig := signRequest(t, signingSecret, ts, body)

		req := httptest.NewRequest("POST", "/api/v1/sync/"+syncID, bytes.NewBuffer(body))
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("GetLatestAfterV1", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/sync/"+syncID, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rr.Code)
		}

		var res models.SyncBlob
		if err := json.NewDecoder(rr.Body).Decode(&res); err != nil {
			t.Fatal(err)
		}

		if res.Data != blobV1 {
			t.Errorf("expected data %s, got %s", blobV1, res.Data)
		}
	})

	t.Run("UploadV2", func(t *testing.T) {
		body, _ := json.Marshal(models.SyncRequest{Data: blobV2})
		ts := time.Now().Unix() + 1 // Ensure newer timestamp
		sig := signRequest(t, signingSecret, ts, body)

		req := httptest.NewRequest("POST", "/api/v1/sync/"+syncID, bytes.NewBuffer(body))
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("VerifyHistory", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/sync/"+syncID+"/history", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rr.Code)
		}

		var history []models.SyncHistoryEntry
		if err := json.NewDecoder(rr.Body).Decode(&history); err != nil {
			t.Fatal(err)
		}

		if len(history) != 2 {
			t.Errorf("expected history size 2, got %d", len(history))
		}
	})

	t.Run("PayloadTooLarge", func(t *testing.T) {
		largeData := strings.Repeat("a", MaxPayloadSize+1024)
		body, _ := json.Marshal(models.SyncRequest{
			Data:               largeData,
			RegistrationSecret: "new-secret",
		})
		ts := time.Now().Unix()
		sig := signRequest(t, "new-secret", ts, body)

		req := httptest.NewRequest("POST", "/api/v1/sync/large-id", bytes.NewBuffer(body))
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 for oversized payload, got %d", rr.Code)
		}
	})

	t.Run("RateLimiting", func(t *testing.T) {
		limitID := "rate-limit-test"
		limitSecret := "limit-secret"

		for i := 0; i < 5; i++ {
			reqBody := models.SyncRequest{Data: "data"}
			if i == 0 {
				reqBody.RegistrationSecret = limitSecret
			}
			body, _ := json.Marshal(reqBody)
			ts := time.Now().Unix() + int64(i)
			sig := signRequest(t, limitSecret, ts, body)

			req := httptest.NewRequest("POST", "/api/v1/sync/"+limitID, bytes.NewBuffer(body))
			req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
			req.Header.Set("X-Sync-Signature", sig)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusCreated {
				t.Fatalf("expected 201 on attempt %d, got %d: %s", i+1, rr.Code, rr.Body.String())
			}
		}

		body, _ := json.Marshal(models.SyncRequest{Data: "data"})
		ts := time.Now().Unix() + 10
		sig := signRequest(t, limitSecret, ts, body)

		req := httptest.NewRequest("POST", "/api/v1/sync/"+limitID, bytes.NewBuffer(body))
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429 for rate limit, got %d", rr.Code)
		}
	})
}

func TestFetchSpecificVersion(t *testing.T) {
	router, _ := setupTest(t)
	syncID := "version-test"
	secret := "version-secret"

	// Upload one version
	body, _ := json.Marshal(models.SyncRequest{
		Data:               "v1",
		RegistrationSecret: secret,
	})
	tsHeader := time.Now().Unix()
	sig := signRequest(t, secret, tsHeader, body)

	req := httptest.NewRequest("POST", "/api/v1/sync/"+syncID, bytes.NewBuffer(body))
	req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", tsHeader))
	req.Header.Set("X-Sync-Signature", sig)

	router.ServeHTTP(httptest.NewRecorder(), req)

	// Get latest to find timestamp
	req = httptest.NewRequest("GET", "/api/v1/sync/"+syncID, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var res models.SyncBlob
	json.NewDecoder(rr.Body).Decode(&res)
	ts := res.Timestamp

	// Fetch specific version by timestamp
	req = httptest.NewRequest("GET", fmt.Sprintf("/api/v1/sync/%s/%d", syncID, ts), nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 fetching specific version, got %d", rr.Code)
	}

	var verRes models.SyncBlob
	json.NewDecoder(rr.Body).Decode(&verRes)
	if verRes.Data != "v1" {
		t.Errorf("expected 'v1', got '%s'", verRes.Data)
	}
}

func TestStatsEndpoint(t *testing.T) {
	router, _ := setupTest(t)

	// Create an identity and upload a blob to have some stats
	syncID := "stats-test-id"
	secret := "stats-secret"
	body, _ := json.Marshal(models.SyncRequest{
		Data:               "some-data",
		RegistrationSecret: secret,
	})
	ts := time.Now().Unix()
	sig := signRequest(t, secret, ts, body)

	req := httptest.NewRequest("POST", "/api/v1/sync/"+syncID, bytes.NewBuffer(body))
	req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Sync-Signature", sig)
	router.ServeHTTP(httptest.NewRecorder(), req)

	// Test GET /api/v1/stats
	req = httptest.NewRequest("GET", "/api/v1/stats", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var stats models.Stats
	if err := json.NewDecoder(rr.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}

	if stats.Totals.Identities != 1 {
		t.Errorf("expected 1 identity, got %d", stats.Totals.Identities)
	}
	if stats.Totals.Blobs != 1 {
		t.Errorf("expected 1 blob, got %d", stats.Totals.Blobs)
	}
	if stats.Activity.IdentitiesCreated24h != 1 {
		t.Errorf("expected 1 identity created in 24h, got %d", stats.Activity.IdentitiesCreated24h)
	}
}
