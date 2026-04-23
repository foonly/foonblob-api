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
	s, err := store.NewSQLiteStore(":memory:", 10, "")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	h := NewHandler(s, "")
	r, stop := NewRouter(h)
	t.Cleanup(stop)
	return r, s
}

func signRequest(t *testing.T, secret string, ts int64, method, path string, body []byte) string {
	var contentToSign string
	if method == http.MethodPost && body != nil {
		hasher := sha256.New()
		hasher.Write(body)
		bodyHash := hex.EncodeToString(hasher.Sum(nil))
		contentToSign = fmt.Sprintf("%d%s", ts, bodyHash)
	} else {
		contentToSign = fmt.Sprintf("%d%s", ts, path)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(contentToSign))
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

		// Should be 404 because identity doesn't exist, even before auth check
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", rr.Code)
		}
	})

	t.Run("UploadV1", func(t *testing.T) {
		path := "/api/v1/sync/" + syncID
		body, _ := json.Marshal(models.SyncRequest{
			Data:               blobV1,
			RegistrationSecret: signingSecret,
		})
		ts := time.Now().Unix()
		sig := signRequest(t, signingSecret, ts, "POST", path, body)

		req := httptest.NewRequest("POST", path, bytes.NewBuffer(body))
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("GetLatestWithoutAuth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/sync/"+syncID, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401 for unauthenticated GET, got %d", rr.Code)
		}
	})

	t.Run("GetLatestWithAuth", func(t *testing.T) {
		path := "/api/v1/sync/" + syncID
		ts := time.Now().Unix() + 10 // ensure newer than upload
		sig := signRequest(t, signingSecret, ts, "GET", path, nil)

		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)

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
		path := "/api/v1/sync/" + syncID
		body, _ := json.Marshal(models.SyncRequest{Data: blobV2})
		ts := time.Now().Unix() + 20
		sig := signRequest(t, signingSecret, ts, "POST", path, body)

		req := httptest.NewRequest("POST", path, bytes.NewBuffer(body))
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("VerifyHistory", func(t *testing.T) {
		path := "/api/v1/sync/" + syncID + "/history"
		ts := time.Now().Unix() + 30
		sig := signRequest(t, signingSecret, ts, "GET", path, nil)

		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)

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
		sig := signRequest(t, "new-secret", ts, "POST", "/api/v1/sync/large-id", body)

		req := httptest.NewRequest("POST", "/api/v1/sync/large-id", bytes.NewBuffer(body))
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 for oversized payload, got %d", rr.Code)
		}
	})
}

func TestFetchSpecificVersion(t *testing.T) {
	router, _ := setupTest(t)
	syncID := "version-test"
	secret := "version-secret"
	path := "/api/v1/sync/" + syncID

	// Upload one version
	body, _ := json.Marshal(models.SyncRequest{
		Data:               "v1",
		RegistrationSecret: secret,
	})
	tsHeader := time.Now().Unix()
	sig := signRequest(t, secret, tsHeader, "POST", path, body)

	req := httptest.NewRequest("POST", path, bytes.NewBuffer(body))
	req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", tsHeader))
	req.Header.Set("X-Sync-Signature", sig)

	router.ServeHTTP(httptest.NewRecorder(), req)

	// Get latest to find timestamp
	tsLatest := time.Now().Unix() + 1
	sigLatest := signRequest(t, secret, tsLatest, "GET", path, nil)
	req = httptest.NewRequest("GET", path, nil)
	req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", tsLatest))
	req.Header.Set("X-Sync-Signature", sigLatest)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var res models.SyncBlob
	json.NewDecoder(rr.Body).Decode(&res)
	tsBlob := res.Timestamp

	// Fetch specific version by timestamp
	versionPath := fmt.Sprintf("/api/v1/sync/%s/%d", syncID, tsBlob)
	tsVer := time.Now().Unix() + 2
	sigVer := signRequest(t, secret, tsVer, "GET", versionPath, nil)

	req = httptest.NewRequest("GET", versionPath, nil)
	req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", tsVer))
	req.Header.Set("X-Sync-Signature", sigVer)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 fetching specific version, got %d: %s", rr.Code, rr.Body.String())
	}

	var verRes models.SyncBlob
	json.NewDecoder(rr.Body).Decode(&verRes)
	if verRes.Data != "v1" {
		t.Errorf("expected 'v1', got '%s'", verRes.Data)
	}
}

func TestOriginEnforcement(t *testing.T) {
	router, _ := setupTest(t)
	syncID := "origin-test-id"
	secret := "origin-test-secret"
	allowedOrigin := "https://example.com"
	path := "/api/v1/sync/" + syncID

	// Register the identity with an explicit allowed origin
	t.Run("RegisterWithOrigin", func(t *testing.T) {
		body, _ := json.Marshal(models.SyncRequest{
			Data:               "initial-data",
			RegistrationSecret: secret,
			AllowedOrigin:      allowedOrigin,
		})
		ts := time.Now().Unix()
		sig := signRequest(t, secret, ts, "POST", path, body)

		req := httptest.NewRequest("POST", path, bytes.NewBuffer(body))
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)
		req.Header.Set("Origin", allowedOrigin)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("GetWithMatchingOrigin", func(t *testing.T) {
		ts := time.Now().Unix() + 10
		sig := signRequest(t, secret, ts, "GET", path, nil)

		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)
		req.Header.Set("Origin", allowedOrigin)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200 for matching origin, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("GetWithMismatchedOrigin", func(t *testing.T) {
		ts := time.Now().Unix() + 20
		sig := signRequest(t, secret, ts, "GET", path, nil)

		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)
		req.Header.Set("Origin", "https://evil.com")

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status 403 for mismatched origin, got %d", rr.Code)
		}
	})

	t.Run("GetWithNoOriginHeader", func(t *testing.T) {
		ts := time.Now().Unix() + 30
		sig := signRequest(t, secret, ts, "GET", path, nil)

		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)
		// No Origin header — non-browser / CLI clients must not be blocked

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200 for request without Origin header, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("PreflightWithMismatchedOrigin", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", path, nil)
		req.Header.Set("Origin", "https://evil.com")
		req.Header.Set("Access-Control-Request-Method", "GET")

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status 403 for preflight with mismatched origin, got %d", rr.Code)
		}
	})
}

func TestOriginValidation(t *testing.T) {
	router, _ := setupTest(t)

	tests := []struct {
		name           string
		origin         string
		expectedStatus int
	}{
		{"WildcardRejected", "*", http.StatusBadRequest},
		{"NoSchemeRejected", "example.com", http.StatusBadRequest},
		{"FTPSchemeRejected", "ftp://example.com", http.StatusBadRequest},
		{"HTTPAccepted", "http://example.com", http.StatusCreated},
		{"HTTPSAccepted", "https://example.com", http.StatusCreated},
		{"PathStripped", "https://example.org/some/path?q=1", http.StatusCreated},
		{"PortPreserved", "https://example.net:8443", http.StatusCreated},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := fmt.Sprintf("origin-valid-%d", i)
			secret := "test-secret"
			p := "/api/v1/sync/" + id
			body, _ := json.Marshal(models.SyncRequest{
				Data:               "data",
				RegistrationSecret: secret,
				AllowedOrigin:      tc.origin,
			})
			ts := time.Now().Unix() + int64(i)
			sig := signRequest(t, secret, ts, "POST", p, body)

			req := httptest.NewRequest("POST", p, bytes.NewBuffer(body))
			req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
			req.Header.Set("X-Sync-Signature", sig)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("origin %q: expected status %d, got %d: %s", tc.origin, tc.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}

	// Verify that path/query stripping was applied: after registering with a URL
	// that has a path, subsequent requests using the bare origin should be accepted.
	t.Run("NormalizationApplied", func(t *testing.T) {
		id := "origin-normalize-check"
		secret := "norm-secret"
		p := "/api/v1/sync/" + id
		rawOrigin := "https://norm.example.com/app?ref=1"
		canonicalOrigin := "https://norm.example.com"

		body, _ := json.Marshal(models.SyncRequest{
			Data:               "data",
			RegistrationSecret: secret,
			AllowedOrigin:      rawOrigin,
		})
		ts := time.Now().Unix()
		sig := signRequest(t, secret, ts, "POST", p, body)
		req := httptest.NewRequest("POST", p, bytes.NewBuffer(body))
		req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Sync-Signature", sig)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("registration failed: got %d: %s", rr.Code, rr.Body.String())
		}

		// A GET with the canonical (path-less) origin must succeed
		ts2 := time.Now().Unix() + 10
		sig2 := signRequest(t, secret, ts2, "GET", p, nil)
		req2 := httptest.NewRequest("GET", p, nil)
		req2.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts2))
		req2.Header.Set("X-Sync-Signature", sig2)
		req2.Header.Set("Origin", canonicalOrigin)
		rr2 := httptest.NewRecorder()
		router.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 with canonical origin after path-stripping, got %d: %s", rr2.Code, rr2.Body.String())
		}
	})
}

func TestStatsEndpoint(t *testing.T) {
	s, err := store.NewSQLiteStore(":memory:", 10, "")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	token := "test-stats-token"
	h := NewHandler(s, token)
	router, stop := NewRouter(h)
	t.Cleanup(stop)

	// Create an identity and upload a blob to have some stats
	syncID := "stats-test-id"
	secret := "stats-secret"
	path := "/api/v1/sync/" + syncID
	body, _ := json.Marshal(models.SyncRequest{
		Data:               "some-data",
		RegistrationSecret: secret,
	})
	ts := time.Now().Unix()
	sig := signRequest(t, secret, ts, "POST", path, body)

	req := httptest.NewRequest("POST", path, bytes.NewBuffer(body))
	req.Header.Set("X-Sync-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Sync-Signature", sig)
	router.ServeHTTP(httptest.NewRecorder(), req)

	// Test GET /api/v1/stats - Unauthorized
	req = httptest.NewRequest("GET", "/api/v1/stats", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for missing token, got %d", rr.Code)
	}

	// Test GET /api/v1/stats - Authorized
	req = httptest.NewRequest("GET", "/api/v1/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var stats models.Stats
	if err := json.NewDecoder(rr.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}

	if stats.Totals.Identities != 1 {
		t.Errorf("expected 1 identity, got %d", stats.Totals.Identities)
	}
}
