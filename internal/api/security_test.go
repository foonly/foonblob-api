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
	"sync"
	"testing"
	"time"

	"github.com/foonly/foonblob-api/internal/models"
	"github.com/foonly/foonblob-api/internal/store"
	"github.com/gorilla/websocket"
)

// testEnv is a router backed by an in-memory store and a live WebSocket hub.
type testEnv struct {
	router http.Handler
	store  store.Store
	hub    *Hub
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:", 10, "")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	hub := NewHub()
	t.Cleanup(hub.Close)
	r, stop := NewRouter(NewHandler(s, "", hub), true)
	t.Cleanup(stop)
	return &testEnv{router: r, store: s, hub: hub}
}

func (e *testEnv) post(t *testing.T, id, secret string, req models.SyncRequest, ts int64, origin string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/v1/sync/" + id
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.Header.Set("X-Sync-Timestamp", fmt.Sprint(ts))
	r.Header.Set("X-Sync-Signature", signRequest(t, secret, ts, http.MethodPost, path, body))
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, r)
	return rr
}

func (e *testEnv) get(t *testing.T, path, secret string, ts int64, origin string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("X-Sync-Timestamp", fmt.Sprint(ts))
	r.Header.Set("X-Sync-Signature", signRequest(t, secret, ts, http.MethodGet, path, nil))
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, r)
	return rr
}

func TestConcurrentReplayAcceptedOnce(t *testing.T) {
	e := newTestEnv(t)
	now := time.Now().Unix()
	if rr := e.post(t, "replay", "s", models.SyncRequest{Data: "x", RegistrationSecret: "s"}, now, ""); rr.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rr.Code, rr.Body)
	}

	// Fire the same signed request many times concurrently: exactly one may succeed.
	ts := now + 1
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := e.get(t, "/api/v1/sync/replay", "s", ts, "")
			mu.Lock()
			codes[rr.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[http.StatusOK] != 1 {
		t.Fatalf("expected exactly one 200 for a replayed request, got %v", codes)
	}
}

func TestConcurrentRegistration(t *testing.T) {
	e := newTestEnv(t)
	ts := time.Now().Unix()
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			secret := fmt.Sprintf("secret-%d", i)
			rr := e.post(t, "race", secret, models.SyncRequest{Data: "x", RegistrationSecret: secret}, ts, "")
			mu.Lock()
			codes[rr.Code]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if codes[http.StatusCreated] != 1 || codes[http.StatusInternalServerError] != 0 {
		t.Fatalf("expected exactly one 201 and no 500s, got %v", codes)
	}
}

func TestFailedRegistrationCreatesNothing(t *testing.T) {
	e := newTestEnv(t)
	// Timestamp far outside the allowed window: signature check must fail.
	rr := e.post(t, "ghost", "s", models.SyncRequest{Data: "x", RegistrationSecret: "s"}, time.Now().Unix()-3600, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if _, err := e.store.GetIdentity(t.Context(), "ghost"); err != store.ErrNotFound {
		t.Fatalf("expected identity not to exist, got %v", err)
	}
}

func TestRegistrationRejectsLongID(t *testing.T) {
	e := newTestEnv(t)
	id := strings.Repeat("a", MaxIDLength+1)
	rr := e.post(t, id, "s", models.SyncRequest{Data: "x", RegistrationSecret: "s"}, time.Now().Unix(), "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestOriginNormalization(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://App.Example.com", "https://app.example.com"},
		{"HTTPS://example.com:443/path", "https://example.com"},
		{"http://example.com:80", "http://example.com"},
		{"http://example.com:8080", "http://example.com:8080"},
		{"http://[::1]:3000", "http://[::1]:3000"},
	}
	for _, c := range cases {
		got, err := normalizeOrigin(c.in)
		if err != nil || got != c.want {
			t.Errorf("normalizeOrigin(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}

	e := newTestEnv(t)
	now := time.Now().Unix()
	rr := e.post(t, "orig", "s", models.SyncRequest{Data: "x", RegistrationSecret: "s", AllowedOrigin: "https://App.Example.com:443"}, now, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rr.Code, rr.Body)
	}
	if rr := e.get(t, "/api/v1/sync/orig", "s", now+1, "https://app.example.com"); rr.Code != http.StatusOK {
		t.Fatalf("browser-form origin should be allowed, got %d", rr.Code)
	}
	if rr := e.get(t, "/api/v1/sync/orig", "s", now+2, "https://evil.example.com"); rr.Code != http.StatusForbidden {
		t.Fatalf("foreign origin should be rejected, got %d", rr.Code)
	}
}

func wsSign(secret string, ts int64, id string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%dsubscribe%s", ts, id)
	return hex.EncodeToString(mac.Sum(nil))
}

func dialWS(t *testing.T, srv *httptest.Server, origin string) *websocket.Conn {
	t.Helper()
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/api/v1/ws", h)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func readWS(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	var m map[string]any
	if err := conn.ReadJSON(&m); err != nil {
		t.Fatalf("read: %v", err)
	}
	return m
}

func TestWebSocketSubscribe(t *testing.T) {
	e := newTestEnv(t)
	srv := httptest.NewServer(e.router)
	defer srv.Close()

	now := time.Now().Unix()
	if rr := e.post(t, "ws-id", "s", models.SyncRequest{Data: "v1", RegistrationSecret: "s", AllowedOrigin: "https://app.example"}, now, ""); rr.Code != http.StatusCreated {
		t.Fatalf("register: %d", rr.Code)
	}

	t.Run("WrongOriginRejected", func(t *testing.T) {
		conn := dialWS(t, srv, "https://evil.example")
		ts := now + 1
		conn.WriteJSON(models.WSClientMessage{Type: "subscribe", ID: "ws-id", Timestamp: ts, Signature: wsSign("s", ts, "ws-id")})
		if m := readWS(t, conn); m["type"] != "error" || m["code"] != float64(http.StatusForbidden) {
			t.Fatalf("expected 403 error, got %v", m)
		}
	})

	conn := dialWS(t, srv, "https://app.example")

	t.Run("BadSignatureRejected", func(t *testing.T) {
		ts := now + 2
		conn.WriteJSON(models.WSClientMessage{Type: "subscribe", ID: "ws-id", Timestamp: ts, Signature: wsSign("wrong", ts, "ws-id")})
		if m := readWS(t, conn); m["type"] != "error" || m["code"] != float64(http.StatusUnauthorized) {
			t.Fatalf("expected 401 error, got %v", m)
		}
	})

	t.Run("SubscribeReceivesInitialAndUpdates", func(t *testing.T) {
		ts := now + 3
		conn.WriteJSON(models.WSClientMessage{Type: "subscribe", ID: "ws-id", Timestamp: ts, Signature: wsSign("s", ts, "ws-id")})
		if m := readWS(t, conn); m["type"] != "update" || m["data"] != "v1" {
			t.Fatalf("expected initial update, got %v", m)
		}
		if rr := e.post(t, "ws-id", "s", models.SyncRequest{Data: "v2"}, now+4, ""); rr.Code != http.StatusCreated {
			t.Fatalf("upload: %d %s", rr.Code, rr.Body)
		}
		if m := readWS(t, conn); m["type"] != "update" || m["data"] != "v2" {
			t.Fatalf("expected v2 update, got %v", m)
		}
	})

	t.Run("ReplayedSubscribeRejected", func(t *testing.T) {
		conn2 := dialWS(t, srv, "https://app.example")
		ts := now + 3 // already consumed above
		conn2.WriteJSON(models.WSClientMessage{Type: "subscribe", ID: "ws-id", Timestamp: ts, Signature: wsSign("s", ts, "ws-id")})
		if m := readWS(t, conn2); m["type"] != "error" || m["code"] != float64(http.StatusUnauthorized) {
			t.Fatalf("expected 401 error, got %v", m)
		}
	})
}

func TestHubSlowClientDoesNotPanic(t *testing.T) {
	hub := NewHub()
	c := &Client{hub: hub, send: make(chan any, 1), done: make(chan struct{}), ip: "1.2.3.4", subs: map[string]struct{}{}}
	if !hub.reserveIP(c.ip) {
		t.Fatal("reserve failed")
	}
	hub.register(c)
	if err := hub.Subscribe(c, "id"); err != nil {
		t.Fatal(err)
	}

	hub.BroadcastUpdate("id", "a", 1) // fills buffer
	hub.BroadcastUpdate("id", "b", 2) // overflows: client is dropped

	select {
	case <-c.done:
	default:
		t.Fatal("slow client should have been unregistered")
	}

	// Everything the read loop might still do after being dropped must be safe.
	c.sendError("", "late", 500)
	if err := hub.Subscribe(c, "other"); err != nil {
		t.Fatal(err)
	}
	hub.BroadcastUpdate("other", "c", 3)
	hub.unregister(c)

	if n := hub.ipCounts[c.ip]; n != 0 {
		t.Fatalf("ip count leaked: %d", n)
	}
	if len(hub.subscriptions) != 0 {
		t.Fatalf("subscriptions leaked: %v", hub.subscriptions)
	}
}

func TestHubIPLimit(t *testing.T) {
	hub := NewHub()
	for i := 0; i < maxConnsPerIP; i++ {
		if !hub.reserveIP("ip") {
			t.Fatalf("reservation %d should succeed", i)
		}
	}
	if hub.reserveIP("ip") {
		t.Fatal("reservation beyond limit should fail")
	}
	hub.releaseIP("ip")
	if !hub.reserveIP("ip") {
		t.Fatal("reservation after release should succeed")
	}
}

func TestDevicesSharingAnIDDoNotCollide(t *testing.T) {
	e := newTestEnv(t)
	now := time.Now().Unix()
	if rr := e.post(t, "shared", "s", models.SyncRequest{Data: "v1", RegistrationSecret: "s"}, now, ""); rr.Code != http.StatusCreated {
		t.Fatalf("register: %d", rr.Code)
	}

	// Two devices in the same second: different requests with equal timestamps,
	// and one device whose clock (or counter) is behind the other.
	if rr := e.get(t, "/api/v1/sync/shared", "s", now+3, ""); rr.Code != http.StatusOK {
		t.Fatalf("device 1 read: %d %s", rr.Code, rr.Body)
	}
	if rr := e.get(t, "/api/v1/sync/shared/history", "s", now+3, ""); rr.Code != http.StatusOK {
		t.Fatalf("device 2 read, same second: %d %s", rr.Code, rr.Body)
	}
	if rr := e.post(t, "shared", "s", models.SyncRequest{Data: "from device 1"}, now+3, ""); rr.Code != http.StatusCreated {
		t.Fatalf("device 1 write: %d %s", rr.Code, rr.Body)
	}
	if rr := e.post(t, "shared", "s", models.SyncRequest{Data: "from device 2"}, now+1, ""); rr.Code != http.StatusCreated {
		t.Fatalf("device 2 write, older timestamp: %d %s", rr.Code, rr.Body)
	}

	// The last write wins regardless of request timestamps.
	rr := e.get(t, "/api/v1/sync/shared", "s", now+4, "")
	var latest models.SyncBlob
	json.Unmarshal(rr.Body.Bytes(), &latest)
	if latest.Data != "from device 2" || latest.Timestamp <= now+3 {
		t.Fatalf("latest = %+v, want device 2's write with a newer version", latest)
	}
}

func TestReplayWithUppercaseSignatureRejected(t *testing.T) {
	e := newTestEnv(t)
	now := time.Now().Unix()
	if rr := e.post(t, "case", "s", models.SyncRequest{Data: "v1", RegistrationSecret: "s"}, now, ""); rr.Code != http.StatusCreated {
		t.Fatalf("register: %d", rr.Code)
	}
	path := "/api/v1/sync/case"
	sig := signRequest(t, "s", now+1, http.MethodGet, path, nil)
	for i, s := range []string{sig, strings.ToUpper(sig)} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("X-Sync-Timestamp", fmt.Sprint(now+1))
		r.Header.Set("X-Sync-Signature", s)
		rr := httptest.NewRecorder()
		e.router.ServeHTTP(rr, r)
		want := []int{http.StatusOK, http.StatusUnauthorized}[i]
		if rr.Code != want {
			t.Fatalf("request %d: got %d, want %d", i, rr.Code, want)
		}
	}
}
