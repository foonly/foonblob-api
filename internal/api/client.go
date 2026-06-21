package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/foonly/foonblob-api/internal/models"
	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 1024 * 1024 // 1MB
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Origin validation is handled in the Upgrade handler
		return true
	},
}

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub

	// The handler for accessing store and shared logic
	handler *Handler

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan interface{}

	// IP address of the client
	ip string

	// Set of active subscriptions (syncID -> true)
	subs map[string]bool

	mu sync.Mutex
}

// readPump pumps messages from the websocket connection to the hub.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Error("websocket read error", "error", err)
			}
			break
		}

		var msg models.WSClientMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			c.sendError("invalid message format", http.StatusBadRequest)
			continue
		}

		switch msg.Type {
		case "subscribe":
			c.handleSubscribe(msg)
		case "unsubscribe":
			c.handleUnsubscribe(msg)
		default:
			c.sendError("unknown message type: "+msg.Type, http.StatusBadRequest)
		}
	}
}

// writePump pumps messages from the hub to the websocket connection.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteJSON(message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Client) sendError(message string, code int) {
	select {
	case c.send <- models.WSErrorMessage{
		Type:    "error",
		Message: message,
		Code:    code,
	}:
	default:
		// Channel is full or closed, ignore
	}
}

func (c *Client) handleSubscribe(msg models.WSClientMessage) {
	if msg.ID == "" {
		c.sendError("missing sync id", http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	if len(c.subs) >= 32 {
		c.mu.Unlock()
		c.sendError("subscription limit exceeded (max 32)", http.StatusTooManyRequests)
		return
	}
	if c.subs[msg.ID] {
		c.mu.Unlock()
		// Already subscribed, ignore or notify? Let's just ignore.
		return
	}
	c.mu.Unlock()

	// 1. Get Identity
	identity, err := c.handler.store.GetIdentity(context.Background(), msg.ID)
	if err != nil {
		c.sendError("sync id not found", http.StatusNotFound)
		return
	}

	// 2. Verify Signature
	// For WS subscriptions, we sign: timestamp + "subscribe" + id
	contentToSign := fmt.Sprintf("%d%s%s", msg.Timestamp, "subscribe", msg.ID)

	// Check Timestamp Window (5 minutes)
	now := time.Now().Unix()
	if math.Abs(float64(now-msg.Timestamp)) > 300 {
		c.sendError("timestamp expired or invalid", http.StatusUnauthorized)
		return
	}

	// Replay Protection
	if msg.Timestamp <= identity.LastTimestamp {
		c.sendError("timestamp must be newer than previous request", http.StatusUnauthorized)
		return
	}

	sigBytes, err := hex.DecodeString(msg.Signature)
	if err != nil {
		c.sendError("invalid signature encoding", http.StatusUnauthorized)
		return
	}

	mac := hmac.New(sha256.New, []byte(identity.SigningSecret))
	mac.Write([]byte(contentToSign))

	if !hmac.Equal(sigBytes, mac.Sum(nil)) {
		c.sendError("invalid signature", http.StatusUnauthorized)
		return
	}

	// 3. Update identity timestamp for replay protection
	if err := c.handler.store.UpdateIdentityTimestamp(context.Background(), msg.ID, msg.Timestamp); err != nil {
		slog.Error("WS handleSubscribe: failed to update identity timestamp", "id", msg.ID, "error", err)
		c.sendError("internal server error", http.StatusInternalServerError)
		return
	}

	// 4. Subscribe in Hub
	c.hub.Subscribe(c, msg.ID)

	// 5. Send initial state immediately
	blob, err := c.handler.store.GetLatestBlob(context.Background(), msg.ID)
	if err == nil {
		c.send <- models.WSUpdateMessage{
			Type:      "update",
			ID:        msg.ID,
			Data:      blob.Data,
			Timestamp: blob.Timestamp,
		}
	}
}

func (c *Client) handleUnsubscribe(msg models.WSClientMessage) {
	if msg.ID == "" {
		c.sendError("missing sync id", http.StatusBadRequest)
		return
	}
	c.hub.Unsubscribe(c, msg.ID)
}
