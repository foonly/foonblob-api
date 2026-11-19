package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/foonly/foonblob-api/internal/models"
	"github.com/foonly/foonblob-api/internal/store"
	"github.com/gorilla/websocket"
)

const (
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = (pongWait * 9) / 10

	// maxMessageSize bounds inbound client messages. Clients only send small
	// subscribe/unsubscribe control messages.
	maxMessageSize = 4096

	// sendBuffer is the number of outbound messages queued per client before it is
	// considered too slow and disconnected.
	sendBuffer = 64

	// storeTimeout bounds database calls made on behalf of WebSocket messages.
	storeTimeout = 5 * time.Second
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Connections are accepted from any origin. The origin is recorded on the client
	// and enforced per subscription against the identity's registered allowed origin.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub     *Hub
	handler *Handler
	conn    *websocket.Conn

	// Buffered channel of outbound messages. Never closed.
	send chan any
	// Closed by the hub when the client is unregistered.
	done chan struct{}

	ip     string
	origin string

	// Active subscriptions. Guarded by hub.mu.
	subs map[string]struct{}
}

func newClient(h *Handler, conn *websocket.Conn, ip, origin string) *Client {
	return &Client{
		hub:     h.hub,
		handler: h,
		conn:    conn,
		send:    make(chan any, sendBuffer),
		done:    make(chan struct{}),
		ip:      ip,
		origin:  origin,
		subs:    make(map[string]struct{}),
	}
}

// trySend queues a message without blocking. It returns false if the client is
// gone or its buffer is full.
func (c *Client) trySend(msg any) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.send <- msg:
		return true
	default:
		return false
	}
}

// readPump pumps messages from the websocket connection to the hub.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister(c)
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
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				slog.Warn("websocket read error", "error", err)
			}
			return
		}

		var msg models.WSClientMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			c.sendError("", "invalid message format", http.StatusBadRequest)
			continue
		}

		switch msg.Type {
		case "subscribe":
			c.handleSubscribe(msg)
		case "unsubscribe":
			c.handleUnsubscribe(msg)
		default:
			c.sendError("", "unknown message type: "+msg.Type, http.StatusBadRequest)
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
		case message := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteJSON(message); err != nil {
				return
			}

		case <-c.done:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			return

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// sendError reports an error to the client. id names the sync ID it relates to
// (empty if none), so clients can tell which subscription to retry.
func (c *Client) sendError(id, message string, code int) {
	c.trySend(models.WSErrorMessage{Type: "error", ID: id, Message: message, Code: code})
}

func (c *Client) handleSubscribe(msg models.WSClientMessage) {
	if msg.ID == "" {
		c.sendError(msg.ID, "missing sync id", http.StatusBadRequest)
		return
	}

	if already, n := c.hub.subscribed(c, msg.ID); already {
		return
	} else if n >= maxSubsPerConn {
		c.sendError(msg.ID, errSubscriptionLimit.Error(), http.StatusTooManyRequests)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	st := c.handler.store

	identity, err := st.GetIdentity(ctx, msg.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.sendError(msg.ID, "sync id not found", http.StatusNotFound)
			return
		}
		slog.Error("WS handleSubscribe: failed to get identity", "id", msg.ID, "error", err)
		c.sendError(msg.ID, "internal server error", http.StatusInternalServerError)
		return
	}

	if !originAllowed(c.origin, identity.AllowedOrigin) {
		c.sendError(msg.ID, "origin not allowed", http.StatusForbidden)
		return
	}

	// Signed content: timestamp + "subscribe" + id
	sig, err := authenticate(identity.SigningSecret, msg.Timestamp, "subscribe"+msg.ID, msg.Signature)
	if err != nil {
		c.sendError(msg.ID, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := st.Consume(ctx, msg.ID, sig); err != nil {
		if errors.Is(err, store.ErrReplay) {
			c.sendError(msg.ID, err.Error(), http.StatusUnauthorized)
			return
		}
		slog.Error("WS handleSubscribe: failed to update identity timestamp", "id", msg.ID, "error", err)
		c.sendError(msg.ID, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := c.hub.Subscribe(c, msg.ID); err != nil {
		c.sendError(msg.ID, err.Error(), http.StatusTooManyRequests)
		return
	}

	// Send initial state immediately.
	blob, err := st.GetLatestBlob(ctx, msg.ID)
	if err == nil {
		c.trySend(models.WSUpdateMessage{Type: "update", ID: msg.ID, Data: blob.Data, Timestamp: blob.Timestamp})
	}
}

func (c *Client) handleUnsubscribe(msg models.WSClientMessage) {
	if msg.ID == "" {
		c.sendError(msg.ID, "missing sync id", http.StatusBadRequest)
		return
	}
	c.hub.Unsubscribe(c, msg.ID)
}
