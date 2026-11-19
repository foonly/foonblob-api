package api

import (
	"errors"
	"log/slog"
	"sync"

	"github.com/foonly/foonblob-api/internal/models"
)

const (
	// maxConnsPerIP bounds concurrent WebSocket connections from a single IP.
	maxConnsPerIP = 32
	// maxSubsPerConn bounds active subscriptions on a single connection.
	maxSubsPerConn = 32
)

var errSubscriptionLimit = errors.New("subscription limit exceeded (max 32)")

// Hub maintains the set of active clients and their subscriptions.
//
// All state, including each client's subscription set, is guarded by mu. A client's
// send channel is never closed; instead its done channel is closed exactly once on
// unregister, so senders can never panic on a closed channel.
type Hub struct {
	mu            sync.Mutex
	clients       map[*Client]struct{}
	subscriptions map[string]map[*Client]struct{}
	ipCounts      map[string]int
}

func NewHub() *Hub {
	return &Hub{
		clients:       make(map[*Client]struct{}),
		subscriptions: make(map[string]map[*Client]struct{}),
		ipCounts:      make(map[string]int),
	}
}

// reserveIP atomically checks the per-IP connection limit and reserves a slot.
func (h *Hub) reserveIP(ip string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ipCounts[ip] >= maxConnsPerIP {
		return false
	}
	h.ipCounts[ip]++
	return true
}

// releaseIP releases a slot reserved by reserveIP.
func (h *Hub) releaseIP(ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.releaseIPLocked(ip)
}

func (h *Hub) releaseIPLocked(ip string) {
	h.ipCounts[ip]--
	if h.ipCounts[ip] <= 0 {
		delete(h.ipCounts, ip)
	}
}

// register adds a client whose IP slot has already been reserved.
func (h *Hub) register(c *Client) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	n := len(h.clients)
	h.mu.Unlock()
	slog.Debug("client registered", "ip", c.ip, "total_clients", n)
}

// unregister removes a client and all its subscriptions. It is idempotent.
func (h *Hub) unregister(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.unregisterLocked(c)
}

func (h *Hub) unregisterLocked(c *Client) {
	if _, ok := h.clients[c]; !ok {
		return
	}
	delete(h.clients, c)
	h.releaseIPLocked(c.ip)
	for id := range c.subs {
		h.removeSubLocked(c, id)
	}
	close(c.done)
	slog.Debug("client unregistered", "ip", c.ip, "total_clients", len(h.clients))
}

func (h *Hub) removeSubLocked(c *Client, id string) {
	if clients, ok := h.subscriptions[id]; ok {
		delete(clients, c)
		if len(clients) == 0 {
			delete(h.subscriptions, id)
		}
	}
	delete(c.subs, id)
}

// subscribed reports whether the client is subscribed to id, and how many
// subscriptions it holds in total.
func (h *Hub) subscribed(c *Client, id string) (bool, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := c.subs[id]
	return ok, len(c.subs)
}

// Subscribe adds a client to the subscription list for a given sync ID. It is a
// no-op for clients that have already been unregistered.
func (h *Hub) Subscribe(c *Client, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.clients[c]; !ok {
		return nil
	}
	if _, ok := c.subs[id]; ok {
		return nil
	}
	if len(c.subs) >= maxSubsPerConn {
		return errSubscriptionLimit
	}
	if h.subscriptions[id] == nil {
		h.subscriptions[id] = make(map[*Client]struct{})
	}
	h.subscriptions[id][c] = struct{}{}
	c.subs[id] = struct{}{}
	slog.Debug("client subscribed", "id", id, "ip", c.ip)
	return nil
}

// Unsubscribe removes a client from the subscription list for a given sync ID.
func (h *Hub) Unsubscribe(c *Client, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.removeSubLocked(c, id)
	slog.Debug("client unsubscribed", "id", id, "ip", c.ip)
}

// BroadcastUpdate sends an update message to all clients subscribed to a given
// sync ID. Clients whose send buffer is full are disconnected.
func (h *Hub) BroadcastUpdate(id string, data string, ts int64) {
	msg := models.WSUpdateMessage{Type: "update", ID: id, Data: data, Timestamp: ts}

	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.subscriptions[id] {
		if !c.trySend(msg) {
			slog.Warn("WS: dropping slow client", "ip", c.ip)
			h.unregisterLocked(c)
		}
	}
}

// Close disconnects all clients. Used on server shutdown.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		h.unregisterLocked(c)
	}
}
