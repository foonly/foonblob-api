package api

import (
	"log/slog"
	"sync"

	"github.com/foonly/foonblob-api/internal/models"
)

// Hub maintains the set of active clients and handles broadcasting messages.
type Hub struct {
	// Registered clients.
	clients map[*Client]bool

	// Subscriptions: syncID -> set of clients
	subscriptions map[string]map[*Client]bool

	// IP tracking: IP -> count of connections
	ipCounts map[string]int

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client

	mu sync.RWMutex
}

func NewHub() *Hub {
	return &Hub{
		clients:       make(map[*Client]bool),
		subscriptions: make(map[string]map[*Client]bool),
		ipCounts:      make(map[string]int),
		register:      make(chan *Client),
		unregister:    make(chan *Client),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.ipCounts[client.ip]++
			h.mu.Unlock()
			slog.Debug("client registered", "ip", client.ip, "total_clients", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				h.ipCounts[client.ip]--
				if h.ipCounts[client.ip] <= 0 {
					delete(h.ipCounts, client.ip)
				}

				// Clean up all subscriptions for this client
				client.mu.Lock()
				for id := range client.subs {
					if clients, ok := h.subscriptions[id]; ok {
						delete(clients, client)
						if len(clients) == 0 {
							delete(h.subscriptions, id)
						}
					}
				}
				client.mu.Unlock()

				close(client.send)
				slog.Debug("client unregistered", "ip", client.ip, "total_clients", len(h.clients))
			}
			h.mu.Unlock()
		}
	}
}

// Subscribe adds a client to the subscription list for a given sync ID.
func (h *Hub) Subscribe(client *Client, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.subscriptions[id] == nil {
		h.subscriptions[id] = make(map[*Client]bool)
	}
	h.subscriptions[id][client] = true

	client.mu.Lock()
	client.subs[id] = true
	client.mu.Unlock()
	slog.Debug("client subscribed", "id", id, "ip", client.ip)
}

// Unsubscribe removes a client from the subscription list for a given sync ID.
func (h *Hub) Unsubscribe(client *Client, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if clients, ok := h.subscriptions[id]; ok {
		delete(clients, client)
		if len(clients) == 0 {
			delete(h.subscriptions, id)
		}
	}

	client.mu.Lock()
	delete(client.subs, id)
	client.mu.Unlock()
	slog.Debug("client unsubscribed", "id", id, "ip", client.ip)
}

// BroadcastUpdate sends an update message to all clients subscribed to a given sync ID.
func (h *Hub) BroadcastUpdate(id string, data string, ts int64) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if clients, ok := h.subscriptions[id]; ok {
		msg := models.WSUpdateMessage{
			Type:      "update",
			ID:        id,
			Data:      data,
			Timestamp: ts,
		}
		for client := range clients {
			select {
			case client.send <- msg:
			default:
				// If the client's send buffer is full, unregister them.
				// This happens in a separate goroutine to avoid deadlocking the hub.
				go func(c *Client) {
					h.unregister <- c
				}(client)
			}
		}
	}
}

// GetIPCount returns the number of active connections from a given IP.
func (h *Hub) GetIPCount(ip string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ipCounts[ip]
}
