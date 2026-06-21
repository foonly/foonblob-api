package models

// WSMessage represents the base structure for all WebSocket messages.
type WSMessage struct {
	Type string `json:"type"`
}

// WSClientMessage is the message sent by the client.
type WSClientMessage struct {
	Type      string `json:"type"`
	ID        string `json:"id,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// WSUpdateMessage is sent by the server when a blob is updated.
type WSUpdateMessage struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Data      string `json:"data"`
	Timestamp int64  `json:"timestamp"`
}

// WSErrorMessage is sent by the server when an error occurs.
type WSErrorMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    int    `json:"code,omitempty"`
}
