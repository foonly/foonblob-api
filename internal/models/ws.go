package models

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
	Type string `json:"type"`
	// ID is the sync ID the error relates to, if any, so clients can retry.
	ID      string `json:"id,omitempty"`
	Message string `json:"message"`
	Code    int    `json:"code,omitempty"`
}
