package models

// SyncIdentity represents the registration and authentication info for a sync ID.
type SyncIdentity struct {
	ID             string `json:"id"`
	SigningSecret  string `json:"signing_secret"`
	AllowedOrigin  string `json:"allowed_origin"`
	LastTimestamp  int64  `json:"last_timestamp"`
	CreatedAt      int64  `json:"created_at"`
	LastAccessedAt int64  `json:"last_accessed_at"`
}

// SyncBlob represents the encrypted data stored for a specific sync ID.
type SyncBlob struct {
	ID        string `json:"id,omitempty"`
	Data      string `json:"data"`
	Timestamp int64  `json:"timestamp"`
}

// SyncHistoryEntry represents a summary of a historical version.
type SyncHistoryEntry struct {
	Timestamp int64 `json:"timestamp"`
}

// SyncRequest represents the payload for uploading a new blob.
type SyncRequest struct {
	Data               string `json:"data"`
	RegistrationSecret string `json:"registration_secret,omitempty"`
	AllowedOrigin      string `json:"allowed_origin,omitempty"`
}

// Stats represents the usage statistics for the service.
type Stats struct {
	Totals struct {
		Identities     int64 `json:"identities"`
		Blobs          int64 `json:"blobs"`
		TotalSizeBytes int64 `json:"total_size_bytes"`
	} `json:"totals"`
	Activity struct {
		IdentitiesCreated24h int64 `json:"identities_created_24h"`
		BlobsCreated24h      struct {
			Current  int64 `json:"current"`
			Previous int64 `json:"previous"`
		} `json:"blobs_created_24h"`
	} `json:"activity"`
}
