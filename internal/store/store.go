package store

import (
	"context"
	"errors"

	"github.com/foonly/foonblob-api/internal/models"
)

// ErrNotFound is returned when the requested sync ID or version does not exist.
var ErrNotFound = errors.New("sync data not found")

// Store defines the interface for persisting encrypted foonblobs and their history.
type Store interface {
	// GetIdentity retrieves identity information for a sync ID.
	GetIdentity(ctx context.Context, id string) (*models.SyncIdentity, error)

	// CreateIdentity stores a new identity with a signing secret.
	CreateIdentity(ctx context.Context, id string, secret string) error

	// UpdateLastAccessed updates the last accessed timestamp for an identity.
	UpdateLastAccessed(ctx context.Context, id string) error

	// SaveBlob stores a new encrypted blob for the given ID and handles pruning of old versions.
	SaveBlob(ctx context.Context, id string, data string, ts int64) error

	// GetLatestBlob retrieves the most recent blob for the given ID.
	GetLatestBlob(ctx context.Context, id string) (*models.SyncBlob, error)

	// GetHistory retrieves a list of timestamps for available historical versions.
	GetHistory(ctx context.Context, id string) ([]models.SyncHistoryEntry, error)

	// GetBlobAtTimestamp retrieves a specific historical blob by its timestamp.
	GetBlobAtTimestamp(ctx context.Context, id string, ts int64) (*models.SyncBlob, error)

	// GetStats retrieves usage statistics.
	GetStats(ctx context.Context) (*models.Stats, error)

	// CleanupOldIdentities removes identities and blobs based on the defined cleanup rules.
	CleanupOldIdentities(ctx context.Context) (int64, error)

	// Close closes the underlying storage connection.
	Close() error
}
