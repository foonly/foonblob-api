package store

import (
	"context"
	"errors"

	"github.com/foonly/foonblob-api/internal/models"
)

var (
	// ErrNotFound is returned when the requested sync ID or version does not exist.
	ErrNotFound = errors.New("sync data not found")

	// ErrStaleTimestamp is returned when a request timestamp is not newer than the
	// last accepted timestamp for an identity (i.e. a replayed or out-of-order request).
	ErrStaleTimestamp = errors.New("timestamp must be newer than previous request")

	// ErrAlreadyExists is returned when registering an identity that already exists.
	ErrAlreadyExists = errors.New("sync id already exists")
)

// Store defines the interface for persisting encrypted foonblobs and their history.
type Store interface {
	// GetIdentity retrieves identity information for a sync ID.
	GetIdentity(ctx context.Context, id string) (*models.SyncIdentity, error)

	// Register atomically creates a new identity and stores its first blob.
	// Returns ErrAlreadyExists if the ID is already registered.
	Register(ctx context.Context, id, secret, origin, data string, ts int64) error

	// SaveBlob stores a new blob for an existing identity, advances its replay
	// timestamp and prunes old versions, all in one transaction.
	// Returns ErrStaleTimestamp if ts is not newer than the last accepted timestamp.
	SaveBlob(ctx context.Context, id string, data string, ts int64) error

	// Touch atomically advances the replay timestamp and last-accessed time for
	// an identity. Returns ErrStaleTimestamp if ts is not newer than the last
	// accepted timestamp, which makes replay protection race-free.
	Touch(ctx context.Context, id string, ts int64) error

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
