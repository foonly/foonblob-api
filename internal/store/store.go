package store

import (
	"context"
	"errors"

	"github.com/foonly/foonblob-api/internal/models"
)

var (
	// ErrNotFound is returned when the requested sync ID or version does not exist.
	ErrNotFound = errors.New("sync data not found")

	// ErrReplay is returned when a request signature has already been accepted for
	// an identity, i.e. the request is a replay.
	ErrReplay = errors.New("request has already been processed")

	// ErrAlreadyExists is returned when registering an identity that already exists.
	ErrAlreadyExists = errors.New("sync id already exists")
)

// Signature identifies an authenticated request for replay protection. Value must
// be canonical (lowercase hex). It is remembered until ExpiresAt (Unix seconds),
// after which the request's timestamp is rejected anyway.
type Signature struct {
	Value     string
	ExpiresAt int64
}

// Store defines the interface for persisting encrypted foonblobs and their history.
type Store interface {
	// GetIdentity retrieves identity information for a sync ID.
	GetIdentity(ctx context.Context, id string) (*models.SyncIdentity, error)

	// Register atomically creates a new identity and stores its first blob.
	// Returns ErrAlreadyExists if the ID is already registered.
	Register(ctx context.Context, id, secret, origin, data string, ts int64) error

	// SaveBlob consumes the request signature, stores a new blob for an existing
	// identity and prunes old versions, all in one transaction. The blob's version
	// timestamp is ts, or one more than the previous version if ts is not newer, so
	// versions always increase in the order they were written. Returns the version
	// timestamp, or ErrReplay if the signature was already used.
	SaveBlob(ctx context.Context, id string, data string, ts int64, sig Signature) (int64, error)

	// Consume records a request signature for an identity and updates its
	// last-accessed time. Returns ErrReplay if the signature was already used.
	Consume(ctx context.Context, id string, sig Signature) error

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
