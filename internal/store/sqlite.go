package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"strings"
	"time"

	"github.com/foonly/foonblob-api/internal/crypto"
	"github.com/foonly/foonblob-api/internal/models"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

type sqliteStore struct {
	db           *sql.DB
	historyLimit int
	encrypter    *crypto.Encrypter
}

// NewSQLiteStore initializes a new SQLite database and runs migrations using goose.
func NewSQLiteStore(dsn string, historyLimit int, encryptionKey string) (Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}

	// Optimize SQLite for concurrency and reliability
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
		return nil, fmt.Errorf("failed to configure sqlite: %w", err)
	}

	// Run migrations
	goose.SetBaseFS(embedMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		return nil, fmt.Errorf("failed to set goose dialect: %w", err)
	}

	if err := goose.Up(db, "migrations"); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	var enc *crypto.Encrypter
	if encryptionKey != "" {
		var err error
		enc, err = crypto.NewEncrypter([]byte(encryptionKey))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize encrypter: %w", err)
		}
	}

	return &sqliteStore{
		db:           db,
		historyLimit: historyLimit,
		encrypter:    enc,
	}, nil
}

func (s *sqliteStore) GetIdentity(ctx context.Context, id string) (*models.SyncIdentity, error) {
	var identity models.SyncIdentity
	query := "SELECT id, signing_secret, allowed_origin, last_timestamp, created_at, last_accessed_at FROM sync_identities WHERE id = ?"
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&identity.ID,
		&identity.SigningSecret,
		&identity.AllowedOrigin,
		&identity.LastTimestamp,
		&identity.CreatedAt,
		&identity.LastAccessedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get identity: %w", err)
	}

	// Decrypt secret if encryption is enabled and it looks encrypted
	if s.encrypter != nil && strings.HasPrefix(identity.SigningSecret, "enc:") {
		decrypted, err := s.encrypter.Decrypt(identity.SigningSecret[4:])
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt signing secret (key mismatch or data corruption): %w", err)
		}
		identity.SigningSecret = decrypted
	}

	return &identity, nil
}

func (s *sqliteStore) CreateIdentity(ctx context.Context, id string, secret string, origin string) error {
	if s.encrypter != nil {
		encrypted, err := s.encrypter.Encrypt(secret)
		if err != nil {
			return fmt.Errorf("failed to encrypt signing secret: %w", err)
		}
		secret = "enc:" + encrypted
	}

	now := time.Now().Unix()
	query := "INSERT INTO sync_identities (id, signing_secret, allowed_origin, last_timestamp, created_at, last_accessed_at) VALUES (?, ?, ?, 0, ?, ?)"
	if _, err := s.db.ExecContext(ctx, query, id, secret, origin, now, now); err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}
	return nil
}

func (s *sqliteStore) SaveBlob(ctx context.Context, id string, data string, ts int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Insert new blob
	_, err = tx.ExecContext(ctx, "INSERT INTO sync_blobs (id, blob, timestamp) VALUES (?, ?, ?)", id, data, ts)
	if err != nil {
		return fmt.Errorf("failed to insert blob: %w", err)
	}

	// Update identity timestamp for replay protection
	_, err = tx.ExecContext(ctx, "UPDATE sync_identities SET last_timestamp = ? WHERE id = ?", ts, id)
	if err != nil {
		return fmt.Errorf("failed to update identity timestamp: %w", err)
	}

	// Prune old versions: Keep only the latest N versions
	pruneQuery := `
	DELETE FROM sync_blobs
	WHERE id = ? AND timestamp NOT IN (
		SELECT timestamp FROM sync_blobs
		WHERE id = ?
		ORDER BY timestamp DESC
		LIMIT ?
	)`
	_, err = tx.ExecContext(ctx, pruneQuery, id, id, s.historyLimit)
	if err != nil {
		return fmt.Errorf("failed to prune history: %w", err)
	}

	return tx.Commit()
}

func (s *sqliteStore) GetLatestBlob(ctx context.Context, id string) (*models.SyncBlob, error) {
	var blob models.SyncBlob
	query := "SELECT id, blob, timestamp FROM sync_blobs WHERE id = ? ORDER BY timestamp DESC LIMIT 1"
	err := s.db.QueryRowContext(ctx, query, id).Scan(&blob.ID, &blob.Data, &blob.Timestamp)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &blob, nil
}

func (s *sqliteStore) GetHistory(ctx context.Context, id string) ([]models.SyncHistoryEntry, error) {
	query := "SELECT timestamp FROM sync_blobs WHERE id = ? ORDER BY timestamp DESC"
	rows, err := s.db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []models.SyncHistoryEntry
	for rows.Next() {
		var entry models.SyncHistoryEntry
		if err := rows.Scan(&entry.Timestamp); err != nil {
			return nil, err
		}
		history = append(history, entry)
	}

	if len(history) == 0 {
		return nil, ErrNotFound
	}

	return history, nil
}

func (s *sqliteStore) GetBlobAtTimestamp(ctx context.Context, id string, ts int64) (*models.SyncBlob, error) {
	var blob models.SyncBlob
	query := "SELECT id, blob, timestamp FROM sync_blobs WHERE id = ? AND timestamp = ?"
	err := s.db.QueryRowContext(ctx, query, id, ts).Scan(&blob.ID, &blob.Data, &blob.Timestamp)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &blob, nil
}

func (s *sqliteStore) UpdateLastAccessed(ctx context.Context, id string) error {
	query := "UPDATE sync_identities SET last_accessed_at = strftime('%s', 'now') WHERE id = ?"
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}

func (s *sqliteStore) UpdateIdentityTimestamp(ctx context.Context, id string, ts int64) error {
	query := "UPDATE sync_identities SET last_timestamp = ? WHERE id = ?"
	_, err := s.db.ExecContext(ctx, query, ts, id)
	return err
}

func (s *sqliteStore) GetStats(ctx context.Context) (*models.Stats, error) {
	stats := &models.Stats{}

	// Totals
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sync_identities").Scan(&stats.Totals.Identities)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sync_blobs").Scan(&stats.Totals.Blobs)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(LENGTH(blob)), 0) FROM sync_blobs").Scan(&stats.Totals.TotalSizeBytes)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	day := int64(24 * 60 * 60)

	// Activity
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sync_identities WHERE created_at > ?", now-day).Scan(&stats.Activity.IdentitiesCreated24h)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sync_blobs WHERE timestamp > ?", now-day).Scan(&stats.Activity.BlobsCreated24h.Current)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sync_blobs WHERE timestamp BETWEEN ? AND ?", now-(2*day), now-day).Scan(&stats.Activity.BlobsCreated24h.Previous)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (s *sqliteStore) CleanupOldIdentities(ctx context.Context) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Rule 1: < 48h active, > 14 days idle
	// Rule 2: >= 48h active, > 90 days idle
	now := time.Now().Unix()
	query := `
	DELETE FROM sync_identities
	WHERE ((last_accessed_at - created_at) < 172800 AND last_accessed_at < ? - 1209600)
	   OR ((last_accessed_at - created_at) >= 172800 AND last_accessed_at < ? - 7776000)
	`
	res, err := tx.ExecContext(ctx, query, now, now)
	if err != nil {
		return 0, err
	}

	deletedCount, _ := res.RowsAffected()

	// Cleanup orphaned blobs
	_, err = tx.ExecContext(ctx, "DELETE FROM sync_blobs WHERE id NOT IN (SELECT id FROM sync_identities)")
	if err != nil {
		return 0, err
	}

	return deletedCount, tx.Commit()
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}
