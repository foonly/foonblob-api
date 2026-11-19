package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"time"

	"github.com/foonly/foonblob-api/internal/crypto"
	"github.com/foonly/foonblob-api/internal/models"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

// encPrefix marks a signing secret that is stored encrypted at rest.
const encPrefix = "enc:"

type sqliteStore struct {
	db           *sql.DB
	historyLimit int
	encrypter    *crypto.Encrypter
}

// withPragmas appends per-connection pragmas to the DSN so that they are applied to
// every connection the pool opens, not just the first one.
func withPragmas(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
}

// NewSQLiteStore initializes a new SQLite database and runs migrations using goose.
func NewSQLiteStore(dsn string, historyLimit int, encryptionKey string) (_ Store, err error) {
	if historyLimit < 1 {
		return nil, fmt.Errorf("history limit must be at least 1, got %d", historyLimit)
	}

	db, err := sql.Open("sqlite", withPragmas(dsn))
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}
	defer func() {
		if err != nil {
			db.Close()
		}
	}()

	// SQLite allows a single writer; serialising through one connection avoids
	// SQLITE_BUSY errors and keeps an in-memory database alive for its lifetime.
	db.SetMaxOpenConns(1)
	db.SetConnMaxIdleTime(0)
	db.SetConnMaxLifetime(0)

	migrations, err := fs.Sub(embedMigrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to load migrations: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations,
		goose.WithSlog(slog.Default().With("component", "migrations")),
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create migration provider: %w", err)
	}
	if _, err := provider.Up(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	var enc *crypto.Encrypter
	if encryptionKey != "" {
		enc, err = crypto.NewEncrypter([]byte(encryptionKey))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize encrypter: %w", err)
		}
	} else {
		// Refuse to start if secrets were encrypted with a key that is no longer
		// configured. Otherwise every affected client would silently get 401s.
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM sync_identities WHERE signing_secret LIKE 'enc:%'").Scan(&n); err != nil {
			return nil, fmt.Errorf("failed to check for encrypted secrets: %w", err)
		}
		if n > 0 {
			return nil, fmt.Errorf("%d signing secrets are encrypted but secret_encryption_key is not set", n)
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
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get identity: %w", err)
	}

	if strings.HasPrefix(identity.SigningSecret, encPrefix) {
		if s.encrypter == nil {
			return nil, errors.New("signing secret is encrypted but no encryption key is configured")
		}
		decrypted, err := s.encrypter.Decrypt(identity.SigningSecret[len(encPrefix):])
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt signing secret (key mismatch or data corruption): %w", err)
		}
		identity.SigningSecret = decrypted
	}

	return &identity, nil
}

func (s *sqliteStore) Register(ctx context.Context, id, secret, origin, data string, ts int64) error {
	if s.encrypter != nil {
		encrypted, err := s.encrypter.Encrypt(secret)
		if err != nil {
			return fmt.Errorf("failed to encrypt signing secret: %w", err)
		}
		secret = encPrefix + encrypted
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO sync_identities (id, signing_secret, allowed_origin, last_timestamp, created_at, last_accessed_at)
		 VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`,
		id, secret, origin, ts, now, now)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAlreadyExists
	}

	if _, err := tx.ExecContext(ctx, "INSERT INTO sync_blobs (id, blob, timestamp) VALUES (?, ?, ?)", id, data, ts); err != nil {
		return fmt.Errorf("failed to insert blob: %w", err)
	}

	return tx.Commit()
}

// advance atomically moves an identity's replay timestamp forward. It is the single
// point where replay protection is enforced, so concurrent requests carrying the same
// timestamp cannot both succeed.
func advance(ctx context.Context, ex interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, id string, ts int64) error {
	res, err := ex.ExecContext(ctx,
		"UPDATE sync_identities SET last_timestamp = ?, last_accessed_at = ? WHERE id = ? AND last_timestamp < ?",
		ts, time.Now().Unix(), id, ts)
	if err != nil {
		return fmt.Errorf("failed to update identity timestamp: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrStaleTimestamp
	}
	return nil
}

func (s *sqliteStore) Touch(ctx context.Context, id string, ts int64) error {
	return advance(ctx, s.db, id, ts)
}

func (s *sqliteStore) SaveBlob(ctx context.Context, id string, data string, ts int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := advance(ctx, tx, id, ts); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, "INSERT INTO sync_blobs (id, blob, timestamp) VALUES (?, ?, ?)", id, data, ts); err != nil {
		return fmt.Errorf("failed to insert blob: %w", err)
	}

	// Prune old versions: keep only the latest N versions.
	pruneQuery := `
	DELETE FROM sync_blobs
	WHERE id = ? AND timestamp NOT IN (
		SELECT timestamp FROM sync_blobs
		WHERE id = ?
		ORDER BY timestamp DESC
		LIMIT ?
	)`
	if _, err := tx.ExecContext(ctx, pruneQuery, id, id, s.historyLimit); err != nil {
		return fmt.Errorf("failed to prune history: %w", err)
	}

	return tx.Commit()
}

func (s *sqliteStore) GetLatestBlob(ctx context.Context, id string) (*models.SyncBlob, error) {
	var blob models.SyncBlob
	query := "SELECT id, blob, timestamp FROM sync_blobs WHERE id = ? ORDER BY timestamp DESC LIMIT 1"
	err := s.db.QueryRowContext(ctx, query, id).Scan(&blob.ID, &blob.Data, &blob.Timestamp)
	if errors.Is(err, sql.ErrNoRows) {
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
	if err := rows.Err(); err != nil {
		return nil, err
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
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &blob, nil
}

func (s *sqliteStore) GetStats(ctx context.Context) (*models.Stats, error) {
	stats := &models.Stats{}
	now := time.Now().Unix()
	day := int64(24 * 60 * 60)

	queries := []struct {
		dest  *int64
		query string
		args  []any
	}{
		{&stats.Totals.Identities, "SELECT COUNT(*) FROM sync_identities", nil},
		{&stats.Totals.Blobs, "SELECT COUNT(*) FROM sync_blobs", nil},
		{&stats.Totals.TotalSizeBytes, "SELECT COALESCE(SUM(LENGTH(blob)), 0) FROM sync_blobs", nil},
		{&stats.Activity.IdentitiesCreated24h, "SELECT COUNT(*) FROM sync_identities WHERE created_at > ?", []any{now - day}},
		{&stats.Activity.BlobsCreated24h.Current, "SELECT COUNT(*) FROM sync_blobs WHERE timestamp > ?", []any{now - day}},
		{&stats.Activity.BlobsCreated24h.Previous, "SELECT COUNT(*) FROM sync_blobs WHERE timestamp > ? AND timestamp <= ?", []any{now - 2*day, now - day}},
	}
	for _, q := range queries {
		if err := s.db.QueryRowContext(ctx, q.query, q.args...).Scan(q.dest); err != nil {
			return nil, err
		}
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
	if _, err := tx.ExecContext(ctx, "DELETE FROM sync_blobs WHERE id NOT IN (SELECT id FROM sync_identities)"); err != nil {
		return 0, err
	}

	return deletedCount, tx.Commit()
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}
