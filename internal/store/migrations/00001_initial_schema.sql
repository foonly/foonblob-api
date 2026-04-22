-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS sync_identities (
    id TEXT PRIMARY KEY,
    signing_secret TEXT NOT NULL,
    allowed_origin TEXT NOT NULL DEFAULT '',
    last_timestamp INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT 0,
    last_accessed_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sync_blobs (
    id TEXT NOT NULL,
    blob TEXT NOT NULL,
    timestamp INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sync_id_ts ON sync_blobs (id, timestamp DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_sync_id_ts;
DROP TABLE IF EXISTS sync_blobs;
DROP TABLE IF EXISTS sync_identities;
-- +goose StatementEnd
