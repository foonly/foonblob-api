-- +goose Up
-- +goose StatementBegin
-- Signatures of accepted requests, kept until the request timestamp falls out of
-- the allowed clock-skew window. Rejecting a repeated signature is what prevents
-- replays; request timestamps no longer have to increase per sync ID.
CREATE TABLE IF NOT EXISTS seen_signatures (
    id TEXT NOT NULL,
    signature TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (id, signature)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_seen_signatures_expires ON seen_signatures (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_seen_signatures_expires;
DROP TABLE IF EXISTS seen_signatures;
-- +goose StatementEnd
