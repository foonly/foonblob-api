# Foonblob API

A decentralized, privacy-focused backend for synchronizing data across devices. This service acts as a "dumb" storage vault, storing encrypted data for clients without ever seeing the decryption keys.

## Features

- **End-to-End Encryption Support**: Designed to store opaque, client-side encrypted blobs.
- **HMAC Authentication**: All requests (reads and writes) are authenticated using HMAC-SHA256 signatures for zero-knowledge authorization.
- **Secret Encryption at Rest**: Client signing secrets are encrypted in the database using AES-GCM.
- **Dynamic CORS**: Sync IDs are locked to the origin that registered them, preventing cross-origin data leakage.
- **History Management**: Automatically retains the last 10 versions (configurable) of your sync data for easy recovery.
- **Automated Cleanup**: Built-in logic to remove stale and abandoned data based on usage patterns.
- **Rate Limiting**: Protection against abuse with per-ID rate limiting and background memory pruning.
- **Lightweight & Portable**: Written in Go with a CGO-free SQLite implementation (`modernc.org/sqlite`).
- **Production Ready**: Structured logging, formal migrations (goose), and robust configuration management (Viper).

## API Specification

All sync endpoints require the following headers for authentication:

- `X-Sync-Timestamp`: Current Unix timestamp (must be within 5 minutes of server time and strictly increasing).
- `X-Sync-Signature`: HMAC-SHA256 signature of the request content (body for POST, URL path for GET).

### Sync Endpoints

- `GET /api/v1/sync/:id`: Retrieve the most recent encrypted blob for a specific Sync ID.
- `POST /api/v1/sync/:id`: Upload a new encrypted blob. (Max size: 1MB)
- `GET /api/v1/sync/:id/history`: List timestamps for all available historical versions.
- `GET /api/v1/sync/:id/:timestamp`: Retrieve a specific historical version by its timestamp.

### Management Endpoints

- `GET /api/v1/stats`: Retrieve usage statistics. Requires `Authorization: Bearer <stats_token>`.
- `GET /health`: Basic health check endpoint.

## Configuration

The API can be configured via `config.toml` or environment variables prefixed with `FOONBLOB_`.

| Variable                | Env Var                          | Default   | Description                          |
| ----------------------- | -------------------------------- | --------- | ------------------------------------ |
| `port`                  | `FOONBLOB_PORT`                  | `8080`    | HTTP port to listen on.              |
| `dsn`                   | `FOONBLOB_DSN`                   | `sync.db` | SQLite database file path.           |
| `history_limit`         | `FOONBLOB_HISTORY_LIMIT`         | `10`      | Versions to retain per ID.           |
| `stats_token`           | `FOONBLOB_STATS_TOKEN`           | `""`      | Bearer token for the stats endpoint. |
| `secret_encryption_key` | `FOONBLOB_SECRET_ENCRYPTION_KEY` | `""`      | Key used to encrypt secrets at rest. |

## Cleanup Policy

To keep the database lean, the API implements a background cleanup worker that runs every 24 hours. Identities and their associated blobs are deleted based on the following rules:

1.  **Short-term Usage**: If an identity was used for less than 48 hours and has been inactive for more than **14 days**, it is deleted.
2.  **Long-term Usage**: If an identity was used for 48 hours or more and has been inactive for more than **90 days**, it is deleted.

## Getting Started

### Prerequisites

- Go 1.24 or higher
- Make

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/foonly/foonblob-api.git
   cd foonblob-api
   ```

2. Build the binary:
   ```bash
   make build
   ```

### Running the Server

1. Create a `config.toml` (optional, uses defaults otherwise):

   ```toml
   port = 8080
   dsn = "sync.db"
   history_limit = 10
   stats_token = "your-secure-token"
   secret_encryption_key = "32-character-secure-key-here"
   ```

2. Start the API:
   ```bash
   make run
   ```

### Development

- `make test`: Run the full test suite (uses in-memory SQLite).
- `make fmt`: Format source code.
- `make tidy`: Update Go dependencies.

## Architecture

- **`cmd/api`**: Server entry point and lifecycle management.
- **`internal/api`**: HTTP routing, HMAC verification, and rate limiting.
- **`internal/store`**: SQLite persistence with automated `goose` migrations.
- **`internal/crypto`**: AES-GCM implementation for encryption at rest.
- **`internal/config`**: Viper-based configuration management.

## Security

Foonblob API implements a multi-layered security model:

1. **Zero-Knowledge Data**: All blobs are encrypted client-side. The server never sees the plaintext data.
2. **Path/Payload Signing**: Every request is signed with a secret known only to the client and the server.
3. **Origin Locking**: Dynamic CORS ensures that a Sync ID cannot be accessed from an unauthorized domain.
4. **Encryption at Rest**: Even if the server's database is compromised, the client secrets are protected by an additional layer of AES-GCM encryption.

## License

[GPL-3.0-only](https://opensource.org/licenses/GPL-3.0-only)
