# Foonblob API

A decentralized, privacy-focused backend for synchronizing data across devices. This service acts as a "dumb" storage vault, storing encrypted data for clients without ever seeing the decryption keys.

## Features

- **End-to-End Encryption Support**: Designed to store opaque, client-side encrypted blobs.
- **HMAC Authentication**: All requests (reads and writes) are authenticated using HMAC-SHA256 signatures for zero-knowledge authorization.
- **Secret Encryption at Rest**: Client signing secrets are encrypted in the database using AES-GCM (requires configuration).
- **Dynamic CORS**: Sync IDs are locked to the origin that registered them, preventing cross-origin data leakage.
- **History Management**: Automatically retains the last 10 versions (configurable) of your sync data for easy recovery.
- **Automated Cleanup**: Built-in logic to remove stale and abandoned data based on usage patterns.
- **Real-time Updates**: WebSocket endpoint that pushes new blobs to subscribed clients.
- **Rate Limiting**: Protection against abuse with per-ID rate limiting and background memory pruning.
- **Lightweight & Portable**: Written in Go with a CGO-free SQLite implementation (`modernc.org/sqlite`).
- **Production Ready**: Structured logging, formal migrations (goose), and robust configuration management (Viper).

## API Specification

All sync endpoints require the following headers for authentication:

- `X-Sync-Timestamp`: Current Unix timestamp (must be within 5 minutes of server time). Each signed request is accepted only once.
- `X-Sync-Signature`: HMAC-SHA256 signature of the request content (body for POST, URL path for GET).

### Sync Endpoints

- `GET /api/v1/sync/:id`: Retrieve the most recent encrypted blob for a specific Sync ID.
- `POST /api/v1/sync/:id`: Upload a new encrypted blob. (Max size: 1MB)
- `GET /api/v1/sync/:id/history`: List timestamps for all available historical versions.
- `GET /api/v1/sync/:id/:timestamp`: Retrieve a specific historical version by its timestamp.
- `GET /api/v1/ws`: WebSocket for real-time update notifications.

See [API.md](API.md) for the full client specification.

### Management Endpoints

- `GET /api/v1/stats`: Retrieve usage statistics. Requires `Authorization: Bearer <stats_token>`.
- `GET /health`: Basic health check endpoint.

## Configuration

The API can be configured via `config.toml` or environment variables prefixed with `FOONBLOB_`.

| Variable                | Env Var                          | Default   | Description                                                            |
| ----------------------- | -------------------------------- | --------- | ---------------------------------------------------------------------- |
| `host`                  | `FOONBLOB_HOST`                  | `""`      | Bind address. Empty means all interfaces; use `127.0.0.1` behind a proxy. |
| `port`                  | `FOONBLOB_PORT`                  | `8080`    | HTTP port to listen on.                                                |
| `dsn`                   | `FOONBLOB_DSN`                   | `sync.db` | SQLite database file path.                                             |
| `history_limit`         | `FOONBLOB_HISTORY_LIMIT`         | `10`      | Versions to retain per ID (minimum 1).                                 |
| `stats_token`           | `FOONBLOB_STATS_TOKEN`           | `""`      | Bearer token for the stats endpoint. Empty disables the endpoint.      |
| `secret_encryption_key` | `FOONBLOB_SECRET_ENCRYPTION_KEY` | `""`      | Key for encryption at rest. If empty, secrets are stored in plaintext. |
| `trust_proxy_headers`   | `FOONBLOB_TRUST_PROXY_HEADERS`   | `true`    | Take client IP from `X-Forwarded-For` & co. Disable when not behind a reverse proxy. |

The config file is read from the path in `FOONBLOB_CONFIG` if set, otherwise `config.toml` is searched for in `.`, `./config` and `/etc/foonblob-api`. Environment variables override file values.

> **Encryption key:** once `secret_encryption_key` is set, never change or remove it. Secrets encrypted with it cannot be recovered without it, and the server refuses to start if encrypted secrets exist but no key is configured. Enabling the key later only encrypts secrets registered from then on.

## Cleanup Policy

To keep the database lean, the API implements a background cleanup worker that runs every hour. Identities and their associated blobs are deleted based on the following rules:

1.  **Short-term Usage**: If an identity was used for less than 48 hours and has been inactive for more than **14 days**, it is deleted.
2.  **Long-term Usage**: If an identity was used for 48 hours or more and has been inactive for more than **90 days**, it is deleted.

## Getting Started

### Prerequisites

- Go 1.25 or higher
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
   secret_encryption_key = "output of: openssl rand -base64 32"
   ```

2. Start the API:
   ```bash
   make run
   ```

### Development

- `make test`: Run the full test suite with the race detector (uses in-memory SQLite).
- `make check`: Run `go vet` and the tests.
- `make fmt`: Format source code.
- `make tidy`: Update Go dependencies.
- `make clean`: Remove build artifacts. `make clean-db` deletes the local `sync.db`.

### Deployment (systemd)

A sample service file is provided in `deploy/foonblob-api.service`. It runs the service under a systemd `DynamicUser` (no system user to create) with its data in `/var/lib/foonblob-api`.

1. **Install binary & service** (or download `foonblob-api` from a GitHub release and check it against `foonblob-api.sha256`):

   ```bash
   make build
   sudo install -m 0755 bin/foonblob-api /usr/local/bin/
   sudo install -m 0644 deploy/foonblob-api.service /etc/systemd/system/
   ```

2. **Configure secrets** in a root-only file (not via `Environment=` lines, which any local user can read with `systemctl show`):

   ```bash
   sudo install -d -m 0755 /etc/foonblob-api
   sudo install -m 0600 /dev/null /etc/foonblob-api/secrets.env
   sudoedit /etc/foonblob-api/secrets.env
   # FOONBLOB_STATS_TOKEN=...
   # FOONBLOB_SECRET_ENCRYPTION_KEY=...
   ```

   Non-secret settings can go in `/etc/foonblob-api/config.toml` or a drop-in (`systemctl edit foonblob-api`). If the service sits behind a reverse proxy on the same host, set `FOONBLOB_HOST=127.0.0.1`; if it is exposed directly, set `FOONBLOB_TRUST_PROXY_HEADERS=false`. Behind nginx, clear the header a client could spoof: `proxy_set_header True-Client-IP "";` alongside `proxy_set_header X-Real-IP $remote_addr;`.

3. **Start**:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now foonblob-api
   journalctl -u foonblob-api -f
   ```

Migrations run automatically on startup. Back up the database before upgrading (e.g. `sqlite3 /var/lib/foonblob-api/foonblob.db ".backup /var/backups/foonblob.db"`).

### Continuous deployment

Pushing a `v*` tag builds a release and, if the repository has a `production` environment configured, deploys it:

- On the server, releases live in `/opt/foonblob-api/releases/<version>`, `/opt/foonblob-api/current` points at the active one and `/usr/local/bin/foonblob-api` links to `current/foonblob-api`.
- `deploy/foonblob-deploy` is installed as `/usr/local/sbin/foonblob-deploy` and bound to the CI key as a forced command (`command="/usr/local/sbin/foonblob-deploy",restrict ssh-ed25519 ...`) for a deploy user that owns `/opt/foonblob-api` and may run `sudo systemctl restart foonblob-api.service`. It verifies the checksum and version, switches `current`, restarts, checks `/health` and rolls back on failure. Set `HEALTH_URL` in `/etc/foonblob-api/deploy.conf` if the port is not 8080.
- Repository settings: secret `SSH_KEY`, variables `DEPLOY_HOST`, `DEPLOY_USER`, `KNOWN_HOSTS` and `PUBLIC_URL` (e.g. `https://blob.example.com`).

`/health` reports the running version in the `X-Foonblob-Version` header, and `foonblob-api -version` prints it.

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
3. **Origin Locking**: Dynamic CORS and server-side Origin checks (HTTP and WebSocket) ensure that a Sync ID registered from a browser cannot be accessed from another web origin.
4. **Encryption at Rest**: When configured, client secrets are protected by an additional layer of AES-GCM encryption, protecting them even if the database is compromised.

## License

[GPL-3.0-only](https://opensource.org/licenses/GPL-3.0-only)
