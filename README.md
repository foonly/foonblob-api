# Foonblob API

A decentralized, privacy-focused backend for synchronizing data across devices. This service acts as a "dumb" storage vault, storing encrypted data for clients without ever seeing the decryption keys.

## Features

- **End-to-End Encryption Support**: Designed to store opaque, client-side encrypted blobs (AES-GCM).
- **History Management**: Automatically retains the last 10 versions of your sync data for easy recovery.
- **Rate Limiting**: Built-in protection against abuse with per-ID rate limiting (5 POSTs/min, 30 GETs/min).
- **Lightweight & Portable**: Written in Go with a CGO-free SQLite implementation (`modernc.org/sqlite`).
- **CORS Ready**: Configured to work with frontend applications out of the box.

## API Specification

### Sync Endpoints

- `GET /api/v1/sync/:id`: Retrieve the most recent encrypted blob for a specific Sync ID.
- `POST /api/v1/sync/:id`: Upload a new encrypted blob. (Max size: 1MB)
- `GET /api/v1/sync/:id/history`: List timestamps for all available historical versions.
- `GET /api/v1/sync/:id/:timestamp`: Retrieve a specific historical version by its timestamp.

### Response Format

```json
{
	"id": "your-sync-id",
	"data": "base64_encrypted_blob",
	"timestamp": 1625000000000
}
```

## Getting Started

### Prerequisites

- Go 1.22 or higher

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/foonly/foonblob-api.git
   cd foonblob-api
   ```

2. Download dependencies:
   ```bash
   go mod download
   ```

### Running the Server

Start the API server with default settings (Port 8080, SQLite database `sync.db`):

```bash
go run cmd/api/main.go
```

#### Configuration Flags

- `-port`: HTTP port to listen on (default: `8080`)
- `-dsn`: SQLite database connection string (default: `sync.db`)
- `-history-limit`: Number of historical versions to retain per ID (default: `10`)

Example with custom flags:

```bash
go run cmd/api/main.go -port 9000 -dsn my-foonblobs.db -history-limit 5
```

### Running Tests

Execute the integration test suite:

```bash
go test -v ./internal/api/...
```

## Architecture

- **`cmd/api`**: Entry point and server lifecycle management.
- **`internal/api`**: HTTP routing, handlers, and rate-limiting middleware.
- **`internal/store`**: Persistence layer abstraction and SQLite implementation.
- **`internal/models`**: Shared data structures.

## Security

The server is designed to be a "zero-knowledge" storage provider. It is the responsibility of the client application to:

1. Generate secure Sync IDs and Keys.
2. Encrypt the data before `POST`ing.
3. Decrypt the data after `GET`ing.

The server never processes or stores the encryption keys.

## License

[GPL-3.0-only](https://opensource.org/licenses/GPL-3.0-only)
