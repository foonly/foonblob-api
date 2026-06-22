# Foonblob API Client Development Guide

This guide provides a detailed technical specification for developers building client applications that integrate with the Foonblob API.

Foonblob is designed as a **zero-knowledge** storage provider. The server facilitates data synchronization but never has access to the plaintext data or the authorization secrets.

---

## 1. Authentication Architecture

Foonblob uses an HMAC-SHA256 request signing scheme. Every request (both reads and writes) must be signed using a `SigningSecret` associated with a `SyncID`.

### Required Headers

For sync operations (`/api/v1/sync/...`):

| Header             | Description                                   |
| ------------------ | --------------------------------------------- |
| `X-Sync-Timestamp` | Current Unix timestamp (seconds).             |
| `X-Sync-Signature` | HMAC-SHA256 signature of the request content. |

For management operations (`/api/v1/stats`):

| Header          | Description            |
| --------------- | ---------------------- |
| `Authorization` | `Bearer <stats_token>` |

### Anti-Replay & Security Rules

1. **Timestamp Window**: The server rejects requests with a timestamp difference > 300 seconds (5 minutes) from server time.
2. **Strict Increment**: For a given `SyncID`, the `X-Sync-Timestamp` must be **strictly greater** than the timestamp of the previous successful request.
3. **Signature Scope**:
   - For `POST` requests, the signature covers the **JSON body**.
   - For `GET` requests, the signature covers the **URL Path**.

---

## 2. Cryptography Implementation

### Data Encryption (Client Responsibility)

Before uploading data, clients should encrypt the payload. We recommend **AES-256-GCM**.

1. Generate a random `DataKey`.
2. Encrypt the data.
3. Base64 encode the resulting ciphertext (including the nonce).
4. Send this string as the `data` field in the JSON request.

### Signing Implementation

To generate the `X-Sync-Signature`:

#### For POST Requests:

1. Generate a SHA256 hash of the raw JSON request body (hex encoded).
2. Concatenate the string: `timestamp + bodyHash`.
3. Compute HMAC-SHA256 of that string using your `SigningSecret`.
4. Hex-encode the result.

#### For GET Requests:

1. Concatenate the string: `timestamp + urlPath` (where `urlPath` includes the leading slash, e.g., `1713820000/api/v1/sync/my-id`).
2. Compute HMAC-SHA256 of that string using your `SigningSecret`.
3. Hex-encode the result.

---

## 3. Endpoints

### Registration & Upload

`POST /api/v1/sync/:id`

If the `:id` does not exist, the server will create it using the `registration_secret` provided in the body. This secret then becomes the `SigningSecret` for all future requests.

**Request Body:**

```json
{
	"data": "base64_encrypted_blob",
	"registration_secret": "your-chosen-secret",
	"allowed_origin": "https://your-app.com"
}
```

_Note: `allowed_origin` is optional. If omitted, the server will lock the ID to the `Origin` header of the registration request._

**Response:**
`201 Created` (No body)

### Retrieve Latest

`GET /api/v1/sync/:id`

**Response:**

```json
{
	"id": "test-user",
	"data": "base64_encrypted_blob",
	"timestamp": 1713820500
}
```

### Retrieve History

`GET /api/v1/sync/:id/history`

Returns a list of available timestamps for historical versions.

**Response:**

```json
[{ "timestamp": 1713820500 }, { "timestamp": 1713819000 }]
```

### Retrieve Specific Version

`GET /api/v1/sync/:id/:timestamp`

Retrieves the blob exactly as it was at the specified timestamp.

**Response:**

```json
{
	"id": "test-user",
	"data": "base64_encrypted_blob",
	"timestamp": 1713820500
}
```

### Usage Statistics

`GET /api/v1/stats`

Requires `Authorization: Bearer <stats_token>`.

**Response:**

```json
{
	"totals": {
		"identities": 150,
		"blobs": 1200,
		"total_size_bytes": 45000000
	},
	"activity": {
		"identities_created_24h": 5,
		"blobs_created_24h": {
			"current": 45,
			"previous": 38
		}
	}
}
```

### Health Check

`GET /health`

Returns `200 OK` with body `ok` if the service is running.

### WebSocket Update Subscription

`GET /api/v1/ws`

Upgrades the connection to a WebSocket for real-time blob update notifications.

**Communication Protocol:**

All messages are JSON-encoded.

#### Client Messages

**Subscribe:**

```json
{
	"type": "subscribe",
	"id": "sync-id",
	"timestamp": 1713820500,
	"signature": "hmac-sha256-signature"
}
```

- `signature`: HMAC-SHA256 of `timestamp + "subscribe" + id` using the `SigningSecret`.

**Unsubscribe:**

```json
{
	"type": "unsubscribe",
	"id": "sync-id"
}
```

#### Server Messages

**Update Notification:**
Sent immediately upon successful subscription and whenever the blob is updated.

```json
{
	"type": "update",
	"id": "sync-id",
	"data": "base64_encrypted_blob",
	"timestamp": 1713820600
}
```

**Error:**

```json
{
	"type": "error",
	"message": "reason for failure",
	"code": 401
}
```

---

## 4. Error Handling

| Code  | Meaning           | Action                                                                 |
| ----- | ----------------- | ---------------------------------------------------------------------- |
| `400` | Bad Request       | Check payload size (max 1MB) or JSON formatting.                       |
| `401` | Unauthorized      | Verify HMAC signature calculation or check if timestamp is increasing. |
| `403` | Forbidden         | Cross-Origin request denied (Origin doesn't match registration).       |
| `404` | Not Found         | Sync ID or specific version does not exist.                            |
| `429` | Too Many Requests | Rate limit exceeded. Back off and retry.                               |

---

## 5. Implementation Example (JavaScript/Pseudo-code)

```javascript
async function foonblobRequest(method, path, secret, body = null) {
	const ts = Math.floor(Date.now() / 1000);
	let contentToSign = "";

	if (method === "POST") {
		const bodyHash = await crypto.subtle.digest(
			"SHA-256",
			new TextEncoder().encode(JSON.stringify(body)),
		);
		contentToSign =
			ts +
			Array.from(new Uint8Array(bodyHash))
				.map((b) => b.toString(16).padStart(2, "0"))
				.join("");
	} else {
		contentToSign = ts + path;
	}

	const signature = await computeHMAC(secret, contentToSign);

	return fetch(path, {
		method,
		headers: {
			"Content-Type": "application/json",
			"X-Sync-Timestamp": ts.toString(),
			"X-Sync-Signature": signature,
		},
		body: body ? JSON.stringify(body) : null,
	});
}
```

## 6. Rate Limits

The default server configuration applies the following limits per Sync ID:

- **Writes**: 15 requests per minute.
- **Reads**: 30 requests per minute.

Additionally, WebSocket connections are limited:

- **Connections per IP**: 32 concurrent connections.
- **Subscriptions per connection**: 32 active sync IDs.

Exceeding these will result in `429 Too Many Requests` (or a WebSocket error message).
