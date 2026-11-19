# Foonblob API Client Development Guide

This guide provides a detailed technical specification for developers building client applications that integrate with the Foonblob API.

Foonblob is designed as a **zero-knowledge** storage provider for your data: the server facilitates data synchronization but never has access to the plaintext data. Note that the server _does_ store each Sync ID's `SigningSecret` (HMAC is symmetric), optionally encrypted at rest, so never reuse your data encryption key as the signing secret.

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
2. **No Replays**: Each signed request is accepted once. The server remembers accepted signatures until their timestamp leaves the 5-minute window and rejects repeats with `401`. Timestamps do not have to increase, so several devices can use the same `SyncID` at the same time. Two _identical_ requests in the same second (e.g. two devices fetching the same path) produce the same signature, so the second gets a `401`; retry it with a new timestamp.
3. **Versions**: The `timestamp` of a stored blob is its version and always increases with each upload: it is the request timestamp, or one more than the previous version if that is not newer.
4. **Signature Scope**:
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

_Note: `allowed_origin` is optional. If omitted, the server will lock the ID to the `Origin` header of the registration request. If neither is present (native clients), the ID is not origin-restricted. The origin is normalized (lowercased, default port removed). Sync IDs are limited to 256 characters._

The registration request must be signed with the `registration_secret` just like any other `POST`.

**Response:**
`201 Created` (No body). `409 Conflict` if another client registered the same ID concurrently.

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
- `timestamp` is subject to the same window and no-replay rules as HTTP requests.
- If the Sync ID has a registered origin, the WebSocket's `Origin` header must match it.

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
	"id": "sync-id",
	"message": "reason for failure",
	"code": 401
}
```

`id` is present when the error concerns a specific subscription, so the client can retry it.

---

## 4. Error Handling

| Code  | Meaning           | Action                                                                 |
| ----- | ----------------- | ---------------------------------------------------------------------- |
| `400` | Bad Request       | Check JSON formatting.                                                 |
| `401` | Unauthorized      | Verify HMAC signature calculation or check if timestamp is increasing. |
| `403` | Forbidden         | Cross-Origin request denied (Origin doesn't match registration).       |
| `404` | Not Found         | Sync ID or specific version does not exist.                            |
| `409` | Conflict          | Sync ID was registered concurrently by another client.                 |
| `413` | Payload Too Large | Request body exceeds 1MB.                                              |
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
