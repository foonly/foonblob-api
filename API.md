# Foonblob API Client Development Guide

This guide provides a detailed technical specification for developers building client applications that integrate with the Foonblob API. 

Foonblob is designed as a **zero-knowledge** storage provider. The server facilitates data synchronization but never has access to the plaintext data or the authorization secrets.

---

## 1. Authentication Architecture

Foonblob uses an HMAC-SHA256 request signing scheme. Every request (both reads and writes) must be signed using a `SigningSecret` associated with a `SyncID`.

### Required Headers

| Header | Description |
|--------|-------------|
| `X-Sync-Timestamp` | Current Unix timestamp (seconds). |
| `X-Sync-Signature` | HMAC-SHA256 signature of the request content. |

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
1. Concatenate the string: `timestamp + urlPath` (e.g., `1713820000/api/v1/sync/my-id`).
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
*Note: `allowed_origin` is optional. If omitted, the server will lock the ID to the `Origin` header of the registration request.*

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
[
  {"timestamp": 1713820500},
  {"timestamp": 1713819000}
]
```

### Retrieve Specific Version
`GET /api/v1/sync/:id/:timestamp`

Retrieves the blob exactly as it was at the specified timestamp.

---

## 4. Error Handling

| Code | Meaning | Action |
|------|---------|--------|
| `400` | Bad Request | Check payload size (max 1MB) or JSON formatting. |
| `401` | Unauthorized | Verify HMAC signature calculation or check if timestamp is increasing. |
| `403` | Forbidden | Cross-Origin request denied (Origin doesn't match registration). |
| `404` | Not Found | Sync ID or specific version does not exist. |
| `429` | Too Many Requests | Rate limit exceeded. Back off and retry. |

---

## 5. Implementation Example (JavaScript/Pseudo-code)

```javascript
async function foonblobRequest(method, path, secret, body = null) {
  const ts = Math.floor(Date.now() / 1000);
  let contentToSign = "";

  if (method === 'POST') {
    const bodyHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(body)));
    contentToSign = ts + Array.from(new Uint8Array(bodyHash)).map(b => b.toString(16).padStart(2, '0')).join('');
  } else {
    contentToSign = ts + path;
  }

  const signature = await computeHMAC(secret, contentToSign);

  return fetch(path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-Sync-Timestamp': ts.toString(),
      'X-Sync-Signature': signature
    },
    body: body ? JSON.stringify(body) : null
  });
}
```

## 6. Rate Limits
The default server configuration applies the following limits per Sync ID:
- **Writes**: 5 requests per minute.
- **Reads**: 30 requests per minute.

Exceeding these will result in `429 Too Many Requests`.
