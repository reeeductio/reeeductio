# REST API Reference

The rEEEductio server exposes a JSON REST API. All space-scoped endpoints are under `/spaces/{space_id}/`.

Most endpoints require a **Bearer token** obtained via the authentication flow below.

---

## Authentication

### Request a challenge

```
POST /spaces/{space_id}/auth/challenge
```

No authentication required.

**Request body:**

```json
{ "public_key": "U..." }
```

**Response:**

```json
{
  "challenge": "<base64-encoded nonce>",
  "expires_at": 1700000000
}
```

---

### Verify and obtain a token

```
POST /spaces/{space_id}/auth/verify
```

**Request body:**

```json
{
  "public_key": "U...",
  "challenge": "<challenge from previous step>",
  "signature": "<base64-encoded Ed25519 signature over the challenge>"
}
```

**Response:**

```json
{
  "token": "<JWT>",
  "expires_at": 1700086400
}
```

Use the token in subsequent requests:

```
Authorization: Bearer <token>
```

---

### Refresh a token

```
POST /spaces/{space_id}/auth/refresh
```

**Auth required:** Yes

Returns a new `TokenResponse` with an extended expiry.

---

## Messages

### Get messages

```
GET /spaces/{space_id}/topics/{topic_id}/messages
```

**Auth required:** Yes

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `from` | integer | Start timestamp (ms, inclusive) |
| `to` | integer | End timestamp (ms, inclusive) |
| `limit` | integer | Max results (1–1000, default 100) |

**Response:**

```json
{
  "messages": [
    {
      "message_hash": "M...",
      "topic_id": "general",
      "type": "chat.text",
      "prev_hash": "M...",
      "data": "<base64>",
      "sender": "U...",
      "signature": "<base64>",
      "server_timestamp": 1700000000000
    }
  ],
  "has_more": false
}
```

---

### Post a message

```
POST /spaces/{space_id}/topics/{topic_id}/messages
```

**Auth required:** Yes

**Topic ID format:** 2–64 characters, lowercase alphanumeric with hyphens and underscores (`[a-z0-9][a-z0-9_-]*[a-z0-9]`).

**Request body:**

```json
{
  "type": "chat.text",
  "prev_hash": "M...",
  "data": "<base64-encoded payload, max 100 KB>",
  "message_hash": "<SHA-256 of canonical fields>",
  "signature": "<Ed25519 signature over message_hash>"
}
```

**Response (201):**

```json
{
  "message_hash": "M...",
  "server_timestamp": 1700000000000
}
```

**Error 409 Conflict:** `prev_hash` does not match the current chain head. Fetch the latest message and retry.

---

### Get a single message

```
GET /spaces/{space_id}/topics/{topic_id}/messages/{message_hash}
```

**Auth required:** Yes

Returns a single `Message` object or **404** if not found.

---

## State

State is an event-sourced key-value store backed by the reserved `state` topic. Every write is a message; the current value at a path is the data from the most recent message for that path.

### Get state history

```
GET /spaces/{space_id}/state
```

**Auth required:** Yes

Accepts the same `from`, `to`, `limit` query parameters as the messages endpoint.

Returns a `MessagesResponse` of all state-change messages.

---

### Get value at a path

```
GET /spaces/{space_id}/state/{path}
```

**Auth required:** Yes

Returns the most recent `Message` whose `type` equals `path`, or **404** if no value has been written to that path.

---

### Set a value

```
PUT /spaces/{space_id}/state/{path}
```

**Auth required:** Yes

**Request body:** Same shape as posting a message. The `type` field must equal the `path`.

**Response:**

```json
{
  "message_hash": "M...",
  "server_timestamp": 1700000000000
}
```

---

## Blobs

Blob IDs are content-addressed: `B` + base64url(SHA-256 of the encrypted content).

### Upload a blob

```
PUT /spaces/{space_id}/blobs/{blob_id}
```

**Auth required:** Yes

**Request body:** Raw binary data (`application/octet-stream`).

**Response (201):**

```json
{ "blob_id": "B...", "size": 102400 }
```

For S3-backed deployments the response may instead be:

```json
{ "blob_id": "B...", "upload_url": "https://..." }
```

In that case, upload the raw bytes directly to `upload_url` via HTTP `PUT`.

---

### Download a blob

```
GET /spaces/{space_id}/blobs/{blob_id}
```

**Auth required:** Yes

Returns raw binary data, or a redirect/presigned URL for S3-backed deployments.

---

### Delete a blob

```
DELETE /spaces/{space_id}/blobs/{blob_id}
```

**Auth required:** Yes

Returns **204 No Content**.

---

## Data (KV store)

The data store is a simple signed key-value store. Unlike state, it has no hash chain; each entry is independently signed.

### Get a value

```
GET /spaces/{space_id}/data/{path}
```

**Auth required:** Yes

**Response:**

```json
{
  "data": "<base64>",
  "signature": "<base64 Ed25519 signature>",
  "signed_by": "U...",
  "signed_at": 1700000000000
}
```

---

### Set a value

```
PUT /spaces/{space_id}/data/{path}
```

**Auth required:** Yes

**Request body:**

```json
{
  "data": "<base64>",
  "signature": "<Ed25519 signature over space_id|path|data|signed_at>",
  "signed_by": "U...",
  "signed_at": 1700000000000
}
```

**Response:**

```json
{ "path": "...", "signed_at": 1700000000000 }
```

---

### Delete a value

```
DELETE /spaces/{space_id}/data/{path}
```

**Auth required:** Yes

Returns **204 No Content**.

---

## WebSocket

### Connect to the real-time stream

```
WebSocket /spaces/{space_id}/stream?token=<JWT>
```

The JWT token is passed as a query parameter (not a header) because browser WebSocket APIs do not support custom headers.

Once connected, the server pushes new messages as JSON-encoded `Message` objects as they are posted to any topic in the space.

```typescript
const wsUrl = `wss://my-server.example.com/spaces/${spaceId}/stream?token=${token}`;
const ws = new WebSocket(wsUrl);
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  // msg is a Message object
};
```

---

## Health check

```
GET /health
```

No authentication required.

**Response:**

```json
{ "status": "healthy", "timestamp": 1700000000000 }
```

---

## Admin API

These endpoints use a separate admin authentication session. The admin space ID is configured server-side.

### Admin challenge

```
POST /admin/auth/challenge
```

Same as the space challenge, but targets the admin space without needing to know its ID in advance.

### Admin verify

```
POST /admin/auth/verify
```

Same as space verify. Returns a JWT scoped to the admin space.

### Get admin space ID

```
GET /admin/space
```

**Auth required:** Yes (admin token)

```json
{ "space_id": "S..." }
```

### Admin delete blob

```
DELETE /admin/blobs/{blob_id}
```

**Auth required:** Yes (admin token)

Deletes a blob across all spaces. Useful for cleaning up orphaned blobs.

---

## OPAQUE (password-based key recovery)

These endpoints implement the OPAQUE protocol for password-based credential wrapping. They do not grant access directly — a successful OPAQUE login recovers the user's `privateKey` and `symmetricRoot`, which are then used for the standard challenge-response flow.

### Enable OPAQUE for a space

```
POST /spaces/{space_id}/opaque/setup
```

**Auth required:** Yes (space admin)

Initializes the OPAQUE server-side setup for this space.

---

### Registration (step 1 of 2)

```
POST /spaces/{space_id}/opaque/register/init
```

**Auth required:** Yes (space member)

```json
{
  "username": "alice",
  "registration_request": "<base64 OPAQUE RegistrationRequest>"
}
```

**Response:**

```json
{ "registration_response": "<base64 OPAQUE RegistrationResponse>" }
```

---

### Registration (step 2 of 2)

```
POST /spaces/{space_id}/opaque/register/finish
```

**Auth required:** Yes

```json
{
  "username": "alice",
  "registration_record": "<base64 OPAQUE RegistrationUpload>"
}
```

---

### Login (step 1 of 2)

```
POST /spaces/{space_id}/opaque/login/init
```

No authentication required.

```json
{
  "username": "alice",
  "credential_request": "<base64 OPAQUE CredentialRequest>"
}
```

**Response:**

```json
{ "credential_response": "<base64 OPAQUE CredentialResponse>" }
```

---

### Login (step 2 of 2)

```
POST /spaces/{space_id}/opaque/login/finish
```

No authentication required.

```json
{
  "username": "alice",
  "credential_finalization": "<base64 OPAQUE CredentialFinalization>"
}
```

**Response:**

```json
{
  "encrypted_credentials": "<base64 AES-GCM wrapped privateKey + symmetricRoot>",
  "public_key": "U..."
}
```

The client decrypts `encrypted_credentials` with the OPAQUE `export_key`, recovers `privateKey` and `symmetricRoot`, and uses them to authenticate via `/auth/challenge` and `/auth/verify`.

---

## Common status codes

| Code | Meaning |
|------|---------|
| 200 | OK |
| 201 | Created |
| 204 | No Content (delete success) |
| 400 | Bad Request — invalid input |
| 401 | Unauthorized — missing or invalid token |
| 403 | Forbidden — insufficient capability |
| 404 | Not Found |
| 409 | Conflict — hash chain conflict (`prev_hash` mismatch) |
| 413 | Payload Too Large — blob exceeds `max_blob_size` |
| 429 | Too Many Requests — OPAQUE rate limit |
| 501 | Not Implemented — feature not enabled (e.g., OPAQUE) |
| 503 | Service Unavailable — database temporarily unavailable |
