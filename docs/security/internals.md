# Security Internals

This page is for security-curious developers who want to understand the cryptographic design in detail.

## Identity and key material

Every participant (space, user, or tool) is an Ed25519 keypair. The public key is encoded as a typed identifier:

| Prefix | Type | Derivation |
|--------|------|-----------|
| `S` | Space ID | `base64url(0b010010 ‖ public_key)` |
| `U` | User ID | `base64url(0b010101 ‖ public_key)` |
| `T` | Tool ID | `base64url(0b010011 ‖ public_key)` |

All identifiers are 44 URL-safe base64 characters (1 type byte + 32 key bytes = 33 bytes → 44 chars).

The space's **public key is the root of trust** — it determines the space ID, and the holder of the corresponding private key is the implicit admin with full authority.

## Key derivation tree

The `symmetricRoot` is a 32-byte random secret that is the root of all encryption in the space. Keys are derived with HKDF-SHA256 and an `info` string that encodes the key's purpose and scope, preventing key reuse across contexts:

```
symmetricRoot  (32 bytes, random)
│
├─ HKDF("message key | {spaceId}")  →  message_key  (32 bytes)
│   │
│   ├─ HKDF("topic key | general")  →  topic_key["general"]
│   ├─ HKDF("topic key | alerts")   →  topic_key["alerts"]
│   └─ HKDF("topic key | state")    →  state_key  (reserved)
│
└─ HKDF("data key | {spaceId}")     →  data_key  (32 bytes)
```

The `spaceId` in the `info` string provides **domain separation** — the same `symmetricRoot` in two different spaces produces completely different keys, so sharing a root across spaces (which you shouldn't do) still doesn't allow cross-space decryption.

## Encryption

All data is encrypted with **AES-256-GCM**:

- **Key**: 32-byte key from the derivation tree above
- **Nonce**: 12-byte random IV, prepended to the ciphertext
- **Tag**: 16-byte authentication tag, appended to the ciphertext
- **Wire format**: `IV (12 bytes) ‖ ciphertext ‖ tag (16 bytes)`, base64-encoded

AES-GCM provides both confidentiality and integrity — a corrupted or tampered ciphertext will fail to decrypt.

## Message integrity: hash chains

Every message in a topic has:

- `message_hash`: SHA-256 of `{spaceId}|{topicId}|{prevHash}|{type}|{data}|{sender}|{signature}`
- `prev_hash`: the `message_hash` of the previous message (or `null` for the first)
- `signature`: Ed25519 signature by the sender over the message hash

This forms a **tamper-evident append-only log**:

- Any modification to a message changes its hash, which invalidates all subsequent `prev_hash` links.
- Any inserted or deleted message breaks the chain.
- Each message is independently verifiable against the sender's public key.

The server enforces chain integrity with **compare-and-swap** at write time: a message is only accepted if its `prev_hash` matches the current chain head, atomically within a database transaction. This prevents forking even under concurrent writes.

## State integrity: event-sourced

State is stored as messages in a reserved topic (`"state"`), using the same hash chain mechanism as regular topics. The state topic uses `state_key` (derived from `message_key`) for encryption.

Each state write records the path being updated in the `type` field. The current value at any path is the data from the most recent message whose `type` matches that path.

Because state is backed by a message chain, the full history of every state change is cryptographically verifiable. A server cannot substitute a forged state entry without breaking the chain.

## Blob integrity: content addressing

Blob IDs are derived from the **hash of the encrypted content**. If the server returns different bytes for the same blob ID, the hash check fails. This prevents substitution attacks.

For encrypted blobs, each blob has its own randomly-generated 32-byte **data encryption key (DEK)**. The DEK is returned to the uploader and must be stored separately — typically encrypted inside a message. The server never has the DEK.

## Authorization: capability chain of trust

Capabilities are stored as signed state entries. The authorization chain works as follows:

1. **Space creator** (the keypair encoded in the space ID) has implicit full authority — no capability entry needed.
2. The creator can write capability entries granting rights to users or roles.
3. Users and tools can only be granted capabilities that are a **subset** of the grantor's own capabilities. The server enforces this: you cannot grant more than you have.
4. Every capability entry is signed by the grantor. The server verifies the signature and the grantor's authority before accepting a write to `auth/`.

**Path-content consistency**: For critical auth paths (role grants, tool definitions), the server verifies that the data content matches the path. A tool with write access to `auth/users/U.../roles/member` cannot write `{"role_id": "admin"}` there — the data must match the path.

## Authentication: challenge-response

```
Client → Server: POST /spaces/{spaceId}/auth/challenge  {public_key: "U..."}
Server → Client: {challenge: "<random nonce>", expires_at: ...}
Client: signature = Ed25519.sign(challenge.encode("utf-8"), privateKey)
Client → Server: POST /spaces/{spaceId}/auth/verify  {public_key, challenge, signature}
Server: verifies signature; issues JWT
```

The JWT is a standard HS256 token signed with the server's `jwt_secret`. It expires after `jwt_expiry_hours` (default 24h). The server validates it on every subsequent request.

The challenge is a random nonce that expires after `challenge_expiry_seconds` (default 300s), preventing replay attacks.

## OPAQUE: password-based key recovery

OPAQUE is an asymmetric PAKE used for **credential recovery only** — not for access control.

When a user registers with OPAQUE:
1. The client runs the OPAQUE registration protocol with the server, producing an `export_key` (64 bytes) known only to the client.
2. The client derives a wrapping key: `wrap_key = HKDF(export_key, "reeeductio-credential-wrap")`.
3. The client encrypts `privateKey ‖ symmetricRoot` with `wrap_key` using AES-256-GCM and stores the ciphertext on the server at a known path.

When a user logs in with OPAQUE:
1. The client runs the OPAQUE login protocol, recovering the same `export_key`.
2. The client derives `wrap_key` and decrypts the stored credentials.
3. The client uses the recovered `privateKey` to perform the normal Ed25519 challenge-response login.

**Key properties:**
- The password is never transmitted to the server (OPAQUE guarantee).
- A server compromise reveals only the wrapped credentials — useless without the password.
- Password changes re-wrap the same keypair; the public key and space ID never change.
- OPAQUE is rate-limited server-side to slow brute-force attacks.

## Data store security comparison

| Store | Encrypted | Signed | Chained | Replay-safe |
|-------|-----------|--------|---------|-------------|
| Topics (messages) | ✅ | ✅ | ✅ | ✅ |
| State | ✅ | ✅ | ✅ | ✅ |
| Blobs | ✅ | n/a | n/a (content-addressed) | ✅ |
| Data (KV) | ✅ | ✅ | ❌ | ⚠️ (cached clients only) |

## Related pages

- [Security Overview](overview.md) — plain-language summary
- [Threat Model](threat-model.md) — what attacks are in and out of scope
