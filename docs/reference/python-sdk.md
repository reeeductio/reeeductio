# Python SDK Reference

**Package:** `reeeductio`
**Install:** `pip install reeeductio`
**Requires:** Python ≥ 3.11

The main entry point is the `Space` class. Import it with:

```python
from reeeductio import Space
```

---

## `Space`

High-level client for interacting with a rEEEductio space.

### Constructor

```python
Space(
    space_id: str,
    member_id: str,
    private_key: bytes,
    symmetric_root: bytes,
    base_url: str = "http://localhost:8000",
    auto_authenticate: bool = True,
    local_store: LocalMessageStore | None = None,
    user_symmetric_key: bytes | None = None,
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `space_id` | `str` | 44-char space identifier (`S...`) |
| `member_id` | `str` | Your user ID (`U...`) or tool ID (`T...`) |
| `private_key` | `bytes` | 32-byte Ed25519 private key |
| `symmetric_root` | `bytes` | 32-byte root encryption key |
| `base_url` | `str` | Server URL (default: `http://localhost:8000`) |
| `auto_authenticate` | `bool` | Authenticate automatically on first call (default: `True`) |
| `local_store` | `LocalMessageStore \| None` | Optional local message cache |
| `user_symmetric_key` | `bytes \| None` | Optional 32-byte user-private key for user-private encryption |

Use as a context manager to ensure the HTTP client is closed:
```python
with Space(...) as space:
    msgs = space.get_messages('general')
```

### Derived attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `space_id` | `str` | Space identifier |
| `member_id` | `str` | This member's user/tool ID |
| `message_key` | `bytes` | Derived message encryption key |
| `state_key` | `bytes` | Derived state encryption key |
| `data_key` | `bytes` | Derived data encryption key |

---

## Authentication

### `authenticate() → str`

Perform challenge-response authentication. Returns a JWT token. Usually called automatically.

```python
token = space.authenticate()
```

---

## Messages

### `post_message(topic_id, msg_type, data, prev_hash=None) → MessageCreated`

Post raw (unencrypted) bytes to a topic.

```python
result = space.post_message('general', 'chat.text', encrypted_bytes)
print(result.message_hash)  # M...
```

### `post_encrypted_message(topic_id, msg_type, data, prev_hash=None) → MessageCreated`

Encrypt `data` client-side with the topic key, then post it.

```python
result = space.post_encrypted_message('general', 'chat.text', b'Hello!')
```

### `decrypt_message_data(msg, topic_id) → bytes`

Decrypt the `data` field of a message returned by `get_messages`.

```python
msgs = space.get_messages('general')
for msg in msgs:
    plaintext = space.decrypt_message_data(msg, 'general')
```

### `get_messages(topic_id, from_timestamp=None, to_timestamp=None, limit=100) → list[Message]`

Retrieve messages from a topic. Results are ordered by `server_timestamp` ascending.

```python
msgs = space.get_messages('general', limit=50)
```

### `get_message(topic_id, message_hash, use_cache=True) → Message`

Retrieve a single message by its hash.

### `derive_topic_key(topic_id) → bytes`

Derive the 32-byte encryption key for a topic. Rarely needed directly.

---

## State

### `get_plaintext_state(path) → str`

Get the current value at a state path as a UTF-8 string.

```python
profile = space.get_plaintext_state('profiles/alice')
```

### `get_encrypted_state(path, key=None) → str`

Get and decrypt the value at a state path.

### `set_plaintext_state(path, data, prev_hash=None) → MessageCreated`

Write a UTF-8 string value to a state path.

```python
space.set_plaintext_state('profiles/alice', '{"name": "Alice"}')
```

### `set_encrypted_state(path, data, prev_hash=None, key=None) → MessageCreated`

Encrypt and write a value to a state path.

### `get_state_history(from_timestamp=None, to_timestamp=None, limit=100) → list[Message]`

Retrieve the full event log of state changes.

---

## Blobs

### `encrypt_and_upload_blob(data) → EncryptedBlobCreated`

Encrypt `data` with a random per-blob DEK and upload it. Returns `blob_id` and `dek`.

```python
result = space.encrypt_and_upload_blob(open('photo.jpg', 'rb').read())
# Save result.blob_id and result.dek — you need both to download
```

### `download_and_decrypt_blob(blob_id, key) → bytes`

Download and decrypt a blob using its DEK.

```python
data = space.download_and_decrypt_blob(blob_id, dek)
```

### `upload_plaintext_blob(data) → BlobCreated`

Upload unencrypted bytes. Returns `blob_id`.

### `download_plaintext_blob(blob_id) → bytes`

Download unencrypted bytes.

### `delete_blob(blob_id) → None`

Delete a blob.

---

## Data (KV store)

### `get_plaintext_data(path) → bytes`

Get a value from the key-value store.

### `get_encrypted_data(path, key=None) → bytes`

Get and decrypt a value.

### `set_plaintext_data(path, data) → int`

Set a value. Returns the signed timestamp.

### `set_encrypted_data(path, data, key=None) → int`

Encrypt and set a value.

---

## Authorization

### `add_user(user_id, description=None) → MessageCreated`

Register a user in the space (writes to `auth/users/{user_id}`).

### `create_tool(tool_id, description=None) → MessageCreated`

Register a tool account.

### `create_role(role_name, description=None) → MessageCreated`

Create a role definition.

### `grant_capability_to_role(role_name, cap_id, capability) → MessageCreated`

Grant a capability to a role. `capability` is `{"op": "read|create|...", "path": "..."}`.

### `assign_role_to_user(user_id, role_name) → MessageCreated`

Assign a role to a user.

### `grant_capability_to_user(user_id, cap_id, capability) → MessageCreated`

Grant a direct capability to a user.

### `grant_capability_to_tool(tool_id, cap_id, capability) → MessageCreated`

Grant a capability to a tool.

---

## Crypto utilities

```python
from reeeductio.crypto import (
    generate_keypair,
    to_space_id,
    to_user_id,
    to_tool_id,
    string_to_bytes,
    bytes_to_string,
    encode_base64,
    decode_base64,
)
```

### `generate_keypair() → tuple[bytes, bytes]`

Returns `(private_key, public_key)` as 32-byte values.

### `to_space_id(public_key) → str`

Encode an Ed25519 public key as a space ID (`S...`).

### `to_user_id(public_key) → str`

Encode as a user ID (`U...`).

### `to_tool_id(public_key) → str`

Encode as a tool ID (`T...`).

---

## Exceptions

| Exception | When raised |
|-----------|-------------|
| `AuthenticationError` | Challenge-response or token refresh failed |
| `AuthorizationError` | Server returned 403 |
| `NotFoundError` | Resource does not exist (404) |
| `ValidationError` | Invalid request or data |
| `ChainError` | Message chain integrity check failed |
| `BlobError` | Blob upload or download failed |
| `OpaqueError` | OPAQUE protocol error |

```python
from reeeductio.exceptions import NotFoundError, ChainError

try:
    data = space.get_plaintext_state('profiles/alice')
except NotFoundError:
    print('No profile yet')
```

---

## Models

Key types returned by SDK methods:

| Type | Fields |
|------|--------|
| `Message` | `message_hash`, `prev_hash`, `type`, `data`, `sender`, `signature`, `server_timestamp` |
| `MessageCreated` | `message_hash`, `server_timestamp` |
| `BlobCreated` | `blob_id`, `size` |
| `EncryptedBlobCreated` | `blob_id`, `size`, `dek` (32-byte DEK) |
| `DataEntry` | `path`, `data`, `signed_by`, `signature`, `timestamp` |

---

## CLI

The `reeeductio-admin` CLI tool is included with the package:

```bash
reeeductio-admin --help

# Key commands
reeeductio-admin space generate        # Generate new space credentials
reeeductio-admin space create          # Register a space on the server
reeeductio-admin user add U...         # Add a user
reeeductio-admin user assign-role U... --role member
reeeductio-admin role create member
reeeductio-admin role grant member --cap-id read-all --op read --path "topics/{any}"
reeeductio-admin tool add T...
reeeductio-admin tool grant T... --cap-id post-alerts --op create --path "topics/alerts/messages/{any}"
```
