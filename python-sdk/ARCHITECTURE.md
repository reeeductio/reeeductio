# Architecture Overview

This document describes the architecture of the new reeeductio Python SDK.

## Design Philosophy

This SDK is a **clean-slate rewrite** built without auto-generated code. The goals are:

1. **Developer-friendly**: Clean, readable code with comprehensive type hints
2. **Modern Python**: Uses dataclasses, type hints, and modern patterns
3. **httpx-based**: Single library for sync/async HTTP and WebSocket support
4. **Modular**: Each API component (messages, blobs, state, data) is a separate module
5. **Maintainable**: Hand-written code is easier to debug and extend

## Module Structure

```
reeeductio/
├── __init__.py          # Public API exports
├── models.py            # Data models (Message, Capability, etc.)
├── exceptions.py        # Custom exception types
├── crypto.py            # Ed25519 signing, hashing, encoding
├── auth.py              # Authentication session management (sync + async)
├── client.py            # High-level Space client
├── messages.py          # Message chain helpers
├── blobs.py             # Blob storage helpers
├── state.py             # State management helpers
├── kvdata.py            # Key-value data helpers
└── streaming.py         # WebSocket streaming (TODO)
```

## Core Concepts

### Typed Identifiers

All identifiers use a typed base64 encoding with a header byte:

```
[6 bits: type][2 bits: version][32 bytes: data] → 44-char base64 string
```

Types:
- `U` - User (Ed25519 public key)
- `S` - Space (Ed25519 public key)
- `T` - Tool (Ed25519 public key)
- `M` - Message (SHA256 hash)
- `B` - Blob (SHA256 hash)

### Message Chains

Messages form blockchain-like chains with cryptographic integrity:

```python
message_hash = SHA256(topic_id|type|prev_hash|data|sender)
```

Each message includes:
- `message_hash`: Content-addressed identifier
- `prev_hash`: Link to previous message
- `signature`: Ed25519 signature over the message_hash
- `sender`: User/tool that created the message
- `data`: Encrypted payload (base64)
- `type`: Message category or state path

### State vs Data

**State** (event-sourced):
- Stored as messages in the "state" topic
- Path goes in the `type` field
- Full history available via event log
- Temporal queries supported
- Example: `auth/users/U_abc123`, `profiles/alice`

**Data** (simple KV):
- Direct PUT/GET operations
- Every entry must be signed
- No history, just current value
- Faster but less features
- Example: `settings/theme`, `cache/user_list`

### Encryption Architecture

The SDK uses a **hierarchical key derivation** approach with HKDF-SHA256:

```
symmetric_root (32 bytes)
    ├─> message_key = HKDF(symmetric_root, info="message key | {space_id}")
    ├─> blob_key = HKDF(symmetric_root, info="blob key | {space_id}")
    ├─> state_key = HKDF(message_key, info="topic key | state")
    └─> data_key = HKDF(symmetric_root, info="data key | {space_id}")
```

Keys are derived once during Space initialization and stored as instance attributes.

**Security Benefits:**
- **Single shared secret** per space
- **Cryptographic separation** between data types and spaces
- **Domain separation**: space_id in HKDF info prevents key reuse across spaces
- **Defense in depth**: Even if users accidentally reuse symmetric_root, keys differ per space
- **Forward compatibility** for key rotation

The `symmetric_root` is provided during `Space` initialization and stored in the client. It must be exactly 32 bytes (256 bits).

### Authentication Flow

1. Request challenge: `POST /spaces/{space_id}/auth/challenge`
2. Sign challenge with Ed25519 private key
3. Verify signature: `POST /spaces/{space_id}/auth/verify`
4. Receive JWT token
5. Use token in `Authorization: Bearer <token>` header
6. Refresh when needed: `POST /spaces/{space_id}/auth/refresh`

## Component Details

### models.py

Pure data models using dataclasses:
- `Message`: Topic message with chain integrity
- `Capability`: Permission definition
- `Member`, `Role`, `RoleGrant`: Authorization primitives
- `DataEntry`: Signed KV entry
- `BlobCreated`, `MessageCreated`: API responses

### crypto.py

Cryptographic primitives:
- `generate_keypair()`: Create Ed25519 key pair
- `sign_data()`, `verify_signature()`: Ed25519 operations
- `compute_hash()`: SHA256 hashing
- `derive_key()`: HKDF-SHA256 key derivation
- `to_message_id()`, `to_blob_id()`: Typed identifier creation
- `encode_base64()`, `decode_base64()`: Data encoding

### auth.py

Two implementations:
- `AuthSession`: Sync authentication
- `AsyncAuthSession`: Async authentication

Both handle:
- Challenge-response flow
- Token refresh
- Token expiration tracking
- Auto-refresh with 60s buffer

### client.py (Space)

High-level client orchestrating all components:
- **Symmetric root key**: Stores 256-bit (32-byte) root key for HKDF key derivation
- Automatic authentication via `AuthSession`
- Context manager support (`with Space(...) as space:`)
- Convenience methods for all API operations
- Handles prev_hash fetching when not provided

The `symmetric_root` is the foundation for deriving encryption keys:
- `message_key`: For encrypting messages across all topics
- `blob_key`: For encrypting blob content
- `state_key`: For encrypting state values
- `data_key`: For encrypting KV data

All keys are 32 bytes (256 bits) and derived deterministically using HKDF-SHA256.
This allows a single shared secret per space while maintaining cryptographic separation between different data types.

### messages.py

Message chain operations:
- `compute_message_hash()`: Hash computation for integrity
- `post_message()`: Post with signature
- `validate_message_chain()`: Verify chain integrity
- `MessageEncryption`: Placeholder for encryption (TODO)

### blobs.py

Content-addressed blob storage:
- `compute_blob_id()`: SHA256-based blob ID
- `upload_blob()`: PUT with S3 redirect support
- `download_blob()`: GET with S3 redirect support
- `delete_blob()`: DELETE operation
- `BlobEncryption`: Placeholder for encryption (TODO)

### state.py

Event-sourced state management:
- `get_state()`: Get current materialized state
- `set_state()`: Post state change message
- `get_state_history()`: Query event log
- Wraps message posting with state-specific logic

### kvdata.py

Simple signed key-value store:
- `get_data()`: Read KV entry
- `set_data()`: Write signed KV entry
- `compute_data_signature()`: Signature over `space_id|path|data|signed_at`

## Dependencies

Minimal and intentional:

```toml
[project]
dependencies = [
    "httpx>=0.23.0,<0.29.0",  # HTTP client (sync/async/websocket)
    "python-dateutil>=2.8.0",  # Date utilities
    "cryptography>=41.0.0",    # Ed25519, SHA256
]
```

No attrs, no generated code dependencies.

## Future Enhancements

1. **Async Client**: `AsyncSpace` class mirroring `Space` but with async methods
2. **Streaming**: WebSocket support for real-time message delivery
3. **Encryption**: AES-GCM helpers for messages and blobs
4. **Testing**: Comprehensive test suite with mocked HTTP
5. **Validation**: Runtime schema validation for API responses
6. **Retry Logic**: Exponential backoff for transient failures
7. **Connection Pooling**: Reusable httpx clients for better performance

## Comparison with Old SDK

| Aspect | Old SDK | New SDK |
|--------|---------|---------|
| Code Generation | openapi-python-client | Hand-written |
| Dependencies | attrs, httpx | httpx, cryptography |
| Type Safety | Partial (attrs) | Full (dataclasses) |
| Lines of Code | ~5000+ (generated) | ~2500 (maintainable) |
| Async Support | No | Yes (via httpx) |
| WebSocket | Partial | Coming soon |
| Maintainability | Low (generated) | High (clean code) |

## Testing Strategy

1. **Unit Tests**: Test crypto, models, helpers in isolation
2. **Integration Tests**: Test against local server
3. **Mock Tests**: Use `respx` to mock HTTP responses
4. **E2E Tests**: Full workflow tests with real server

Example test structure:
```python
tests/
├── test_crypto.py
├── test_models.py
├── test_auth.py
├── test_messages.py
├── test_blobs.py
├── test_state.py
├── test_kvdata.py
├── test_client.py
└── test_integration.py
```
