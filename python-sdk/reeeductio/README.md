# reeeductio - High-Level Python SDK

High-level Python SDK for interacting with reeeductio encrypted spaces. This package provides a convenient interface on top of the auto-generated `reeeductio_client`.

## Features

- **Simplified Authentication**: Automatic challenge-response flow handling
- **Cryptographic Utilities**: Ed25519 signing, verification, and hashing
- **State Management**: Easy-to-use methods for reading/writing space state
- **Message Handling**: Helpers for message chain validation and posting
- **Blob Storage**: Upload and download encrypted blobs

## Installation

```bash
pip install reeeductio-client
```

## Quick Start

### 1. Generate or Load Key Pair

```python
from reeeductio import generate_keypair, Ed25519KeyPair

# Generate new keypair
keypair = generate_keypair()

# Or load from existing keys
keypair = Ed25519KeyPair(
    private_key=b'...',  # 32 bytes
    public_key=b'...',   # 32 bytes
)

# Get typed public key identifier
user_id = keypair.to_typed_public_key()  # 44-char base64 string
```

### 2. Connect to a Space

```python
from reeeductio import Space

space = Space(
    space_id="...",  # 44-char typed space identifier
    keypair=keypair,
    base_url="https://api.example.com",
    auto_authenticate=True,  # Automatically handle auth
)

# Authenticate (if auto_authenticate=False)
token = space.authenticate()
```

### 3. Work with State

```python
# Get state
profile_entry = space.get_state("profiles/alice")
if profile_entry:
    print(f"Data: {profile_entry.data}")  # base64-encoded

# Set state (automatically signed)
import json
profile = {"name": "Alice", "avatar": "..."}
data = json.dumps(profile).encode('utf-8')
space.set_state("profiles/alice", data)

# Delete state
space.delete_state("profiles/alice")

# Convenience methods for JSON profiles
profile = space.get_profile(user_id)
space.set_profile(user_id, {"name": "Alice"})
```

### 4. Work with Messages

```python
# Get messages from a topic
messages = space.get_messages(
    topic_id="general",
    limit=50,
)

for msg in messages:
    print(f"From: {msg.sender}")
    print(f"Encrypted: {msg.encrypted_payload}")
    print(f"Hash: {msg.message_hash}")

# Get specific message
message = space.get_message("general", message_hash="...")
```

### 5. Work with Blobs

```python
from reeeductio.crypto import compute_hash, to_typed_hash

# Upload blob
encrypted_data = b"..."  # Your encrypted file
blob_hash = to_typed_hash(compute_hash(encrypted_data))
space.upload_blob(blob_hash, encrypted_data)

# Download blob
data = space.download_blob(blob_hash)

# Delete blob
space.delete_blob(blob_hash)
```

## Architecture

The SDK has two layers:

### Low-Level Layer (`reeeductio_client`)
Auto-generated from OpenAPI spec using `openapi-python-client`. Provides:
- Type-safe API calls with Pydantic models
- Sync and async variants of all endpoints
- Direct 1:1 mapping to REST API

### High-Level Layer (`reeeductio`)
Hand-written convenience layer that:
- Handles authentication flow automatically
- Provides cryptographic utilities
- Simplifies common operations
- Manages message chains and signatures

## Cryptographic Utilities

```python
from reeeductio.crypto import (
    generate_keypair,
    sign_data,
    verify_signature,
    compute_hash,
    to_typed_hash,
    encode_base64,
    decode_base64,
)

# Generate keypair
keypair = generate_keypair()

# Sign data
signature = sign_data(b"message", keypair.private_key)

# Verify signature
is_valid = verify_signature(b"message", signature, keypair.public_key)

# Hash data
hash_bytes = compute_hash(b"data")
typed_hash = to_typed_hash(hash_bytes)  # 44-char identifier

# Base64 encoding
encoded = encode_base64(b"data")
decoded = decode_base64(encoded)
```

## Advanced Usage

### Using the Low-Level Client Directly

```python
from reeeductio_client import AuthenticatedClient
from reeeductio_client.api.state import get_spaces_space_id_state_path

client = AuthenticatedClient(
    base_url="https://api.example.com",
    token="your-jwt-token",
)

state_entry = get_spaces_space_id_state_path.sync(
    client=client,
    space_id="...",
    path="profiles/alice",
)
```

### Manual Authentication Control

```python
from reeeductio.auth import AuthSession

auth = AuthSession(
    space_id="...",
    public_key_typed="...",
    private_key=keypair.private_key,
    base_url="https://api.example.com",
)

# Authenticate
token = auth.authenticate()

# Check if authenticated
if auth.is_authenticated:
    print("Session is valid")

# Refresh token
new_token = auth.refresh_token()

# Ensure authenticated (auto-refresh if needed)
token = auth.ensure_authenticated()
```

## Development

This high-level SDK is designed to be maintained separately from the auto-generated `reeeductio_client`. When the OpenAPI spec changes:

1. Regenerate `reeeductio_client` using `openapi-python-client`
2. Update `reeeductio` if new endpoints or patterns need high-level wrappers
3. The two layers remain independent

## License

See the main project LICENSE file.
