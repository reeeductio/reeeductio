# Typed Identifiers Implementation

## Overview

This E2E encrypted pubsub system now uses **typed identifiers** with a 264-bit format that encodes cleanly as 44 characters of **URL-safe base64** with no padding.

## Format Specification

### Structure
- **Total**: 264 bits (33 bytes) → 44 characters URL-safe base64
- **Header byte** (8 bits):
  - First 6 bits: Type identifier
  - Last 2 bits: Version number (currently 0)
- **Data** (256 bits / 32 bytes): Cryptographic material (Ed25519 keys or SHA256 hashes)

### Type Codes

| Type    | First Char | 6-bit Value | Binary   | Purpose                    |
|---------|-----------|-------------|----------|----------------------------|
| Space | `C`       | 2           | 000010   | Ed25519 space public key |
| User    | `U`       | 20          | 010100   | Ed25519 user public key    |
| Tool    | `T`       | 19          | 010011   | Ed25519 tool public key    |
| Message | `M`       | 12          | 001100   | SHA256 message hash        |
| Blob    | `B`       | 1           | 000001   | SHA256 blob hash           |

### Encoding

- **Base64 variant**: URL-safe (RFC 4648 §5)
  - Uses `-` instead of `+`
  - Uses `_` instead of `/`
  - No padding (`=`)
- **Character set**: `A-Z`, `a-z`, `0-9`, `-`, `_`
- **Length**: Always exactly 44 characters

## Examples

```
Space ID: CDlvwh-oQw-d-_52f0hhmcrrPQ0U-OWQ__W8_xRX5vnk
User ID:    UDlvwh-oQw-d-_52f0hhmcrrPQ0U-OWQ__W8_xRX5vnk
Tool ID:    TDlvwh-oQw-d-_52f0hhmcrrPQ0U-OWQ__W8_xRX5vnk
Message ID: MM-q0VU7Bk8QX-pfJA1GM-KVashl_taBkA1A9n-_lMpZ
Blob ID:    BM-q0VU7Bk8QX-pfJA1GM-KVashl_taBkA1A9n-_lMpZ
```

## Benefits

1. **URL-safe**: Can be used directly in URLs without encoding
2. **Type-safe**: Header prevents mixing space IDs with message hashes
3. **Clean encoding**: 264 bits → exactly 44 base64 chars (no padding)
4. **Versioned**: 2-bit version field for future format evolution
5. **Intent verification**: Signatures over full identifier (header + data) prove intent

## Python API

### Creating Identifiers

```python
from identifiers import (
    encode_space_id,
    encode_user_id,
    encode_tool_id,
    encode_message_id,
    encode_blob_id
)

# From Ed25519 public key (32 bytes)
space_id = encode_space_id(public_key_bytes)
user_id = encode_user_id(public_key_bytes)
tool_id = encode_tool_id(public_key_bytes)

# From SHA256 hash (32 bytes)
message_id = encode_message_id(hash_bytes)
blob_id = encode_blob_id(hash_bytes)
```

### Extracting Raw Data

```python
from identifiers import extract_public_key, extract_hash

# Extract 32-byte public key from space or user ID
pubkey_bytes = extract_public_key(space_id)  # Validates type

# Extract 32-byte hash from message or blob ID
hash_bytes = extract_hash(message_id)  # Validates type
```

### Decoding and Inspection

```python
from identifiers import decode_identifier, IdType

# Decode any typed identifier
tid = decode_identifier(space_id)
print(tid.id_type)     # IdType.SPACE
print(tid.version)     # 0
print(tid.data.hex())  # Raw 32-byte data as hex
```

## Cryptographic Integration

### Message Signatures

Signatures are computed over the **complete typed identifier** (33 bytes: header + hash), not just the raw hash. This proves the signer intends to sign specifically a message hash, not some other 256-bit object like a public key.

```python
# crypto.py verifies the type header before signature verification
def verify_message_signature(message_hash: str, signature: bytes,
                            sender_public_key: bytes) -> bool:
    tid = decode_identifier(message_hash)
    if tid.id_type != IdType.MESSAGE:
        raise ValueError("Expected MESSAGE type")

    # Sign over full 33-byte identifier
    message_bytes = tid.to_bytes()
    return verify_signature(message_bytes, signature, sender_public_key)
```

### Message Hash Computation

```python
# Automatically returns typed message identifier
message_hash = crypto.compute_message_hash(
    space_id,    # Typed space ID
    topic_id,      # String
    prev_hash,     # Typed message ID or None
    payload,       # Base64 encrypted content
    sender_id      # Typed user ID
)
# Returns: 44-char typed message identifier starting with 'M'
```

### Blob IDs

```python
# Compute blob ID from raw data
blob_id = crypto.compute_blob_id(blob_bytes)
# Returns: 44-char typed blob identifier starting with 'B'
```

## OpenAPI Specification

All identifier fields in the API now use:

```yaml
type: string
pattern: '^[A-Za-z0-9_-]{44}$'
minLength: 44
maxLength: 44
description: Typed <type> identifier (44-char URL-safe base64)
```

## Database Storage

Identifiers are stored as strings in the database. The database layer is transparent to the format change since it only stores/retrieves string values.

## Version Evolution

The 2-bit version field (0-3) allows future format changes:
- Version 0: Current implementation
- Versions 1-3: Reserved for future use

Decoders will need to handle multiple versions as the format evolves.

## Testing

Run the comprehensive test suite:

```bash
.venv/bin/python test_identifiers.py
```

Tests verify:
- Encoding/decoding correctness
- Type validation
- URL-safety (no `+` or `/` characters)
- No padding characters
- Crypto integration
- Type differentiation

## Files Modified

- `identifiers.py` - Core typed identifier implementation (NEW)
- `crypto.py` - Updated to use typed identifiers
- `main.py` - API endpoints use typed identifiers
- `authorization.py` - Capability verification with typed identifiers
- `openapi.yaml` - Updated all identifier schemas to URL-safe base64
- `test_identifiers.py` - Comprehensive test suite (NEW)

## Migration Notes

If migrating from an existing system:

1. Existing 32-byte keys/hashes can be wrapped with appropriate type headers
2. Database identifiers change from 43-44 chars (plain base64) to exactly 44 chars (typed URL-safe base64)
3. URL handling improved since `+` and `/` no longer need escaping
4. Signatures must be recomputed over the new 33-byte format
