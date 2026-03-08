# rEEEductio

**Absurdly simple encrypted spaces for developers.**

rEEEductio is an end-to-end encrypted data layer for building apps with secure messaging, encrypted file storage, and auditable shared state — without writing any cryptography yourself.

**→ [Documentation](https://reeeductio.github.io/)**

## What it is

A rEEEductio **space** is a shared, encrypted container that holds:

- **Topics** — append-only message streams, hash-chained and signed
- **State** — a hierarchical key-value store backed by the same hash chain, with full audit history
- **Blobs** — content-addressed encrypted file storage
- **Data** — a lightweight signed key-value store for less critical data

All encryption, signing, hashing, key derivation, authentication, and authorization is handled by the SDK. Developers focus on their application logic.

## Components

| Component | Description |
|-----------|-------------|
| [backend/](backend/) | Python server built on [FastAPI](https://fastapi.tiangolo.com/). Supports SQLite and Firestore. |
| [python-sdk/](python-sdk/) | Python client SDK and `reeeductio-admin` CLI |
| [typescript-sdk/](typescript-sdk/) | TypeScript SDK for Node.js and browsers |

## Quick start

```python
from reeeductio import Space
from reeeductio.crypto import generate_keypair, to_user_id, to_space_id
import secrets

# Generate credentials (do this once, save the results)
private_key, public_key = generate_keypair()
space_id = to_space_id(public_key)
symmetric_root = secrets.token_bytes(32)

# Connect
space = Space(
    space_id=space_id,
    member_id=to_user_id(public_key),
    private_key=private_key,
    symmetric_root=symmetric_root,
)

# Post an encrypted message
space.post_encrypted_message('general', 'chat.text', b'Hello, world!')

# Read it back
for msg in space.get_messages('general'):
    print(space.decrypt_message_data(msg, 'general'))
```

See the [Python Quick Start](https://reeeductio.github.io/getting-started/quickstart-python/) and [TypeScript Quick Start](https://reeeductio.github.io/getting-started/quickstart-typescript/) for full walkthroughs.

## Security model

- The server stores only ciphertext — it cannot read messages, state, or blobs.
- Every message is signed by its sender and linked to the previous message by hash, forming a tamper-evident chain.
- Access control uses a capability system stored in the space's own state and verified by the server.
- Password-based key recovery is available via [OPAQUE](https://reeeductio.github.io/how-to/password-login/), an asymmetric PAKE — the password is never sent to the server.

See [Security Internals](https://reeeductio.github.io/security/internals/) for the full cryptographic design.

## Running the server

```bash
docker run -p 8000:8000 ghcr.io/reeeductio/reeeductio-backend:latest
```

See [Running the Server](https://reeeductio.github.io/getting-started/running-the-server/) and [Self-Hosting](https://reeeductio.github.io/how-to/self-hosting/) for production setup.

## License

Available under your choice of permissive open-source licenses.
