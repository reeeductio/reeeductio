# rEEEductio

rEEEductio is an absurdly simple end-to-end encrypted (EEE) data layer for building apps with secure messaging and encrypted cloud storage.

It handles all the complexity of encryption, hashing, signing, verification, key derivation, authentication, and authorization.  Developers are then free to focus on building the core features of their apps.

rEEEductio is available as open source, under a permissive license, so you can use it to build what you want.
Several components are provided, including:

* A Python [backend](./backend/) built on FastAPI
* A Python [client SDK](./new-python-sdk/) built on httpx
* A set of [command-line tools](./new-python-sdk/reeeductio/cli/) built on the Python SDK
* A TypeScript [client SDK](./typescript-sdk/) that works both in the browser and in Node

## Features

**Messaging**

Each space supports multiple independent message topics, each maintaining a blockchain-style hash chain for tamper detection. Messages are end-to-end encrypted and signed client-side before being sent to the server, so the server only ever sees opaque ciphertext.

**Cloud Storage**

rEEEductio provides content-addressable blob storage where files are encrypted client-side, identified by the SHA-256 hash of their ciphertext, and uploaded to a pluggable backend (S3/MinIO or local filesystem). Spaces also include a hierarchical key-value state store, backed by the message hash chain for full audit history, and a lightweight signed key-value data store for application data that doesn't need event-sourced history. All storage paths are governed by the same capability-based authorization system used for messaging, providing unified access control across the entire data layer.

## Security

**Encryption**

All message content, blob data, and application state are encrypted client-side using AES-GCM before leaving the device. The server operates in a true zero-knowledge mode — it stores and relays only opaque ciphertext and never has access to plaintext or key material. Each space derives its encryption keys from a single shared symmetric root using HKDF-SHA256 with domain-separated info strings, providing cryptographic isolation between messages, blobs, state, and key-value data without requiring users to manage multiple keys.

**Integrity**

Every message is individually signed with the sender's Ed25519 key and includes a SHA-256 hash computed over its space, topic, type, payload, sender, and the hash of the preceding message. This creates a per-topic hash chain that makes tampering, reordering, or deletion of messages detectable by any participant. State entries are similarly signed and timestamped, and blobs are content-addressed by the SHA-256 hash of their ciphertext, ensuring integrity at rest.

**Authentication**

Users authenticate via Ed25519 challenge-response: the server issues a random nonce, and the client signs it with its private key to prove possession without ever transmitting the key. Successful authentication yields a short-lived JWT for subsequent API calls. For optional key recovery, rEEEductio implements the OPAQUE asymmetric PAKE protocol, which allows users to set up a username and password without the server ever learning the password or being able to derive the user's private key from it.

**Authorization**

Access control is built on a capability-based system where each capability is a signed grant specifying a subject, an operation (read, create, modify, delete, or the compound write), and a path pattern with wildcards (`{self}`, `{any}`, `{...}`). Capabilities form a chain of trust rooted at the space creator, and the server validates each chain before permitting an action. Role-based access control is layered on top, with roles mapping to sets of capabilities for convenient administration. Tool accounts (limited-use API keys) receive only explicitly granted capabilities with no ambient authority, enabling use cases like invite links and bots with tightly scoped permissions.


## Core Concepts

### Spaces
Spaces are the core data structure in rEEEductio, somewhat similar to the concept of a "room" in Matrix or a "group" in Signal.  Everything happens in a Space, and each Space stands alone as its own self-contained thing. Each space has:
- A unique Ed25519 public key as its identifier.  The "root" user who created the space holds the private key.
- Zero or more non-root users, identified by their Ed25519 public keys
- A shared symmetric key for deriving encryption keys, known only to the users and not to the server
- Multiple independent *topics* for sending messages.  Messages within a topic are cryptographically linked together in a block chain for integrity verification.
- State, represented as a hierarchical key-value store and stored as messages in the special "state" topic for integrity
- Efficient key-value storage with cryptographic signatures
- Content-addressable object ("blob") storage for files and other large data.  Blobs are identified by the SHA-256 hash of their content.

### Topics
Topics are message streams within a space. Each topic maintains:
- A blockchain-style hash chain of messages (each message links to the previous via `prev_hash`)
- Independent message sequences (across topics)
- Linear ordering of messages within a topic is verified and enforced by the server

### User Accounts
Users are identified only by their public key
- Users connect to the space using only their public/private keys
- No connection to email addresses, domain names, or phone numbers
- Keys are unique per space. Having no long-term keys and no cross-space identities makes it very difficult to stalk or track a user across spaces.
- Users can optionally set up a username and password in a space to enable secure recovery of their private key. This is strictly opt-in and requires action by both the space admin and the individual user.

### State
The state for each space is a hierarchical, ordered key-value store
- State is stored as events in the `state` topic for blockchain integrity.
- State can hold:
  - **Plaintext state**: Used by the space itself - User identities, roles, capabilities, tools, topic metadata (server can read for authorization)
  - **Encrypted state**: Used by the application - User preferences, private data (server stores as opaque blobs)
- **All state entries must be signed**: Each entry includes the state path, signature, signed_by (user ID), and signed_at (timestamp)
- Data is stored as base64. Interpretation is up to the application, and format is determined by the path of the state entry, ie the "key" in the key-value store.
