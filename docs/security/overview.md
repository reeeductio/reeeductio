# Security Overview

!!! warning "Not independently audited"
    rEEEductio has been designed with security in mind but has not been independently security-audited. Use it at your own risk for anything sensitive.

## What rEEEductio protects

rEEEductio is built around one core principle: **the server should not be trusted with your data**. Every piece of user content is encrypted before it leaves the client. The server stores only ciphertext and the bare minimum plaintext state required for authentication and authorization.

| Property | Mechanism |
|----------|-----------|
| **Confidentiality** | AES-256-GCM encryption, keys derived client-side with HKDF |
| **Message integrity** | SHA-256 hash chains — any tampering breaks the chain |
| **Sender authenticity** | Ed25519 signatures on every message |
| **Access control** | Capability-based, stored in signed state entries |
| **Authentication** | Ed25519 challenge-response → short-lived JWT |
| **Password login** | OPAQUE aPAKE — password never reaches the server |

## Cryptographic primitives

| Primitive | Algorithm | Use |
|-----------|-----------|-----|
| Signing | Ed25519 | Identity, message signatures, capability grants |
| Key derivation | HKDF-SHA256 | Deriving per-topic, per-space encryption keys |
| Symmetric encryption | AES-256-GCM | Data at rest on the server |
| Hashing | SHA-256 | Message IDs, blob IDs, chain integrity |
| Password auth | OPAQUE | Optional password-based credential recovery |

## What the server can and cannot do

| Action | Can the server? |
|--------|----------------|
| Read encrypted message content | ❌ No — stored as AES-GCM ciphertext |
| Read encrypted app state | ❌ No — also encrypted |
| Read plaintext auth state | ✅ Yes — required for authentication and authorization |
| Read encrypted blob content | ❌ No — also encrypted |
| Forge a message | ❌ No — messages require a valid Ed25519 signature |
| Reorder messages in a topic | ⚠️ Partially — the server controls `server_timestamp`, but clients verify the `prev_hash` chain |
| Drop messages | ⚠️ Yes — a malicious server can withhold messages, but clients detect gaps in the chain |
| Replay old messages | ⚠️ Partially — timestamps and chain links make this detectable |
| Deny access to data | ✅ Yes — the server decides whether to respond to requests |
| Learn who communicates with whom | ⚠️ Partially — the server sees which user IDs authenticate to each space and when, but user identities cannot be linked across spaces |

## Data store security notes

Not all storage primitives have identical security guarantees:

**Topics (message chains):** Strongest guarantee. Every message is signed and chained. A server that substitutes or reorders messages will be detected by chain validation.

**State:** Strong guarantee. State is backed by the message chain, so the full history is verifiable. The current value is the latest signed write.

**Blobs:** Content-addressed. The blob ID is derived from the encrypted content hash, so the server cannot substitute different content for the same ID without detection.

**Data (KV store):** Weaker. Each entry is signed, but there is no chain. A compromised server can replay an older value for a key without detection by a client that hasn't previously cached the newer value. For security-sensitive metadata, use **State** instead of Data.

## Known limitations

- **No forward secrecy**: If the `symmetricRoot` is compromised, all past and future messages in the space can be decrypted. Key rotation requires migrating to a new space.
- **Server sees metadata**: The server knows which space IDs exist, which user IDs authenticate, and when. It does not see content, but it sees traffic patterns.
- **Server can withhold messages**: There is no cryptographic proof that the server delivered all messages. A malicious server can withhold or delay them; clients can detect gaps but cannot force delivery.
- **No independent audit**: This project has not been reviewed by an independent security firm.

## Related pages

- [Threat Model](threat-model.md) — what attacks are in scope and out of scope
- [Security Internals](internals.md) — detailed cryptographic design for security-curious developers
