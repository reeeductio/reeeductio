# Threat Model

This page describes what rEEEductio is designed to protect against, what it explicitly does not protect against, and the honest status of its security review.

## Principals

| Principal | Description |
|-----------|-------------|
| **Space creator** | Holds the space's Ed25519 private key; has full implicit access to the space |
| **Space member** | A user or tool with explicitly granted capabilities |
| **Server operator** | Runs the rEEEductio server and has access to the database and object store |
| **Network attacker** | Can observe or intercept traffic between client and server |
| **Passive third party** | Can read data that leaks outside the system (e.g. backups, logs) |

## In scope — threats we aim to prevent

### Honest-but-curious server

A server that follows the protocol correctly but reads everything it can.

- **Message content**: Server sees only AES-GCM ciphertext. Without the `symmetricRoot`, content cannot be decrypted.
- **State content**: Same — encrypted at rest.
- **Blob content**: Encrypted with a per-blob DEK. The server stores ciphertext only.
- **Forgery**: The server cannot forge messages or state entries because it doesn't have users' Ed25519 private keys.

### Message tampering

- Each message includes an Ed25519 signature from its sender. A modified message will have an invalid signature.
- Each message includes `prev_hash` — the SHA-256 hash of the previous message. Inserting, deleting, or reordering messages breaks the chain and is detected by clients.

### Unauthorized access

- Non-members cannot authenticate (the challenge-response requires an Ed25519 private key that only space members hold).
- Members are limited to their granted capabilities; the server enforces these against the signed capability entries in the space's state.

### Privilege escalation through tool creation

- A tool cannot be granted capabilities its creator doesn't have. The server enforces that the grantor's permissions are a superset of what they are granting.
- Once created and granted powers, a tool *can* grant capabilities and roles that it itself does not have. Be very careful when creating tools and when sharing their private keys.

### Password interception (OPAQUE)

- When OPAQUE is enabled, passwords are never transmitted to the server. The OPAQUE protocol is designed so the server cannot recover the password even with a full database dump.

## Partially in scope — detectable but not fully preventable

### Message withholding

A malicious server can refuse to deliver messages. Clients cannot force delivery. However:
- The hash chain means clients that do receive messages can verify they form a contiguous, unforked sequence.
- A gap between the last cached message and new messages is detectable.

### Message replay (state and data)

- **State**: The full history is in the chain; clients can detect if the server presents an older state as current, because newer signed entries would be missing.
- **Data (KV)**: A compromised server *can* silently replay an old value for a key to a client that has never seen the newer value. This is a known weakness — use State for security-sensitive data.

### Metadata

The server learns: which space IDs exist, which user IDs authenticate, when they connect, and approximately how much data is in each topic. This is traffic analysis, not content analysis, but it is real information leakage.

## Out of scope — threats we do not aim to prevent

### Compromised client

If an attacker controls the client device, they can read plaintext directly. No server-side design can prevent this.

### Compromised `symmetricRoot`

The `symmetricRoot` is the root encryption secret. Anyone who has it can decrypt all content in the space — past and future. Protecting it is the user's responsibility (use OS keychain, secrets manager, OPAQUE for recovery).

### Denial of service

The server can be taken offline or overloaded. rEEEductio has no built-in DoS mitigation.

### Physical access to the server

An attacker with physical access to the server hardware or database files sees encrypted content. But combined with the `symmetricRoot` (from a captured client), they could decrypt everything. Protect the server like any other sensitive infrastructure.

### Anonymity

rEEEductio does not hide who is communicating with whom. For anonymity, route traffic through Tor or a VPN before reaching the rEEEductio server.

### Supply chain attacks

rEEEductio depends on third-party libraries (`@noble/ed25519`, `@noble/ciphers`, `@noble/hashes`, `@serenity-kit/opaque`, etc.). Compromised dependencies could undermine all security guarantees. Use dependency pinning and integrity checking in production.

## Audit status

| Area | Status |
|------|--------|
| Cryptographic design | Self-reviewed; not independently audited |
| Implementation | Self-reviewed; no formal code review |
| Dependencies | Reputable libraries; no formal audit of dependencies |
| Penetration testing | None |

**Recommendation**: Do not rely on rEEEductio for life-critical or legally regulated data without an independent security review.

## Related pages

- [Security Overview](overview.md) — what the system protects
- [Security Internals](internals.md) — cryptographic design details
