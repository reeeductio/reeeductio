# rEEEductio

**rEEEductio** is an end-to-end encrypted data layer that makes it simple to build apps with secure messaging and encrypted cloud storage — without becoming a cryptography expert.

!!! warning "Early-stage project"
    rEEEductio has not been independently security-audited. See the [Security](security/overview.md) section for details. Use at your own risk.

## What it does

rEEEductio handles encryption, key management, authentication, and access control so you don't have to. You get:

- **Encrypted messaging** — end-to-end encrypted message streams, organized into topics
- **Encrypted file storage** — content-addressed blob storage with client-side encryption
- **Encrypted key-value state** — a structured store for app data and configuration
- **Capability-based access control** — fine-grained, signed permissions for users, roles, and bots

The server stores only ciphertext. It never sees your data.

## How it compares

| | rEEEductio | Firebase / Supabase | Signal / Matrix |
|---|---|---|---|
| End-to-end encrypted | ✅ | ❌ | ✅ |
| Developer SDK | ✅ | ✅ | ⚠️ Limited |
| Self-hostable | ✅ | ❌ | ✅ |
| Open source | ✅ | ❌ | ✅ |
| No phone/email required | ✅ | ❌ | ❌ |

## Where to start

<div class="grid cards" markdown>

- **New here?** Start with [Running the Server](getting-started/running-the-server.md) then pick a quick start.
- **Python developer?** Jump to the [Python Quick Start](getting-started/quickstart-python.md).
- **TypeScript developer?** Jump to the [TypeScript Quick Start](getting-started/quickstart-typescript.md).
- **Just browsing?** Read [Core Concepts](concepts/spaces.md) for an overview.

</div>
