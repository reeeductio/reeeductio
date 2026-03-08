# Documentation Plan

## Current State: What Exists

| Location | Content | Audience |
|---|---|---|
| `README.md` | High-level overview, core concepts, security | Partially developer-friendly |
| `docs-internal/AUTHORIZATION.md` | Authorization system design | Internal / security expert |
| `docs-internal/SECURITY.md` | Security reference | Security expert |
| `docs-internal/CHAIN_VALIDATION.md` | CAS implementation detail | Backend implementer |
| `docs-internal/EVENT_SOURCED_STATE.md` | Event sourcing internals | Backend implementer |
| `docs-internal/UNIFIED_NAMESPACE.md` | Capability path spec | Internal spec |
| `docs-internal/TYPED_IDENTIFIERS.md` | ID encoding format | Internal spec |
| `python-sdk/ARCHITECTURE.md` | SDK module breakdown | SDK contributor |
| `python-sdk/SECURITY.md` | Key derivation notes | Security expert |
| `backend/ADMIN.md` | Admin space API | Ops / server admin |
| `backend/DOCKER.md` | Docker deployment | Ops |
| `backend/LOGGING.md` | Logging config | Ops |

## Problems with Current Docs

1. **No Getting Started guide** — zero path from "I just discovered this" to "it works on my machine"
2. **No tutorials or examples** — no "send your first message" walkthrough
3. **README leads with cryptographic jargon** — terms like HKDF, Ed25519, OPAQUE, compare-and-swap appear before developers understand what they're building
4. **Concepts explained from a security POV, not a developer POV** — Spaces are described by their cryptographic properties rather than by what you *do* with them
5. **The old `docs/` folder is internal implementation notes**, not end-user documentation
6. **No TypeScript SDK documentation** beyond a TODO file
7. **No "why this vs. alternatives"** section for developers evaluating the project
8. **No diagrams** — the system has meaningful structure (key hierarchy, message chains, auth flow) that's hard to understand from prose alone

---

## Plan: Content to Write

### 1. Home / Introduction (rewrite README or use as doc site home)
- Plain-language pitch: "what problem does this solve?" (secure messaging/storage *without* managing crypto)
- Positioning relative to things developers know: Firebase/Supabase but zero-knowledge; like Signal/Matrix but as a library
- Brief feature list in developer terms (not security terms)
- Links to quick starts

### 2. Getting Started (completely new)
- **Prerequisites**: Python 3.10+ or Node/Bun, a running server
- **Python Quick Start**: Install SDK → create space → post a message → read it back (~15 lines of code)
- **TypeScript Quick Start**: Same workflow in TypeScript
- **Running the server locally**: Docker one-liner to have a server for development

### 3. Core Concepts (developer-friendly, mostly new)
Each concept explained in "what it is / what you use it for / simple example" format:
- **Spaces** — the unit of deployment; think "a project" or "an app instance"
- **Topics** — ordered message streams within a space; think "chat channels" or "event logs"
- **State** — event-sourced key-value store; think "configuration" or "member list"
- **KV Data** — simpler key-value for ephemeral app data
- **Blobs** — encrypted file storage
- **Users & Authentication** — key-based identity; what this means in practice
- **Access Control** — capabilities and roles explained without assuming familiarity with capability theory

### 4. How-To Guides (new)
Task-oriented, each a short focused page:
- Create and configure a space
- Add users to a space
- Send and receive messages
- Store and retrieve files
- Manage roles and permissions
- Set up username/password login with OPAQUE
- Create a bot/tool account (e.g., an invite link)
- Self-host the server

### 5. SDK Reference (new)
- Python SDK: module-by-module reference with examples
- TypeScript SDK: same

### 6. Server Reference (reorganize existing)
- Configuration reference (from `backend/DOCKER.md`)
- Admin API (from `backend/ADMIN.md`)
- Logging (from `backend/LOGGING.md`)

### 7. API Reference
- Link to/embed the OpenAPI spec (already exists at `/docs` when server is running)
- Explain the ID format (from `docs-internal/TYPED_IDENTIFIERS.md`, simplified)

### 8. Security Reference (reorganize existing docs-internal/)
- Move the current `docs-internal/` content here, targeted at security-conscious developers rather than implementers
- Simplified threat model and what is/isn't protected
- Honest disclosure: not audited, use at own risk

---

## Diagrams Needed

| Diagram | Format | Priority |
|---|---|---|
| System architecture (client ↔ server ↔ storage) | Box/arrow | High |
| Data model (Space → Topics/State/Blobs/KV) | Hierarchy | High |
| Authentication flow (challenge-response → JWT) | Sequence | High |
| Key derivation tree (symmetric_root → derived keys) | Tree | Medium |
| Message chain (prev_hash linking) | Chain | Medium |
| Capability chain of trust | Tree | Medium |
| OPAQUE login flow | Sequence | Low |

All diagrams should be authored in **Mermaid** (renders natively in MkDocs Material and on GitHub).

---

## Target Directory Structure

```
docs/
├── index.md                        # Home / introduction
├── getting-started/
│   ├── quickstart-python.md
│   ├── quickstart-typescript.md
│   └── running-the-server.md
├── concepts/
│   ├── spaces.md
│   ├── topics-and-messages.md
│   ├── state-and-data.md
│   ├── blobs.md
│   └── access-control.md
├── how-to/
│   ├── create-a-space.md
│   ├── add-users.md
│   ├── send-messages.md
│   ├── store-files.md
│   ├── manage-permissions.md
│   ├── password-login.md
│   ├── tool-accounts.md
│   └── self-hosting.md
├── reference/
│   ├── python-sdk.md
│   ├── typescript-sdk.md
│   ├── server-config.md
│   └── api.md
└── security/
    ├── overview.md
    ├── threat-model.md
    └── internals.md
```

---

## Documentation Engine Recommendation

### Option A: MkDocs + Material theme (recommended)
- Markdown-based, minimal config, easy to host on **Read the Docs** or GitHub Pages
- Material theme is the most widely used, looks professional
- Supports Mermaid diagrams natively via the `pymdownx.superfences` extension
- `mkdocs.yml` config is simple; no build toolchain required
- **Best if**: you want lowest friction to get running

### Option B: Docusaurus
- React/MDX-based, very polished, used by major open source projects (React, Jest, Babel)
- Excellent versioning, search, i18n support
- Better suited for multi-SDK projects (sidebar can organize Python vs TypeScript)
- **Best if**: you plan to invest more in docs long-term and want a best-in-class developer site

**Verdict: start with MkDocs + Material.** Can migrate to Docusaurus later if the project grows.

### MkDocs Setup

```bash
pip install mkdocs-material
mkdocs new .   # creates mkdocs.yml and docs/index.md
mkdocs serve   # local preview at http://127.0.0.1:8000
```

Minimal `mkdocs.yml`:
```yaml
site_name: rEEEductio
theme:
  name: material
  features:
    - navigation.tabs
    - navigation.sections
markdown_extensions:
  - pymdownx.superfences:
      custom_fences:
        - name: mermaid
          class: mermaid
          format: !!python/name:pymdownx.superfences.fence_code_format
  - pymdownx.highlight
  - admonition
```

---

## Suggested Priority Order

1. **MkDocs setup** — scaffold the site so pages have a home as we write them
2. **Getting Started / Quick Start** — biggest gap, highest impact for developer adoption
3. **Architecture diagram** — one picture replaces 3 pages of prose
4. **Concepts guide** — re-explains what's in README but for developers, not cryptographers
5. **How-to guides** — practical task-oriented content
6. **SDK reference** — detailed, can be incremental
7. **Reorganize `docs-internal/`** content into the Security section
