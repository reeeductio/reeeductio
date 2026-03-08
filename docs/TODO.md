# Documentation TODO

See [DOCS_PLAN.md](DOCS_PLAN.md) for the full analysis and rationale.

## Infrastructure

- [x] Set up MkDocs + Material theme (`pip install mkdocs-material`, create `mkdocs.yml`)
- [ ] Configure Read the Docs (or GitHub Pages) for auto-deploy
- [x] Add Mermaid diagram support to `mkdocs.yml`

## Diagrams (Mermaid)

- [ ] System architecture — client ↔ server ↔ storage
- [ ] Data model — Space → Topics / State / Blobs / KV
- [ ] Authentication flow — challenge-response → JWT sequence diagram
- [ ] Key derivation tree — symmetric_root → message/blob/state/data keys
- [ ] Message chain — how prev_hash links messages
- [ ] Capability chain of trust — how rights flow from space creator
- [ ] OPAQUE login flow — optional password login sequence

## Home / Introduction

- [x] `docs/index.md` — plain-language pitch, comparison table, quick links (first draft done)
- [ ] Flesh out "Why rEEEductio?" — positioning vs. Firebase/Supabase, Signal/Matrix

## Getting Started

- [x] `getting-started/running-the-server.md` — Docker Compose, GHCR image, dev config
- [x] `getting-started/quickstart-python.md` — install → create space → post message → read it back
- [x] `getting-started/quickstart-typescript.md` — same flow in TypeScript (Node + browser)

## SDK Changes Made While Writing Docs

- [x] Fixed stale `C` space ID prefix → `S` in `python-sdk/ARCHITECTURE.md`, `docs-internal/TYPED_IDENTIFIERS.md`, `typescript-sdk/src/index.ts`
- [x] Added `Space.decryptMessageData(msg, topicId)` to TypeScript SDK (`client.ts`) to match Python SDK parity

## Core Concepts

- [ ] `concepts/spaces.md` — what a space is, when to use it, diagram
- [ ] `concepts/topics-and-messages.md` — topics, message chains, ordering guarantees
- [ ] `concepts/state-and-data.md` — event-sourced state vs. lightweight KV; when to use each
- [ ] `concepts/blobs.md` — content-addressed encrypted file storage
- [ ] `concepts/access-control.md` — users, roles, capabilities explained for developers (not security experts)

## How-To Guides

- [ ] `how-to/create-a-space.md`
- [ ] `how-to/add-users.md`
- [ ] `how-to/send-messages.md`
- [ ] `how-to/store-files.md`
- [ ] `how-to/manage-permissions.md`
- [ ] `how-to/password-login.md` — OPAQUE opt-in setup
- [ ] `how-to/tool-accounts.md` — bots, invite links, scoped API keys
- [ ] `how-to/self-hosting.md` — production deployment guide

## SDK Reference

- [ ] `reference/python-sdk.md` — module-by-module reference with examples
- [ ] `reference/typescript-sdk.md` — same for TypeScript SDK
- [ ] `reference/api.md` — OpenAPI overview, link to `/docs` endpoint, explain ID format
- [ ] `reference/server-config.md` — consolidate from `backend/DOCKER.md`, `backend/LOGGING.md`, `backend/ADMIN.md`

## Security Section

- [ ] `security/overview.md` — simplified: what the system protects, what it doesn't
- [ ] `security/threat-model.md` — in scope / out of scope; honest about audit status
- [ ] `security/internals.md` — reorganize `docs-internal/` content for security-curious developers
