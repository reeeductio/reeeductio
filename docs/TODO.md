# Documentation TODO

See [DOCS_PLAN.md](DOCS_PLAN.md) for the full analysis and rationale.

## Infrastructure

- [x] Set up MkDocs + Material theme (`pip install mkdocs-material`, create `mkdocs.yml`)
- [ ] Configure Read the Docs (or GitHub Pages) for auto-deploy
- [x] Add Mermaid diagram support to `mkdocs.yml`

## Diagrams (Mermaid)

- [x] System architecture — client ↔ server ↔ storage (`index.md`)
- [x] Data model — Space → Topics / State / Blobs / KV (`concepts/spaces.md`)
- [x] Authentication flow — challenge-response → JWT sequence diagram (`concepts/spaces.md`)
- [x] Key derivation tree — symmetric_root → message/blob/state/data keys (`concepts/spaces.md`)
- [x] Message chain — how prev_hash links messages (`concepts/topics-and-messages.md`)
- [x] Capability chain of trust — how rights flow from space creator (`concepts/access-control.md`)
- [x] OPAQUE login flow — optional password login sequence (`how-to/password-login.md`)

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

- [x] `concepts/spaces.md` — what a space is, when to use it, diagram
- [x] `concepts/topics-and-messages.md` — topics, message chains, ordering guarantees
- [x] `concepts/state-and-data.md` — event-sourced state vs. lightweight KV; when to use each
- [x] `concepts/blobs.md` — content-addressed encrypted file storage
- [x] `concepts/access-control.md` — users, roles, capabilities explained for developers (not security experts)

## How-To Guides

- [x] `how-to/create-a-space.md`
- [x] `how-to/add-users.md`
- [x] `how-to/send-messages.md`
- [x] `how-to/store-files.md`
- [x] `how-to/manage-permissions.md`
- [x] `how-to/password-login.md` — OPAQUE opt-in setup
- [x] `how-to/tool-accounts.md` — bots, invite links, scoped API keys
- [x] `how-to/self-hosting.md` — production deployment guide

## SDK Reference

- [x] `reference/python-sdk.md` — module-by-module reference with examples
- [x] `reference/typescript-sdk.md` — same for TypeScript SDK
- [x] `reference/api.md` — OpenAPI overview, link to `/docs` endpoint, explain ID format
- [x] `reference/server-config.md` — consolidate from `backend/DOCKER.md`, `backend/LOGGING.md`, `backend/ADMIN.md`

## Security Section

- [x] `security/overview.md` — simplified: what the system protects, what it doesn't
- [x] `security/threat-model.md` — in scope / out of scope; honest about audit status
- [x] `security/internals.md` — reorganize `docs-internal/` content for security-curious developers
