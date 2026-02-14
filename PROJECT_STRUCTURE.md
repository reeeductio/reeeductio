# rEEEductio: Absurdly Simple Encrypted Spaces - Project Structure

## Files Overview

```
reeeductio/
│
├── docs/                      # Design documentation
│
├── backend/                   # Backend server implementation
│   └── tests/                 # Test suite
│       └── e2e/                      # End-to-end tests
│
├── python-sdk/                # Python client SDK
│   ├── reeeductio/            # SDK package
│   │   └── cli/               # CLI tool (reeeductio-admin)
│   ├── examples/              # Usage examples
│   └── tests/                 # SDK tests
│
├── typescript-sdk/            # TypeScript/JavaScript client SDK
│   ├── src/                   # Source code
│   │   └── __tests__/         # Unit tests
│   │       └── e2e/                  # End-to-end tests
│   │
│   └── dist/                  # Built output (generated)
│
└── ideas/                     # Design ideas and proposals
```

## Quick Start

### 1. Install Dependencies
```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment and install dependencies
uv venv
uv pip install -e .
```

### 2. Run Tests
```bash
# Backend tests
uv run pytest
uv run pytest backend/tests/test_rbac.py

# Python SDK tests
cd python-sdk && uv run pytest

# TypeScript SDK tests
cd typescript-sdk && npm test
```

### 3. Start Server
```bash
.venv/bin/python backend/main.py
```

Or use the convenience script:
```bash
./start.sh
```

### 4. Access API Documentation
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## File Descriptions

### Core Backend Files

**backend/main.py**
- FastAPI application entry point
- HTTP endpoint definitions
- JWT authentication middleware
- Request/response validation

**backend/space.py**
- Space management logic
- State and message operations
- Authentication (challenge/verify/JWT)
- Authorization checks via AuthorizationEngine

**backend/space_manager.py**
- Multi-space lifecycle management
- Space creation and lookup

**backend/admin_space.py**
- Admin space operations and bootstrapping

**backend/config.py**
- Server configuration loading (YAML-based)

**backend/crypto.py**
- Ed25519 signature verification
- SHA256 hash computation
- Message and blob ID generation
- Base64 encoding/decoding utilities

**backend/authorization.py**
- Capability-based access control with RBAC
- Role management and validation
- Tool authorization and use limits
- Path pattern matching via PathValidator
- Permission checking (read/create/write)
- Capability subset validation
- Privilege escalation prevention

**backend/path_validation.py**
- Path wildcard pattern matching
- Supports {any}, {self}, {other}, {...} wildcards
- Used by authorization engine

**backend/identifiers.py**
- Typed identifier encoding/decoding
- Supports Space (C_), User (U_), Tool (T_), Message (M_), Blob (B_)
- 264-bit format (44-char URL-safe base64)
- Type validation

**backend/exceptions.py**
- Custom exception types for the backend

**backend/logging_config.py**
- Structured logging configuration

**backend/lru_cache.py**
- LRU cache for performance optimization

### Storage Layer

**Data Storage**
- `data_store.py` - DataStore interface
- `sql_data_store.py` - SQL DataStore base implementation
- `sqlite_data_store.py` - SQLite DataStore implementation
- `firestore_data_store.py` - Firestore DataStore implementation
- `event_sourced_state_store.py` - Event-sourced state store

**Message Storage**
- `message_store.py` - MessageStore interface
- `sql_message_store.py` - SQL MessageStore base implementation
- `sqlite_message_store.py` - SQLite MessageStore implementation
- `firestore_message_store.py` - Firestore MessageStore implementation
- Hash chain validation

**Blob Storage**
- `blob_store.py` - BlobStore interface
- `filesystem_blob_store.py` - Filesystem implementation
- `sqlite_blob_store.py` - SQLite implementation
- `s3_blob_store.py` - S3 implementation
- Content-addressed storage

### Python SDK (`python-sdk/`)

The Python SDK provides a high-level client library for interacting with rEEEductio servers.

**Core Modules**
- `client.py` - HTTP client for server API calls
- `auth.py` - Authentication workflows (challenge/verify/JWT)
- `crypto.py` - Client-side Ed25519 signing, key generation
- `state.py` - State read/write operations
- `messages.py` - Message posting and retrieval
- `blobs.py` - Blob upload and download
- `kvdata.py` - Key-value data operations
- `models.py` - Pydantic data models
- `exceptions.py` - SDK-specific exception types
- `opaque.py` - OPAQUE password-authenticated key exchange
- `local_store.py` - Local credential and key storage

**CLI Tool (`reeeductio-admin`)**
- `cli/main.py` - CLI entry point
- `cli/commands/` - Subcommands for auth, blob, key, space, tool, and user management

### TypeScript SDK (`typescript-sdk/`)

The TypeScript SDK provides a client library for Node.js and browser environments.

**Core Modules**
- `client.ts` - HTTP client for server API calls
- `auth.ts` - Authentication workflows (challenge/verify/JWT)
- `crypto.ts` - Client-side Ed25519 signing, key generation
- `state.ts` - State read/write operations
- `messages.ts` - Message posting and retrieval
- `blobs.ts` - Blob upload and download
- `kvdata.ts` - Key-value data operations
- `types.ts` - TypeScript type definitions
- `exceptions.ts` - SDK-specific exception types
- `opaque.ts` - OPAQUE password-authenticated key exchange
- `local_store.ts` - Local credential/key storage (Node.js filesystem)
- `local_store_idb.ts` - Local storage using IndexedDB (browser)
- `debug.ts` - Debug logging utilities

### Configuration Files

**openapi.yaml**
- Complete API specification
- Request/response schemas
- Authentication schemes
- Example payloads
- Can be imported into Postman, Insomnia, etc.

**pyproject.toml**
- Project metadata and build configuration
- FastAPI and Uvicorn (web framework)
- Pydantic (data validation)
- PyJWT (JWT tokens)
- Cryptography (Ed25519 signatures)

### Documentation

**README.md** - Project overview, architecture, and setup
**API.md** - API endpoint documentation
**SECURITY.md** - Security model and threat analysis
**docs/** - Detailed design documents (authorization, chain validation, event-sourced state, typed identifiers, unified namespace)

## Development Workflow

### 1. Modify API
Edit `openapi.yaml` first to define the contract, then update `backend/main.py` to implement it.

### 2. Add Features
- Add storage methods in appropriate store implementation
- Add crypto operations in `backend/crypto.py`
- Add authorization logic in `backend/authorization.py`
- Add path validation patterns in `backend/path_validation.py`
- Wire everything together in `backend/space.py` and `backend/main.py`
- Update SDKs to support new features

### 3. Test
- Backend tests: `uv run pytest`
- Python SDK tests: `cd python-sdk && uv run pytest`
- TypeScript SDK tests: `cd typescript-sdk && npm test`
- E2E tests: `cd typescript-sdk && npx vitest --config vitest.e2e.config.ts`
- Run with coverage: `uv run pytest --cov=backend --cov-report=html`

### 4. Document
- Update README.md with new features
- Update API.md for endpoint changes
- Add examples to SDK `examples/` directories
