# Backend Tests

This directory contains pytest-based tests for the E2EE messaging system backend.

## Running Tests

From the project root:

```bash
# Run all tests
uv run pytest

# Run tests in parallel (faster)
uv run pytest -n auto

# Run specific test file
uv run pytest backend/tests/test_crypto.py

# Run specific test function
uv run pytest backend/tests/test_crypto.py::test_signature_verification

# Run with extra verbosity
uv run pytest -vv
```

From the backend directory:

```bash
cd backend

# Run all tests
uv run pytest tests/

# Run tests in parallel
uv run pytest tests/ -n auto
```

## Test Structure

Tests are organized by functional area:

- `test_database.py` - Database and state storage operations
- `test_crypto.py` - Cryptographic operations (signing, hashing, encoding)
- `test_authorization.py` - Authorization engine and capability checks
- `test_blob_storage.py` - Blob storage backends (filesystem and database)
- `test_identifiers.py` - Typed identifier encoding/decoding
- `test_integration.py` - End-to-end workflows

## Fixtures

Common test fixtures are defined in `conftest.py`:

- `temp_db_path` - Temporary database file (auto-cleanup)
- `temp_blob_dir` - Temporary directory for blob storage (auto-cleanup)
- `db` - Database instance
- `state_store` - State store instance
- `crypto` - CryptoUtils instance
- `authz` - AuthorizationEngine instance
- `fs_blob_store` - Filesystem blob store instance
- `db_blob_store` - Database blob store instance
- `admin_keypair` - Admin keypair with channel_id
- `user_keypair` - User keypair

## Test Coverage

Run with coverage reporting:

```bash
# Install coverage tool
uv pip install pytest-cov

# Run with coverage
uv run pytest --cov=backend --cov-report=html

# View HTML report
open htmlcov/index.html
```
