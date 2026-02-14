# Tests

Test suite for the reeeductio Python SDK.

## Running Tests

### Install test dependencies

```bash
pip install -e ".[dev]"
```

Or with uv:

```bash
uv pip install pytest pytest-asyncio
```

### Run all tests

```bash
pytest
```

### Run specific test file

```bash
pytest tests/test_key_derivation.py
```

### Run with verbose output

```bash
pytest -v
```

### Run specific test class or function

```bash
pytest tests/test_key_derivation.py::TestDomainSeparation
pytest tests/test_key_derivation.py::TestDomainSeparation::test_different_spaces_different_keys
```

## Test Organization

### `test_smoke.py`

Comprehensive smoke test covering the entire public API surface:

- **Import Validation**: All public API imports work correctly
- **Key Generation**: Ed25519 keypair generation and identifier creation
- **Identifier Types**: Type detection for user/space/tool IDs
- **Signing**: Data signing and verification
- **Hashing**: Hash computation and ID generation (message, blob)
- **Base64 Encoding**: Encoding/decoding utilities
- **Space Initialization**: Full Space client initialization with symmetric_root
- **Key Derivation**: All derived keys (message, blob, state, data) are generated and unique
- **Determinism**: Same inputs produce same keys
- **Domain Separation**: Different space_ids produce different keys
- **Validation**: Symmetric root size validation

This test runs as a single comprehensive test function that validates the basic functionality of the entire SDK.

### `test_key_derivation.py`

Comprehensive tests for HKDF key derivation:

- **TestDeriveKey**: Basic `derive_key()` function tests
  - Key length validation
  - Determinism
  - Context separation

- **TestSpaceKeyDerivation**: Space client key derivation tests
  - All keys are derived on init
  - Keys match manual derivation
  - Deterministic behavior

- **TestDomainSeparation**: Critical security tests
  - Different `space_id` → different keys (even with same root)
  - Validates domain separation implementation

- **TestSecurityProperties**: Security invariants
  - No key reuse across types (message, blob, state, data)
  - No key reuse across spaces
  - Symmetric root validation

- **TestEdgeCases**: Edge cases and error handling
  - Empty/unicode info strings
  - Special characters in space_id
  - Very long info strings

## Test Coverage

Current test coverage:

- ✅ Smoke test (public API surface)
- ✅ Key derivation (HKDF)
- ✅ Domain separation (space_id scoping)
- ✅ Security properties
- ✅ Basic crypto operations (signing, hashing, encoding)
- ⏳ Authentication (TODO)
- ⏳ Messages (TODO)
- ⏳ Blobs (TODO)
- ⏳ State (TODO)
- ⏳ KV Data (TODO)

## Writing Tests

### Test Structure

Follow pytest conventions:

```python
class TestFeature:
    """Tests for a specific feature."""

    def test_basic_behavior(self):
        """Test the basic case."""
        # Arrange
        ...

        # Act
        ...

        # Assert
        assert expected == actual
```

### Security Tests

When writing security-related tests:

1. **Be explicit** about what security property is being tested
2. **Use descriptive names** (e.g., `test_no_key_reuse_across_spaces`)
3. **Add docstrings** explaining why the test matters
4. **Test both positive and negative cases**

Example:

```python
def test_different_spaces_different_keys(self):
    """Test that different space_ids produce different keys even with same root.

    This is critical for security: prevents cross-space key reuse.
    """
    # Test implementation...
```

### Async Tests

For async code, use `pytest-asyncio`:

```python
import pytest

class TestAsyncFeature:
    @pytest.mark.asyncio
    async def test_async_operation(self):
        """Test async operation."""
        result = await some_async_function()
        assert result is not None
```

## CI/CD Integration

These tests can be integrated into CI/CD pipelines:

### GitHub Actions

```yaml
- name: Run tests
  run: |
    pip install -e ".[dev]"
    pytest
```

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
pytest --tb=short
```

## Test Data

Test data should be:

- **Generated randomly** for cryptographic tests (use `os.urandom()`)
- **Deterministic** when testing determinism (use same inputs)
- **Isolated** (no shared state between tests)

## Debugging Failed Tests

### Show more detail

```bash
pytest -vv --tb=long
```

### Stop at first failure

```bash
pytest -x
```

### Run last failed tests

```bash
pytest --lf
```

### Print output (for debugging)

```bash
pytest -s  # Show print statements
```
