"""
Shared pytest fixtures for backend tests
"""
import sys
import os
import tempfile
import shutil
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sqlite_message_store import SqliteMessageStore
from sqlite_data_store import SqliteDataStore
from crypto import CryptoUtils
from authorization import AuthorizationEngine
from identifiers import encode_space_id, encode_user_id
from filesystem_blob_store import FilesystemBlobStore
from sqlite_blob_store import SqliteBlobStore


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_addoption(parser):
    """Add custom command-line options for pytest"""
    parser.addoption(
        "--firestore-emulator",
        action="store",
        default="auto",
        help="Firestore emulator mode: auto|testcontainers|external"
    )


@pytest.fixture
def temp_db_path():
    """Create a temporary database file and clean it up after the test"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name

    yield db_path

    # Cleanup
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def temp_blob_dir():
    """Create a temporary directory for blob storage and clean it up after the test"""
    blob_dir = tempfile.mkdtemp()

    yield blob_dir

    # Cleanup
    shutil.rmtree(blob_dir)


@pytest.fixture
def message_store(temp_db_path):
    """Create a SqliteMessageStore instance with temporary storage"""
    return SqliteMessageStore(temp_db_path)


@pytest.fixture
def state_store(temp_db_path):
    """Create a SqliteDataStore instance with temporary storage"""
    return SqliteDataStore(temp_db_path)

@pytest.fixture
def sqlite_state_store(temp_db_path):
    """Create a SqliteDataStore instance with temporary storage"""
    return SqliteDataStore(temp_db_path)

@pytest.fixture
def crypto():
    """Create a CryptoUtils instance"""
    return CryptoUtils()


@pytest.fixture
def authz(state_store, crypto):
    """Create an AuthorizationEngine instance"""
    return AuthorizationEngine(state_store, crypto)


@pytest.fixture
def fs_blob_store(temp_blob_dir):
    """Create a FilesystemBlobStore instance with temporary storage"""
    return FilesystemBlobStore(temp_blob_dir)


@pytest.fixture
def db_blob_store(temp_db_path):
    """Create a SqliteBlobStore instance"""
    return SqliteBlobStore(temp_db_path)


@pytest.fixture(params=['filesystem', 'sqlite'])
def any_blob_store(request, temp_blob_dir, temp_db_path):
    """
    Parametrized fixture that provides all blob store implementations.
    Tests using this fixture will run once for each blob store type.
    """
    if request.param == 'filesystem':
        return FilesystemBlobStore(temp_blob_dir)
    elif request.param == 'sqlite':
        return SqliteBlobStore(temp_db_path)
    else:
        raise ValueError(f"Unknown blob store type: {request.param}")


@pytest.fixture
def admin_keypair():
    """Generate an admin keypair for testing"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()
    user_id = encode_user_id(public_key_bytes)

    return {
        'private': private_key,
        'public': public_key,
        'public_bytes': public_key_bytes,
        'user_id': user_id,
        'space_id': encode_space_id(public_key_bytes),
        'id': user_id
    }


@pytest.fixture
def user_keypair():
    """Generate a user keypair for testing"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()
    user_id = encode_user_id(public_key_bytes)

    return {
        'private': private_key,
        'public': public_key,
        'public_bytes': public_key_bytes,
        'user_id': user_id,
        'id': user_id
    }


def sign_state_entry(
    space_id: str,
    path: str,
    data: str,
    signer_private_key,
    signer_user_id: str,
    signed_at: int
) -> str:
    """
    Convenience function to create a signed state entry for tests.

    Args:
        space_id: Space identifier
        path: State path
        data: Base64-encoded state data
        signer_private_key: Ed25519 private key of signer
        signer_user_id: User ID of signer (must match private key's public key)
        signed_at: Unix timestamp in milliseconds when entry was signed

    Returns:
        Dictionary with keys: data, signature, signed_by, signed_at

    Raises:
        ValueError: If signer_user_id doesn't match the private key's public key
    """
    from identifiers import extract_public_key

    # Verify that signer_user_id matches the private key's public key
    expected_public_key_bytes = signer_private_key.public_key().public_bytes_raw()
    actual_public_key_bytes = extract_public_key(signer_user_id)

    if expected_public_key_bytes != actual_public_key_bytes:
        raise ValueError(
            f"signer_user_id ({signer_user_id}) does not match the provided private key's public key"
        )

    # Create signature message: space_id|path|data|signed_at
    message = f"{space_id}|{path}|{data}|{signed_at}".encode('utf-8')
    signature_bytes = signer_private_key.sign(message)
    signature = base64.b64encode(signature_bytes).decode('utf-8')

    return signature


def sign_and_store_state(
    state_store,
    space_id: str,
    path: str,
    contents: object,
    signer_private_key,
    signer_user_id: str,
    signed_at: int
) -> None:
    """
    Convenience function to create a signed state entry and store it in the state store.

    This combines create_signed_state_entry() and state_store.set_state() into a single call.

    Args:
        state_store: DataStore instance to store the entry in
        space_id: Space identifier
        path: State path
        contents: JSON-compatible object
        signer_private_key: Ed25519 private key of signer
        signer_user_id: User ID of signer (must match private key's public key)
        signed_at: Unix timestamp in milliseconds when entry was signed

    Raises:
        ValueError: If signer_user_id doesn't match the private key's public key
    """
    data_b64 = base64.b64encode(json.dumps(contents).encode()).decode()

    signature = sign_state_entry(
        space_id,
        path,
        data_b64,
        signer_private_key,
        signer_user_id,
        signed_at
    )

    print(f"Saving signed state in {path}")

    state_store.set_state(
        space_id,
        path,
        data_b64,
        signature,
        signer_user_id,
        signed_at
    )

def set_space_state(space, path, contents, token, keypair):
        """
        Convenience function to sign and set state in a Space
        """
        data = CryptoUtils.base64_encode_object(contents)
        timestamp = int(time.time() * 1000)
        signature = sign_state_entry(space.space_id, path, data, keypair['private'], keypair['id'], timestamp)
        space.set_state(path, data, token, signature, keypair['id'], timestamp)

# ============================================================================
# Firestore Emulator Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def firestore_emulator(request):
    """
    Smart Firestore emulator fixture that adapts to environment.

    Modes:
    - auto: Use testcontainers if available, else external (default)
    - testcontainers: Spin up container automatically
    - external: Use existing emulator at localhost:8080

    Usage:
        # Automatic (tries testcontainers, falls back to external)
        pytest backend/tests/test_firestore_stores.py

        # Use docker-compose emulator
        docker-compose up -d firestore-emulator
        pytest --firestore-emulator=external

        # Force testcontainers
        pytest --firestore-emulator=testcontainers
    """
    mode = request.config.getoption("--firestore-emulator")

    if mode == "external":
        # For local dev with docker-compose
        os.environ['FIRESTORE_EMULATOR_HOST'] = 'localhost:8080'
        os.environ['GCLOUD_PROJECT'] = 'test-project'
        yield
        return

    # Try testcontainers first (for CI and auto mode)
    if mode in ("auto", "testcontainers"):
        try:
            from testcontainers.core.container import DockerContainer
            import time

            # Use generic container with Firestore emulator image
            container = DockerContainer("gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators")
            container.with_command("gcloud beta emulators firestore start --host-port=0.0.0.0:8080")
            container.with_exposed_ports(8080)

            container.start()

            # Get the mapped port and set environment variables
            port = container.get_exposed_port(8080)
            os.environ['FIRESTORE_EMULATOR_HOST'] = f'localhost:{port}'
            os.environ['GCLOUD_PROJECT'] = 'test-project'

            # Wait for emulator to be ready
            time.sleep(3)

            yield container

            container.stop()
            return

        except ImportError:
            if mode == "testcontainers":
                pytest.skip("testcontainers not installed (pip install testcontainers)")
            # Fall through to external mode for 'auto'
        except Exception as e:
            if mode == "testcontainers":
                pytest.skip(f"Failed to start Firestore container: {e}")
            # Fall through to external mode for 'auto'

    # Fallback to external emulator (for auto mode when testcontainers fails)
    if os.environ.get('FIRESTORE_EMULATOR_HOST'):
        # Assume external emulator is running
        os.environ['GCLOUD_PROJECT'] = 'test-project'
        yield
    else:
        pytest.skip(
            "Firestore emulator not available. "
            "Run 'docker-compose up -d firestore-emulator' "
            "or install testcontainers: pip install testcontainers[google]"
        )


def _clear_firestore_data(project_id: str = 'test-project'):
    """Helper to delete all Firestore data"""
    from google.cloud import firestore
    import time

    client = firestore.Client(project=project_id)

    # Delete the main 'spaces' collection which contains all our data
    # as subcollections (spaces/{id}/state and spaces/{id}/topics/{id}/messages)
    spaces_ref = client.collection('spaces')
    _delete_collection(spaces_ref, batch_size=100)

    # Give the emulator time to process deletions
    # (Firestore emulator processes deletes asynchronously)
    time.sleep(1.0)


def _delete_collection(coll_ref, batch_size: int = 100):
    """Recursively delete all documents in a collection"""
    docs = coll_ref.limit(batch_size).stream()
    deleted = 0

    for doc in docs:
        # Delete subcollections first
        for subcollection in doc.reference.collections():
            _delete_collection(subcollection, batch_size)

        # Delete the document
        doc.reference.delete()
        deleted += 1

    # Continue if there might be more documents
    if deleted >= batch_size:
        return _delete_collection(coll_ref, batch_size)


@pytest.fixture
def unique_space_id(request):
    """
    Generate a unique space ID for each test to avoid conflicts.

    Uses the test name to ensure uniqueness.
    """
    return f"test-{request.node.name}"


@pytest.fixture
def firestore_state_store(firestore_emulator):
    """
    Get FirestoreDataStore for testing.

    Note: Use the unique_space_id fixture in your tests to avoid
    conflicts between tests when the emulator cleanup is slow.
    """
    from firestore_data_store import FirestoreDataStore

    store = FirestoreDataStore(project_id='test-project')

    yield store

    # Cleanup after test (best effort - may not complete before next test)
    _clear_firestore_data('test-project')


@pytest.fixture
def firestore_message_store(firestore_emulator):
    """
    Get FirestoreMessageStore for testing.

    Note: Use the unique_space_id fixture in your tests to avoid
    conflicts between tests when the emulator cleanup is slow.
    """
    from firestore_message_store import FirestoreMessageStore

    store = FirestoreMessageStore(project_id='test-project')

    yield store

    # Cleanup after test (best effort - may not complete before next test)
    _clear_firestore_data('test-project')
