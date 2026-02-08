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
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sqlite_message_store import SqliteMessageStore
from event_sourced_state_store import EventSourcedStateStore
from sqlite_data_store import SqliteDataStore
from crypto import CryptoUtils
from authorization import AuthorizationEngine
from identifiers import encode_space_id, encode_user_id
from filesystem_blob_store import FilesystemBlobStore
from sqlite_blob_store import SqliteBlobStore
from space import Space
from typing import Any, Dict


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
    parser.addoption(
        "--s3-emulator",
        action="store",
        default="auto",
        help="S3 emulator mode: auto|testcontainers|external (external uses env vars for real S3)"
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

#region Utils

@pytest.fixture
def crypto():
    """Create a CryptoUtils instance"""
    return CryptoUtils()


@pytest.fixture
def authz(state_store, crypto):
    """Create an AuthorizationEngine instance"""
    return AuthorizationEngine(state_store, crypto)


#region Stores

@pytest.fixture
def message_store(temp_db_path):
    """Create a SqliteMessageStore instance with temporary storage"""
    return SqliteMessageStore(temp_db_path)

@pytest.fixture
def state_store(message_store):
    """Create an EventSourcedStateStore from the message store"""
    return EventSourcedStateStore(message_store)

@pytest.fixture
def data_store(temp_db_path):
    """Create a SqliteDataStore instance with temporary storage"""
    return SqliteDataStore(temp_db_path)


@pytest.fixture
def sqlite_data_store(temp_db_path):
    """Create a SqliteDataStore instance with temporary storage"""
    return SqliteDataStore(temp_db_path)


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


#region Keypairs

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

#region Spaces

@pytest.fixture
def unique_admin_keypair(request):
    """
    Generate a unique admin keypair for each test to avoid conflicts.

    Uses the test name to ensure uniqueness by hashing it and deriving
    an ed25519 keypair, then encoding the space ID from the public key.
    """
    msg_to_hash = f"test-{request.node.name}"
    hash_bytes = CryptoUtils.sha256_hash_str(msg_to_hash)

    # Derive an ed25519 private key from the hash (use first 32 bytes)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(hash_bytes[:32])
    
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
def unique_space_id(unique_admin_keypair):
    """
    Generate a unique space ID for each test to avoid conflicts.
    """
    return unique_admin_keypair['space_id']

@pytest.fixture
def unique_space(unique_admin_keypair, message_store, data_store):
    space_id = unique_admin_keypair['space_id']
    secret = base64.b64encode(CryptoUtils.sha256_hash_str("test secret")).decode('utf-8')
    space = Space(space_id, message_store, data_store, None, secret)
    return space


############################################################
#region Helper Functions
############################################################

def sign_data_entry(
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


def sign_and_store_data(
    data_store,
    space_id: str,
    path: str,
    contents: object,
    signer_private_key,
    signer_user_id: str,
    signed_at: int
) -> None:
    """
    Convenience function to create a signed data entry and store it in the data store.

    This combines create_signed_data_entry() and data_store.set_data() into a single call.

    Args:
        data_store: DataStore instance to store the entry in
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

    signature = sign_data_entry(
        space_id,
        path,
        data_b64,
        signer_private_key,
        signer_user_id,
        signed_at
    )

    print(f"Saving signed data in {path}")

    data_store.set_data(
        space_id,
        path,
        data_b64,
        signature,
        signer_user_id,
        signed_at
    )

def set_space_state(space, path, contents, token, keypair):
        """
        Convenience function to sign and set state in a Space using message format.

        Handles calling the async set_state method from sync context.
        """
        import asyncio
        from crypto import CryptoUtils
        crypto = CryptoUtils()

        data = CryptoUtils.base64_encode_object(contents)

        # Get current chain head for prev_hash
        head = space.message_store.get_chain_head(space.space_id, "state")
        prev_hash = head["message_hash"] if head else None

        # Compute message hash
        message_hash = crypto.compute_message_hash(
            space.space_id,
            "state",
            path,
            prev_hash,
            data,
            keypair['id']
        )

        # Sign the message hash
        # Decode the typed identifier and convert to bytes for signing
        from identifiers import decode_identifier
        message_tid = decode_identifier(message_hash)
        message_bytes = message_tid.to_bytes()
        signature_bytes = keypair['private'].sign(message_bytes)
        signature = crypto.base64_encode(signature_bytes)
        print(f"Saving state at {path} with signature {signature}")

        # Call async function from sync context
        return asyncio.run(space.set_state(path, prev_hash, data, message_hash, signature, token))


def authenticate_with_challenge(space, user_id, private_key):
    """Helper to do full challenge/verify/JWT flow and return token"""
    challenge_response = space.create_challenge(user_id)
    challenge = challenge_response['challenge']

    message = challenge.encode('utf-8')
    signature = private_key.sign(message)
    signature_b64 = base64.b64encode(signature).decode()

    space.verify_challenge(user_id, challenge, signature_b64)

    token_response = space.create_jwt(user_id)
    return token_response['token']

def delete_space_state(space: Space, path: str, token: str, keypair: Dict[str,Any]):
    
    # Get current chain head for prev_hash
    head = space.message_store.get_chain_head(space.space_id, "state")
    prev_hash = head["message_hash"] if head else None

    # Compute message hash
    from crypto import CryptoUtils
    crypto = CryptoUtils()
    message_hash = crypto.compute_message_hash(
        space.space_id,
        "state",
        path,
        prev_hash,
        "",
        keypair['id']
    )

    # Sign the message hash
    # Decode the typed identifier and convert to bytes for signing
    from identifiers import decode_identifier
    message_tid = decode_identifier(message_hash)
    message_bytes = message_tid.to_bytes()
    signature_bytes = keypair['private'].sign(message_bytes)
    signature = crypto.base64_encode(signature_bytes)

    import asyncio
    return asyncio.run(space.post_message(
        "state",
        message_hash,
        path,
        prev_hash,
        "",
        signature,
        token
    ))


#region Firestore
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
def firestore_data_store(firestore_emulator):
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


#region S3 Blob Store
# ============================================================================
# S3 Blob Store Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def s3_emulator(request):
    """
    Smart S3 emulator fixture that adapts to environment.

    Modes:
    - auto: Use testcontainers if available, else external (default)
    - testcontainers: Spin up MinIO container automatically
    - external: Use real S3-compatible service (Backblaze B2, AWS S3, etc.)
                configured via environment variables

    Environment variables for external mode:
    - S3_BUCKET_NAME: Bucket name (required)
    - S3_ENDPOINT_URL: Custom endpoint URL (required for B2/MinIO)
    - S3_ACCESS_KEY_ID: Access key ID (required)
    - S3_SECRET_ACCESS_KEY: Secret access key (required)
    - S3_REGION_NAME: Region name (default: us-east-1)

    Usage:
        # Automatic (tries testcontainers, falls back to external)
        pytest backend/tests/test_s3_blob_storage.py

        # Use real S3 service (Backblaze B2, etc.)
        export S3_BUCKET_NAME=my-test-bucket
        export S3_ENDPOINT_URL=https://s3.us-west-004.backblazeb2.com
        export S3_ACCESS_KEY_ID=your-key-id
        export S3_SECRET_ACCESS_KEY=your-secret-key
        pytest --s3-emulator=external

        # Force testcontainers
        pytest --s3-emulator=testcontainers
    """
    mode = request.config.getoption("--s3-emulator")

    if mode == "external":
        # For real S3 services (Backblaze B2, AWS S3, etc.)
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        endpoint_url = os.environ.get('S3_ENDPOINT_URL')
        access_key = os.environ.get('S3_ACCESS_KEY_ID')
        secret_key = os.environ.get('S3_SECRET_ACCESS_KEY')
        region = os.environ.get('S3_REGION_NAME', 'us-east-1')

        if not all([bucket_name, access_key, secret_key]):
            pytest.skip(
                "External S3 mode requires environment variables: "
                "S3_BUCKET_NAME, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY"
            )

        yield {
            'bucket_name': bucket_name,
            'endpoint_url': endpoint_url,
            'access_key_id': access_key,
            'secret_access_key': secret_key,
            'region_name': region
        }
        return

    # Try testcontainers first (for CI and auto mode)
    if mode in ("auto", "testcontainers"):
        try:
            from testcontainers.minio import MinioContainer
            import time

            # Create MinIO container with default credentials
            container = MinioContainer()
            container.start()

            # Get connection details from container
            # The endpoint from get_config() doesn't include the scheme, so add http://
            endpoint = container.get_config()['endpoint']
            if not endpoint.startswith('http'):
                endpoint = f'http://{endpoint}'

            s3_config = {
                'bucket_name': f'test-bucket-{secrets.token_hex(4)}',
                'endpoint_url': endpoint,
                'access_key_id': container.access_key,
                'secret_access_key': container.secret_key,
                'region_name': 'us-east-1'
            }

            # Give MinIO time to initialize
            time.sleep(1)

            yield s3_config

            container.stop()
            return

        except ImportError:
            if mode == "testcontainers":
                pytest.skip("testcontainers[minio] not installed (pip install testcontainers[minio])")
            # Fall through to external mode for 'auto'
        except Exception as e:
            if mode == "testcontainers":
                pytest.skip(f"Failed to start MinIO container: {e}")
            # Fall through to external mode for 'auto'

    # Fallback to external S3 (for auto mode when testcontainers fails)
    bucket_name = os.environ.get('S3_BUCKET_NAME')
    access_key = os.environ.get('S3_ACCESS_KEY_ID')
    secret_key = os.environ.get('S3_SECRET_ACCESS_KEY')

    if all([bucket_name, access_key, secret_key]):
        yield {
            'bucket_name': bucket_name,
            'endpoint_url': os.environ.get('S3_ENDPOINT_URL'),
            'access_key_id': access_key,
            'secret_access_key': secret_key,
            'region_name': os.environ.get('S3_REGION_NAME', 'us-east-1')
        }
    else:
        pytest.skip(
            "S3 emulator not available. "
            "Install testcontainers: pip install testcontainers[minio] "
            "or set S3_* environment variables for external S3"
        )


def _cleanup_s3_blobs(s3_client, bucket_name):
    """Helper to delete all objects with 'blobs/' prefix"""
    from botocore.exceptions import ClientError
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name, Prefix='blobs/'):
            if 'Contents' in page:
                for obj in page['Contents']:
                    # Delete objects one at a time (MinIO doesn't support batch delete well)
                    s3_client.delete_object(Bucket=bucket_name, Key=obj['Key'])
    except ClientError as e:
        # Ignore "bucket doesn't exist" errors
        if e.response.get('Error', {}).get('Code') not in ('NoSuchBucket', '404'):
            raise


@pytest.fixture
def s3_blob_store(s3_emulator, request):
    """
    Create an S3BlobStore instance for testing.

    Cleans up test objects before and after each test to ensure isolation.
    """
    from s3_blob_store import S3BlobStore
    from config import S3BlobConfig

    # Create config from emulator settings
    config = S3BlobConfig(
        bucket_name=s3_emulator['bucket_name'],
        endpoint_url=s3_emulator['endpoint_url'],
        access_key_id=s3_emulator['access_key_id'],
        secret_access_key=s3_emulator['secret_access_key'],
        region_name=s3_emulator['region_name'],
        presigned_url_expiration=300  # 5 minutes for tests
    )

    store = S3BlobStore(config)

    # Cleanup before test to ensure isolation (previous test may have left data)
    _cleanup_s3_blobs(store.s3_client, config.bucket_name)

    yield store

    # Cleanup after test
    _cleanup_s3_blobs(store.s3_client, config.bucket_name)
