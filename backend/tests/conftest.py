"""
Shared pytest fixtures for backend tests
"""
import sys
import os
import tempfile
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from database import Database
from sqlite_state_store import SqliteStateStore
from crypto import CryptoUtils
from authorization import AuthorizationEngine
from identifiers import encode_channel_id, encode_user_id
from filesystem_blob_store import FilesystemBlobStore
from database_blob_store import DatabaseBlobStore


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
def db(temp_db_path):
    """Create a Database instance with temporary storage"""
    return Database(temp_db_path)


@pytest.fixture
def state_store(temp_db_path):
    """Create a SqliteStateStore instance with temporary storage"""
    return SqliteStateStore(temp_db_path)


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
def db_blob_store(db):
    """Create a DatabaseBlobStore instance"""
    return DatabaseBlobStore(db)


@pytest.fixture
def admin_keypair():
    """Generate an admin keypair for testing"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()

    return {
        'private': private_key,
        'public': public_key,
        'public_bytes': public_key_bytes,
        'user_id': encode_user_id(public_key_bytes),
        'channel_id': encode_channel_id(public_key_bytes)
    }


@pytest.fixture
def user_keypair():
    """Generate a user keypair for testing"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()

    return {
        'private': private_key,
        'public': public_key,
        'public_bytes': public_key_bytes,
        'user_id': encode_user_id(public_key_bytes)
    }
