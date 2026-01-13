"""
Tests for blob authorization and access control

This test suite validates the blob authorization implementation including:
- Space-scoped access control
- Upload authorization (any space member)
- Download authorization (space members only)
- Delete authorization (uploader or admin only)
- Cross-space access prevention
"""

import sys
import os
import tempfile
import time
import pytest

from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

from blob_store import BlobMetadata, BlobReference, BlobStore
from filesystem_blob_store import FilesystemBlobStore
from sqlite_blob_store import SqliteBlobStore
from space import Space
from sqlite_data_store import SqliteDataStore
from sqlite_message_store import SqliteMessageStore
from crypto import CryptoUtils
import base64

# ============================================================================
# Blob Metadata Tests
# ============================================================================

class TestBlobMetadata:
    """Test BlobMetadata class"""

    def test_metadata_creation(self):
        """Test creating BlobMetadata object with references"""
        ref = BlobReference(
            space_id="space_123",
            uploaded_by="user_abc",
            uploaded_at=1234567890
        )
        metadata = BlobMetadata(references=[ref])

        assert len(metadata.references) == 1
        assert metadata.references[0].space_id == "space_123"
        assert metadata.references[0].uploaded_by == "user_abc"
        assert metadata.references[0].uploaded_at == 1234567890

    def test_metadata_attributes(self):
        """Test metadata attributes and methods are accessible"""
        ref = BlobReference(
            space_id="test_space",
            uploaded_by="test_user",
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # All attributes should be accessible
        assert hasattr(metadata, 'references')
        assert hasattr(metadata, 'has_reference')
        assert hasattr(metadata, 'get_reference')
        assert metadata.has_reference("test_space") is True
        assert metadata.has_reference("other_space") is False


# ============================================================================
# Blob Store Authorization Tests
# ============================================================================

def generic_store_metadata(blob_store: BlobStore, space_id: str, user_id: str):
    """Generic test that blob store stores and retrieves metadata with references"""
    blob_data = b"encrypted blob content"
    blob_id = CryptoUtils.compute_blob_id(blob_data)

    # Add blob with metadata
    blob_store.add_blob(blob_id, blob_data, space_id, user_id)

    # Retrieve metadata
    metadata = blob_store.get_blob_metadata(blob_id)
    assert metadata is not None
    assert len(metadata.references) == 1
    assert metadata.has_reference(space_id)
    ref = metadata.get_reference(space_id, user_id)
    assert ref is not None
    assert ref.space_id == space_id
    assert ref.uploaded_by == user_id
    assert ref.uploaded_at > 0


def generic_metadata_persists_after_retrieval(blob_store: BlobStore):
    """Generic test that metadata persists after blob retrieval"""
    blob_data = b"test content"
    blob_id = CryptoUtils.compute_blob_id(blob_data)
    space_id = "persist_space"
    user_id = "persist_user"

    # Add blob
    blob_store.add_blob(blob_id, blob_data, space_id, user_id)

    # Get blob content
    retrieved_data = blob_store.get_blob(blob_id)
    assert retrieved_data == blob_data

    # Metadata should still be accessible
    metadata = blob_store.get_blob_metadata(blob_id)
    assert metadata is not None
    assert metadata.has_reference(space_id)


def generic_metadata_deleted_with_blob(blob_store: BlobStore):
    """Generic test that metadata is deleted when last reference is removed"""
    blob_data = b"temporary content"
    blob_id = CryptoUtils.compute_blob_id(blob_data)
    space_id = "temp_space"
    user_id = "temp_user"

    # Add and remove blob reference
    blob_store.add_blob(blob_id, blob_data, space_id, user_id)
    blob_deleted = blob_store.remove_blob_reference(blob_id, space_id, user_id)

    # Should have deleted blob content since no references remain
    assert blob_deleted is True
    assert blob_store.get_blob(blob_id) is None
    assert blob_store.get_blob_metadata(blob_id) is None


def generic_nonexistent_blob_metadata(blob_store: BlobStore):
    """Generic test for getting metadata for non-existent blob returns None"""
    fake_data = b"nonexistent"
    fake_blob_id = CryptoUtils.compute_blob_id(fake_data)
    metadata = blob_store.get_blob_metadata(fake_blob_id)
    assert metadata is None


class TestBlobStoreWithMetadata:
    """Test blob stores properly handle metadata"""

    def test_filesystem_store_metadata(self, fs_blob_store):
        """Test FilesystemBlobStore stores and retrieves metadata with references"""
        generic_store_metadata(fs_blob_store, "space_123", "user_abc")

    def test_sqlite_store_metadata(self, db_blob_store):
        """Test SqliteBlobStore stores and retrieves metadata with references"""
        generic_store_metadata(db_blob_store, "space_456", "user_xyz")

    def test_metadata_persists_after_retrieval(self, fs_blob_store):
        """Test metadata persists after blob retrieval"""
        generic_metadata_persists_after_retrieval(fs_blob_store)

    def test_metadata_deleted_with_blob(self, fs_blob_store):
        """Test metadata is deleted when last reference is removed"""
        generic_metadata_deleted_with_blob(fs_blob_store)

    def test_nonexistent_blob_metadata(self, fs_blob_store):
        """Test getting metadata for non-existent blob returns None"""
        generic_nonexistent_blob_metadata(fs_blob_store)
