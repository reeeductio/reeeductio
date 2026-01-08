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

import conftest
sign_state_entry = conftest.sign_state_entry
sign_and_store_state = conftest.sign_and_store_state


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


# ============================================================================
# Space Authorization Tests
# ============================================================================

class TestSpaceBlobAuthorization:
    """Test Space class blob authorization methods"""

    @pytest.fixture
    def space(self, temp_db_path, admin_keypair):
        """Create a test space"""
        space_id = admin_keypair['space_id']
        state_store = SqliteDataStore(temp_db_path)
        message_store = SqliteMessageStore(temp_db_path)

        space = Space(
            space_id=space_id,
            state_store=state_store,
            message_store=message_store,
            jwt_secret="test_secret",
            jwt_algorithm="HS256",
            jwt_expiry_hours=24
        )

        return space

    @pytest.fixture
    def space_with_member(self, space, admin_keypair, user_keypair):
        """Create a space with admin and one member"""

        admin_id = admin_keypair['user_id']
        admin_private = admin_keypair['private']
        user_id = user_keypair['user_id']

        # Add user as member
        member_data = {"user_id": user_id}
        sign_and_store_state(
            state_store=space.state_store,
            space_id=space.space_id,
            path=f"auth/users/{user_id}",
            contents=member_data,
            signer_private_key=admin_private,
            signer_user_id=admin_id,
            signed_at=1234567890
        )
        return space

    def test_is_space_admin(self, space, admin_keypair, user_keypair):
        """Test is_space_admin identifies admin correctly"""
        # Admin (space owner) - uses space_id as their identifier
        assert space.is_space_admin(admin_keypair['space_id']) is True

        # Regular user
        assert space.is_space_admin(user_keypair['user_id']) is False

    def test_authorize_upload_as_member(self, space_with_member, user_keypair):
        """Test that space members can upload blobs"""
        # Create JWT for member
        token = space_with_member.create_jwt(user_keypair['user_id'])

        # Should authorize successfully
        result = space_with_member.authorize_blob_upload(
            user_keypair['user_id'],
            token['token']
        )
        assert result is True

    def test_authorize_upload_as_admin(self, space, admin_keypair):
        """Test that admin can upload blobs"""
        # Admin uses space_id as their user identifier
        token = space.create_jwt(admin_keypair['space_id'])

        result = space.authorize_blob_upload(
            admin_keypair['space_id'],
            token['token']
        )
        assert result is True

    def test_authorize_upload_non_member_fails(self, space, user_keypair):
        """Test that non-members cannot upload blobs"""
        # Create a JWT (would normally fail, but for testing...)
        token = space.create_jwt(space.space_id)

        # Should raise ValueError for non-member
        with pytest.raises(ValueError, match="Not a member"):
            space.authorize_blob_upload(user_keypair['user_id'], token['token'])

    def test_authorize_download_same_space(self, space_with_member, user_keypair):
        """Test download authorization for same space"""
        token = space_with_member.create_jwt(user_keypair['user_id'])

        # Create metadata for blob in same space
        ref = BlobReference(
            space_id=space_with_member.space_id,
            uploaded_by="other_user",
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Should authorize successfully
        result = space_with_member.authorize_blob_download(
            user_keypair['user_id'],
            token['token'],
            metadata
        )
        assert result is True

    def test_authorize_download_different_space_fails(self, space_with_member, user_keypair):
        """Test download fails for blob from different space"""
        token = space_with_member.create_jwt(user_keypair['user_id'])

        # Create metadata for blob in different space
        ref = BlobReference(
            space_id="different_space_id",
            uploaded_by="other_user",
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Should raise ValueError for different space
        with pytest.raises(ValueError, match="different space"):
            space_with_member.authorize_blob_download(
                user_keypair['user_id'],
                token['token'],
                metadata
            )

    def test_authorize_delete_as_uploader(self, space_with_member, user_keypair):
        """Test uploader can delete their own blob reference"""
        token = space_with_member.create_jwt(user_keypair['user_id'])

        # Create metadata where user is the uploader
        ref = BlobReference(
            space_id=space_with_member.space_id,
            uploaded_by=user_keypair['user_id'],
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Should authorize successfully
        result = space_with_member.authorize_blob_delete(
            user_keypair['user_id'],
            token['token'],
            metadata
        )
        assert result is True

    def test_authorize_delete_as_admin(self, space, admin_keypair):
        """Test admin can delete any blob reference in their space"""
        # Admin uses space_id as their user identifier
        token = space.create_jwt(admin_keypair['space_id'])

        # Create metadata where someone else is the uploader
        ref = BlobReference(
            space_id=space.space_id,
            uploaded_by="other_user",
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Admin should be able to delete
        result = space.authorize_blob_delete(
            admin_keypair['space_id'],
            token['token'],
            metadata
        )
        assert result is True

    def test_authorize_delete_non_uploader_fails(self, space_with_member, user_keypair):
        """Test non-uploader cannot delete blob reference"""
        token = space_with_member.create_jwt(user_keypair['user_id'])

        # Create metadata where user is NOT the uploader
        ref = BlobReference(
            space_id=space_with_member.space_id,
            uploaded_by="other_user",
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Should raise ValueError
        with pytest.raises(ValueError, match="uploader or space admin"):
            space_with_member.authorize_blob_delete(
                user_keypair['user_id'],
                token['token'],
                metadata
            )

    def test_authorize_delete_different_space_fails(self, space_with_member, user_keypair):
        """Test cannot delete blob from different space"""
        token = space_with_member.create_jwt(user_keypair['user_id'])

        # Create metadata for different space
        ref = BlobReference(
            space_id="different_space",
            uploaded_by=user_keypair['user_id'],
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Should raise ValueError for different space
        with pytest.raises(ValueError, match="different space"):
            space_with_member.authorize_blob_delete(
                user_keypair['user_id'],
                token['token'],
                metadata
            )


# ============================================================================
# Integration Tests
# ============================================================================

class TestBlobAuthorizationIntegration:
    """Integration tests for complete blob authorization flow"""

    @pytest.fixture
    def setup(self, temp_db_path, admin_keypair, user_keypair, any_blob_store):
        """Setup complete environment with space, blob store, and users"""
        # Create space
        space_id = admin_keypair['space_id']
        admin_id = admin_keypair['user_id']
        admin_private = admin_keypair['private']
        user_id = user_keypair['user_id']
        state_store = SqliteDataStore(temp_db_path + "_state")
        message_store = SqliteMessageStore(temp_db_path + "_msg")

        space = Space(
            space_id=space_id,
            state_store=state_store,
            message_store=message_store,
            jwt_secret="test_secret",
            jwt_algorithm="HS256",
            jwt_expiry_hours=24
        )

        # Add user as member
        user_info = {"user_id": user_id}
        user_path = f"auth/users/{user_id}"
        sign_and_store_state(
            state_store=state_store,
            space_id=space_id,
            path=user_path,
            contents=user_info,
            signer_private_key=admin_private,
            signer_user_id=admin_id,
            signed_at=1234567890
        )

        return {
            'space': space,
            'blob_store': any_blob_store,
            'admin': admin_keypair,
            'user': user_keypair
        }

    def test_complete_upload_download_delete_flow(self, setup):
        """Test complete blob lifecycle with authorization"""
        space = setup['space']
        blob_store = setup['blob_store']
        user = setup['user']

        # 1. Upload blob
        blob_data = b"test encrypted content"
        blob_id = CryptoUtils.compute_blob_id(blob_data)
        user_token = space.create_jwt(user['user_id'])

        # Authorize and upload
        space.authorize_blob_upload(user['user_id'], user_token['token'])
        blob_store.add_blob(blob_id, blob_data, space.space_id, user['user_id'])

        # 2. Download blob
        metadata = blob_store.get_blob_metadata(blob_id)
        assert metadata is not None

        space.authorize_blob_download(user['user_id'], user_token['token'], metadata)
        retrieved_data = blob_store.get_blob(blob_id)
        assert retrieved_data == blob_data

        # 3. Delete blob reference (as uploader)
        space.authorize_blob_delete(user['user_id'], user_token['token'], metadata)
        blob_deleted = blob_store.remove_blob_reference(blob_id, space.space_id, user['user_id'])

        # Verify deletion - blob content should be deleted since no references remain
        assert blob_deleted is True
        assert blob_store.get_blob(blob_id) is None
        assert blob_store.get_blob_metadata(blob_id) is None

    def test_admin_can_delete_user_blob(self, setup):
        """Test admin can delete blob reference uploaded by user"""
        space = setup['space']
        blob_store = setup['blob_store']
        admin = setup['admin']
        user = setup['user']

        # User uploads blob
        blob_data = b"user content"
        blob_id = CryptoUtils.compute_blob_id(blob_data)
        user_token = space.create_jwt(user['user_id'])

        space.authorize_blob_upload(user['user_id'], user_token['token'])
        blob_store.add_blob(blob_id, blob_data, space.space_id, user['user_id'])

        # Admin deletes the user's reference (admin uses space_id as their identifier)
        admin_token = space.create_jwt(admin['space_id'])
        metadata = blob_store.get_blob_metadata(blob_id)

        space.authorize_blob_delete(admin['space_id'], admin_token['token'], metadata)
        blob_deleted = blob_store.remove_blob_reference(blob_id, space.space_id, user['user_id'])

        # Verify deletion - blob content should be deleted since no references remain
        assert blob_deleted is True
        assert blob_store.get_blob(blob_id) is None

    def test_cross_space_access_prevented(self, temp_db_path, admin_keypair, user_keypair, any_blob_store):
        """Test users from one space cannot access blobs from another"""
        # Create two separate spaces
        from cryptography.hazmat.primitives.asymmetric import ed25519

        # Space 1
        space1_key = ed25519.Ed25519PrivateKey.generate()
        space1_id = admin_keypair['space_id']
        state_store1 = SqliteDataStore(temp_db_path + "_ch1")
        message_store1 = SqliteMessageStore(temp_db_path + "_msg1")
        space1 = Space(
            space_id=space1_id,
            state_store=state_store1,
            message_store=message_store1,
            jwt_secret="secret1",
            jwt_algorithm="HS256"
        )

        # Space 2
        space2_key = ed25519.Ed25519PrivateKey.generate()
        space2_pub = space2_key.public_key().public_bytes_raw()
        from identifiers import encode_space_id
        space2_id = encode_space_id(space2_pub)
        state_store2 = SqliteDataStore(temp_db_path + "_ch2")
        message_store2 = SqliteMessageStore(temp_db_path + "_msg2")
        space2 = Space(
            space_id=space2_id,
            state_store=state_store2,
            message_store=message_store2,
            jwt_secret="secret2",
            jwt_algorithm="HS256"
        )

        # Upload blob to space1
        blob_store = any_blob_store
        blob_data = b"space1 data"
        blob_id = CryptoUtils.compute_blob_id(blob_data)

        token1 = space1.create_jwt(space1_id)
        space1.authorize_blob_upload(space1_id, token1['token'])
        blob_store.add_blob(blob_id, blob_data, space1_id, space1_id)

        # Try to access from space2
        token2 = space2.create_jwt(space2_id)
        metadata = blob_store.get_blob_metadata(blob_id)

        # Should fail - different space
        with pytest.raises(ValueError, match="different space"):
            space2.authorize_blob_download(space2_id, token2['token'], metadata)

    def test_blob_deduplication_across_spaces(self, temp_db_path, admin_keypair, any_blob_store):
        """Test blob deduplication when multiple spaces upload same content"""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from identifiers import encode_space_id

        # Create two spaces
        space1_id = admin_keypair['space_id']
        state_store1 = SqliteDataStore(temp_db_path + "_ch1")
        message_store1 = SqliteMessageStore(temp_db_path + "_msg1")
        space1 = Space(
            space_id=space1_id,
            state_store=state_store1,
            message_store=message_store1,
            jwt_secret="secret1",
            jwt_algorithm="HS256"
        )

        space2_key = ed25519.Ed25519PrivateKey.generate()
        space2_pub = space2_key.public_key().public_bytes_raw()
        space2_id = encode_space_id(space2_pub)
        state_store2 = SqliteDataStore(temp_db_path + "_ch2")
        message_store2 = SqliteMessageStore(temp_db_path + "_msg2")
        space2 = Space(
            space_id=space2_id,
            state_store=state_store2,
            message_store=message_store2,
            jwt_secret="secret2",
            jwt_algorithm="HS256"
        )

        # Same blob content
        blob_data = b"shared content across spaces"
        blob_id = CryptoUtils.compute_blob_id(blob_data)
        blob_store = any_blob_store

        # Space 1 uploads blob
        token1 = space1.create_jwt(space1_id)
        space1.authorize_blob_upload(space1_id, token1['token'])
        blob_store.add_blob(blob_id, blob_data, space1_id, space1_id)

        # Verify blob exists
        assert blob_store.get_blob(blob_id) == blob_data
        metadata = blob_store.get_blob_metadata(blob_id)
        assert len(metadata.references) == 1
        assert metadata.has_reference(space1_id)

        # Space 2 uploads same content (deduplication)
        token2 = space2.create_jwt(space2_id)
        space2.authorize_blob_upload(space2_id, token2['token'])
        blob_store.add_blob(blob_id, blob_data, space2_id, space2_id)

        # Verify blob still exists with two references
        assert blob_store.get_blob(blob_id) == blob_data
        metadata = blob_store.get_blob_metadata(blob_id)
        assert len(metadata.references) == 2
        assert metadata.has_reference(space1_id)
        assert metadata.has_reference(space2_id)

        # Both spaces can download
        space1.authorize_blob_download(space1_id, token1['token'], metadata)
        space2.authorize_blob_download(space2_id, token2['token'], metadata)

        # Space 1 deletes their reference
        space1.authorize_blob_delete(space1_id, token1['token'], metadata)
        blob_deleted = blob_store.remove_blob_reference(blob_id, space1_id, space1_id)

        # Blob content should still exist (space 2 still references it)
        assert blob_deleted is False
        assert blob_store.get_blob(blob_id) == blob_data
        metadata = blob_store.get_blob_metadata(blob_id)
        assert len(metadata.references) == 1
        assert metadata.has_reference(space2_id)
        assert not metadata.has_reference(space1_id)

        # Space 2 can still download
        space2.authorize_blob_download(space2_id, token2['token'], metadata)

        # Space 2 deletes their reference
        space2.authorize_blob_delete(space2_id, token2['token'], metadata)
        blob_deleted = blob_store.remove_blob_reference(blob_id, space2_id, space2_id)

        # Now blob content should be deleted (no references remain)
        assert blob_deleted is True
        assert blob_store.get_blob(blob_id) is None
        assert blob_store.get_blob_metadata(blob_id) is None
