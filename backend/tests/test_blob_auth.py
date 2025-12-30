"""
Tests for blob authorization and access control

This test suite validates the blob authorization implementation including:
- Channel-scoped access control
- Upload authorization (any channel member)
- Download authorization (channel members only)
- Delete authorization (uploader or admin only)
- Cross-channel access prevention
"""

import sys
import os
import tempfile
import time

import pytest

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from blob_store import BlobMetadata, BlobReference
from filesystem_blob_store import FilesystemBlobStore
from sqlite_blob_store import SqliteBlobStore
from channel import Channel
from sqlite_state_store import SqliteStateStore
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
            channel_id="channel_123",
            uploaded_by="user_abc",
            uploaded_at=1234567890
        )
        metadata = BlobMetadata(references=[ref])

        assert len(metadata.references) == 1
        assert metadata.references[0].channel_id == "channel_123"
        assert metadata.references[0].uploaded_by == "user_abc"
        assert metadata.references[0].uploaded_at == 1234567890

    def test_metadata_attributes(self):
        """Test metadata attributes and methods are accessible"""
        ref = BlobReference(
            channel_id="test_channel",
            uploaded_by="test_user",
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # All attributes should be accessible
        assert hasattr(metadata, 'references')
        assert hasattr(metadata, 'has_reference')
        assert hasattr(metadata, 'get_reference')
        assert metadata.has_reference("test_channel") is True
        assert metadata.has_reference("other_channel") is False


# ============================================================================
# Blob Store Authorization Tests
# ============================================================================

class TestBlobStoreWithMetadata:
    """Test blob stores properly handle metadata"""

    def test_filesystem_store_metadata(self, fs_blob_store):
        """Test FilesystemBlobStore stores and retrieves metadata with references"""
        blob_data = b"encrypted blob content"
        blob_id = CryptoUtils.compute_blob_id(blob_data)
        channel_id = "channel_123"
        user_id = "user_abc"

        # Add blob with metadata
        fs_blob_store.add_blob(blob_id, blob_data, channel_id, user_id)

        # Retrieve metadata
        metadata = fs_blob_store.get_blob_metadata(blob_id)
        assert metadata is not None
        assert len(metadata.references) == 1
        assert metadata.has_reference(channel_id)
        ref = metadata.get_reference(channel_id, user_id)
        assert ref is not None
        assert ref.channel_id == channel_id
        assert ref.uploaded_by == user_id
        assert ref.uploaded_at > 0

    def test_sqlite_store_metadata(self, db_blob_store):
        """Test SqliteBlobStore stores and retrieves metadata with references"""
        blob_data = b"encrypted blob content"
        blob_id = CryptoUtils.compute_blob_id(blob_data)
        channel_id = "channel_456"
        user_id = "user_xyz"

        # Add blob with metadata
        db_blob_store.add_blob(blob_id, blob_data, channel_id, user_id)

        # Retrieve metadata
        metadata = db_blob_store.get_blob_metadata(blob_id)
        assert metadata is not None
        assert len(metadata.references) == 1
        assert metadata.has_reference(channel_id)
        ref = metadata.get_reference(channel_id, user_id)
        assert ref is not None
        assert ref.channel_id == channel_id
        assert ref.uploaded_by == user_id
        assert ref.uploaded_at > 0

    def test_metadata_persists_after_retrieval(self, fs_blob_store):
        """Test metadata persists after blob retrieval"""
        blob_data = b"test content"
        blob_id = CryptoUtils.compute_blob_id(blob_data)
        channel_id = "persist_channel"
        user_id = "persist_user"

        # Add blob
        fs_blob_store.add_blob(blob_id, blob_data, channel_id, user_id)

        # Get blob content
        retrieved_data = fs_blob_store.get_blob(blob_id)
        assert retrieved_data == blob_data

        # Metadata should still be accessible
        metadata = fs_blob_store.get_blob_metadata(blob_id)
        assert metadata is not None
        assert metadata.has_reference(channel_id)

    def test_metadata_deleted_with_blob(self, fs_blob_store):
        """Test metadata is deleted when last reference is removed"""
        blob_data = b"temporary content"
        blob_id = CryptoUtils.compute_blob_id(blob_data)
        channel_id = "temp_channel"
        user_id = "temp_user"

        # Add and remove blob reference
        fs_blob_store.add_blob(blob_id, blob_data, channel_id, user_id)
        blob_deleted = fs_blob_store.remove_blob_reference(blob_id, channel_id, user_id)

        # Should have deleted blob content since no references remain
        assert blob_deleted is True
        assert fs_blob_store.get_blob(blob_id) is None
        assert fs_blob_store.get_blob_metadata(blob_id) is None

    def test_nonexistent_blob_metadata(self, fs_blob_store):
        """Test getting metadata for non-existent blob returns None"""
        fake_data = b"nonexistent"
        fake_blob_id = CryptoUtils.compute_blob_id(fake_data)
        metadata = fs_blob_store.get_blob_metadata(fake_blob_id)
        assert metadata is None


# ============================================================================
# Channel Authorization Tests
# ============================================================================

class TestChannelBlobAuthorization:
    """Test Channel class blob authorization methods"""

    @pytest.fixture
    def channel(self, temp_db_path, admin_keypair):
        """Create a test channel"""
        channel_id = admin_keypair['channel_id']
        state_store = SqliteStateStore(temp_db_path)
        message_store = SqliteMessageStore(temp_db_path)

        channel = Channel(
            channel_id=channel_id,
            state_store=state_store,
            message_store=message_store,
            jwt_secret="test_secret",
            jwt_algorithm="HS256",
            jwt_expiry_hours=24
        )

        return channel

    @pytest.fixture
    def channel_with_member(self, channel, admin_keypair, user_keypair):
        """Create a channel with admin and one member"""
        # Add user as member
        member_data = base64.b64encode(b"member_info").decode('ascii')
        channel.state_store.set_state(
            channel.channel_id,
            f"members/{user_keypair['user_id']}",
            member_data,
            admin_keypair['user_id'],
            int(time.time() * 1000)
        )
        return channel

    def test_is_channel_admin(self, channel, admin_keypair, user_keypair):
        """Test is_channel_admin identifies admin correctly"""
        # Admin (channel owner) - uses channel_id as their identifier
        assert channel.is_channel_admin(admin_keypair['channel_id']) is True

        # Regular user
        assert channel.is_channel_admin(user_keypair['user_id']) is False

    def test_authorize_upload_as_member(self, channel_with_member, user_keypair):
        """Test that channel members can upload blobs"""
        # Create JWT for member
        token = channel_with_member.create_jwt(user_keypair['user_id'])

        # Should authorize successfully
        result = channel_with_member.authorize_blob_upload(
            user_keypair['user_id'],
            token['token']
        )
        assert result is True

    def test_authorize_upload_as_admin(self, channel, admin_keypair):
        """Test that admin can upload blobs"""
        # Admin uses channel_id as their user identifier
        token = channel.create_jwt(admin_keypair['channel_id'])

        result = channel.authorize_blob_upload(
            admin_keypair['channel_id'],
            token['token']
        )
        assert result is True

    def test_authorize_upload_non_member_fails(self, channel, user_keypair):
        """Test that non-members cannot upload blobs"""
        # Create a JWT (would normally fail, but for testing...)
        token = channel.create_jwt(channel.channel_id)

        # Should raise ValueError for non-member
        with pytest.raises(ValueError, match="Not a member"):
            channel.authorize_blob_upload(user_keypair['user_id'], token['token'])

    def test_authorize_download_same_channel(self, channel_with_member, user_keypair):
        """Test download authorization for same channel"""
        token = channel_with_member.create_jwt(user_keypair['user_id'])

        # Create metadata for blob in same channel
        ref = BlobReference(
            channel_id=channel_with_member.channel_id,
            uploaded_by="other_user",
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Should authorize successfully
        result = channel_with_member.authorize_blob_download(
            user_keypair['user_id'],
            token['token'],
            metadata
        )
        assert result is True

    def test_authorize_download_different_channel_fails(self, channel_with_member, user_keypair):
        """Test download fails for blob from different channel"""
        token = channel_with_member.create_jwt(user_keypair['user_id'])

        # Create metadata for blob in different channel
        ref = BlobReference(
            channel_id="different_channel_id",
            uploaded_by="other_user",
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Should raise ValueError for different channel
        with pytest.raises(ValueError, match="different channel"):
            channel_with_member.authorize_blob_download(
                user_keypair['user_id'],
                token['token'],
                metadata
            )

    def test_authorize_delete_as_uploader(self, channel_with_member, user_keypair):
        """Test uploader can delete their own blob reference"""
        token = channel_with_member.create_jwt(user_keypair['user_id'])

        # Create metadata where user is the uploader
        ref = BlobReference(
            channel_id=channel_with_member.channel_id,
            uploaded_by=user_keypair['user_id'],
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Should authorize successfully
        result = channel_with_member.authorize_blob_delete(
            user_keypair['user_id'],
            token['token'],
            metadata
        )
        assert result is True

    def test_authorize_delete_as_admin(self, channel, admin_keypair):
        """Test admin can delete any blob reference in their channel"""
        # Admin uses channel_id as their user identifier
        token = channel.create_jwt(admin_keypair['channel_id'])

        # Create metadata where someone else is the uploader
        ref = BlobReference(
            channel_id=channel.channel_id,
            uploaded_by="other_user",
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Admin should be able to delete
        result = channel.authorize_blob_delete(
            admin_keypair['channel_id'],
            token['token'],
            metadata
        )
        assert result is True

    def test_authorize_delete_non_uploader_fails(self, channel_with_member, user_keypair):
        """Test non-uploader cannot delete blob reference"""
        token = channel_with_member.create_jwt(user_keypair['user_id'])

        # Create metadata where user is NOT the uploader
        ref = BlobReference(
            channel_id=channel_with_member.channel_id,
            uploaded_by="other_user",
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Should raise ValueError
        with pytest.raises(ValueError, match="uploader or channel admin"):
            channel_with_member.authorize_blob_delete(
                user_keypair['user_id'],
                token['token'],
                metadata
            )

    def test_authorize_delete_different_channel_fails(self, channel_with_member, user_keypair):
        """Test cannot delete blob from different channel"""
        token = channel_with_member.create_jwt(user_keypair['user_id'])

        # Create metadata for different channel
        ref = BlobReference(
            channel_id="different_channel",
            uploaded_by=user_keypair['user_id'],
            uploaded_at=int(time.time() * 1000)
        )
        metadata = BlobMetadata(references=[ref])

        # Should raise ValueError for different channel
        with pytest.raises(ValueError, match="different channel"):
            channel_with_member.authorize_blob_delete(
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
    def setup(self, temp_db_path, temp_blob_dir, admin_keypair, user_keypair):
        """Setup complete environment with channel, blob store, and users"""
        # Create channel
        channel_id = admin_keypair['channel_id']
        state_store = SqliteStateStore(temp_db_path + "_state")
        message_store = SqliteMessageStore(temp_db_path + "_msg")
        blob_store = FilesystemBlobStore(temp_blob_dir)

        channel = Channel(
            channel_id=channel_id,
            state_store=state_store,
            message_store=message_store,
            jwt_secret="test_secret",
            jwt_algorithm="HS256",
            jwt_expiry_hours=24
        )

        # Add user as member
        member_data = base64.b64encode(b"member_info").decode('ascii')
        channel.state_store.set_state(
            channel.channel_id,
            f"members/{user_keypair['user_id']}",
            member_data,
            admin_keypair['user_id'],
            int(time.time() * 1000)
        )

        return {
            'channel': channel,
            'blob_store': blob_store,
            'admin': admin_keypair,
            'user': user_keypair
        }

    def test_complete_upload_download_delete_flow(self, setup):
        """Test complete blob lifecycle with authorization"""
        channel = setup['channel']
        blob_store = setup['blob_store']
        user = setup['user']

        # 1. Upload blob
        blob_data = b"test encrypted content"
        blob_id = CryptoUtils.compute_blob_id(blob_data)
        user_token = channel.create_jwt(user['user_id'])

        # Authorize and upload
        channel.authorize_blob_upload(user['user_id'], user_token['token'])
        blob_store.add_blob(blob_id, blob_data, channel.channel_id, user['user_id'])

        # 2. Download blob
        metadata = blob_store.get_blob_metadata(blob_id)
        assert metadata is not None

        channel.authorize_blob_download(user['user_id'], user_token['token'], metadata)
        retrieved_data = blob_store.get_blob(blob_id)
        assert retrieved_data == blob_data

        # 3. Delete blob reference (as uploader)
        channel.authorize_blob_delete(user['user_id'], user_token['token'], metadata)
        blob_deleted = blob_store.remove_blob_reference(blob_id, channel.channel_id, user['user_id'])

        # Verify deletion - blob content should be deleted since no references remain
        assert blob_deleted is True
        assert blob_store.get_blob(blob_id) is None
        assert blob_store.get_blob_metadata(blob_id) is None

    def test_admin_can_delete_user_blob(self, setup):
        """Test admin can delete blob reference uploaded by user"""
        channel = setup['channel']
        blob_store = setup['blob_store']
        admin = setup['admin']
        user = setup['user']

        # User uploads blob
        blob_data = b"user content"
        blob_id = CryptoUtils.compute_blob_id(blob_data)
        user_token = channel.create_jwt(user['user_id'])

        channel.authorize_blob_upload(user['user_id'], user_token['token'])
        blob_store.add_blob(blob_id, blob_data, channel.channel_id, user['user_id'])

        # Admin deletes the user's reference (admin uses channel_id as their identifier)
        admin_token = channel.create_jwt(admin['channel_id'])
        metadata = blob_store.get_blob_metadata(blob_id)

        channel.authorize_blob_delete(admin['channel_id'], admin_token['token'], metadata)
        blob_deleted = blob_store.remove_blob_reference(blob_id, channel.channel_id, user['user_id'])

        # Verify deletion - blob content should be deleted since no references remain
        assert blob_deleted is True
        assert blob_store.get_blob(blob_id) is None

    def test_cross_channel_access_prevented(self, temp_db_path, temp_blob_dir, admin_keypair, user_keypair):
        """Test users from one channel cannot access blobs from another"""
        # Create two separate channels
        from cryptography.hazmat.primitives.asymmetric import ed25519

        # Channel 1
        channel1_key = ed25519.Ed25519PrivateKey.generate()
        channel1_id = admin_keypair['channel_id']
        state_store1 = SqliteStateStore(temp_db_path + "_ch1")
        message_store1 = SqliteMessageStore(temp_db_path + "_msg1")
        channel1 = Channel(
            channel_id=channel1_id,
            state_store=state_store1,
            message_store=message_store1,
            jwt_secret="secret1",
            jwt_algorithm="HS256"
        )

        # Channel 2
        channel2_key = ed25519.Ed25519PrivateKey.generate()
        channel2_pub = channel2_key.public_key().public_bytes_raw()
        from identifiers import encode_channel_id
        channel2_id = encode_channel_id(channel2_pub)
        state_store2 = SqliteStateStore(temp_db_path + "_ch2")
        message_store2 = SqliteMessageStore(temp_db_path + "_msg2")
        channel2 = Channel(
            channel_id=channel2_id,
            state_store=state_store2,
            message_store=message_store2,
            jwt_secret="secret2",
            jwt_algorithm="HS256"
        )

        # Upload blob to channel1
        blob_store = FilesystemBlobStore(temp_blob_dir)
        blob_data = b"channel1 data"
        blob_id = CryptoUtils.compute_blob_id(blob_data)

        token1 = channel1.create_jwt(channel1_id)
        channel1.authorize_blob_upload(channel1_id, token1['token'])
        blob_store.add_blob(blob_id, blob_data, channel1_id, channel1_id)

        # Try to access from channel2
        token2 = channel2.create_jwt(channel2_id)
        metadata = blob_store.get_blob_metadata(blob_id)

        # Should fail - different channel
        with pytest.raises(ValueError, match="different channel"):
            channel2.authorize_blob_download(channel2_id, token2['token'], metadata)

    def test_blob_deduplication_across_channels(self, temp_db_path, temp_blob_dir, admin_keypair):
        """Test blob deduplication when multiple channels upload same content"""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from identifiers import encode_channel_id

        # Create two channels
        channel1_id = admin_keypair['channel_id']
        state_store1 = SqliteStateStore(temp_db_path + "_ch1")
        message_store1 = SqliteMessageStore(temp_db_path + "_msg1")
        channel1 = Channel(
            channel_id=channel1_id,
            state_store=state_store1,
            message_store=message_store1,
            jwt_secret="secret1",
            jwt_algorithm="HS256"
        )

        channel2_key = ed25519.Ed25519PrivateKey.generate()
        channel2_pub = channel2_key.public_key().public_bytes_raw()
        channel2_id = encode_channel_id(channel2_pub)
        state_store2 = SqliteStateStore(temp_db_path + "_ch2")
        message_store2 = SqliteMessageStore(temp_db_path + "_msg2")
        channel2 = Channel(
            channel_id=channel2_id,
            state_store=state_store2,
            message_store=message_store2,
            jwt_secret="secret2",
            jwt_algorithm="HS256"
        )

        # Same blob content
        blob_data = b"shared content across channels"
        blob_id = CryptoUtils.compute_blob_id(blob_data)
        blob_store = FilesystemBlobStore(temp_blob_dir)

        # Channel 1 uploads blob
        token1 = channel1.create_jwt(channel1_id)
        channel1.authorize_blob_upload(channel1_id, token1['token'])
        blob_store.add_blob(blob_id, blob_data, channel1_id, channel1_id)

        # Verify blob exists
        assert blob_store.get_blob(blob_id) == blob_data
        metadata = blob_store.get_blob_metadata(blob_id)
        assert len(metadata.references) == 1
        assert metadata.has_reference(channel1_id)

        # Channel 2 uploads same content (deduplication)
        token2 = channel2.create_jwt(channel2_id)
        channel2.authorize_blob_upload(channel2_id, token2['token'])
        blob_store.add_blob(blob_id, blob_data, channel2_id, channel2_id)

        # Verify blob still exists with two references
        assert blob_store.get_blob(blob_id) == blob_data
        metadata = blob_store.get_blob_metadata(blob_id)
        assert len(metadata.references) == 2
        assert metadata.has_reference(channel1_id)
        assert metadata.has_reference(channel2_id)

        # Both channels can download
        channel1.authorize_blob_download(channel1_id, token1['token'], metadata)
        channel2.authorize_blob_download(channel2_id, token2['token'], metadata)

        # Channel 1 deletes their reference
        channel1.authorize_blob_delete(channel1_id, token1['token'], metadata)
        blob_deleted = blob_store.remove_blob_reference(blob_id, channel1_id, channel1_id)

        # Blob content should still exist (channel 2 still references it)
        assert blob_deleted is False
        assert blob_store.get_blob(blob_id) == blob_data
        metadata = blob_store.get_blob_metadata(blob_id)
        assert len(metadata.references) == 1
        assert metadata.has_reference(channel2_id)
        assert not metadata.has_reference(channel1_id)

        # Channel 2 can still download
        channel2.authorize_blob_download(channel2_id, token2['token'], metadata)

        # Channel 2 deletes their reference
        channel2.authorize_blob_delete(channel2_id, token2['token'], metadata)
        blob_deleted = blob_store.remove_blob_reference(blob_id, channel2_id, channel2_id)

        # Now blob content should be deleted (no references remain)
        assert blob_deleted is True
        assert blob_store.get_blob(blob_id) is None
        assert blob_store.get_blob_metadata(blob_id) is None
