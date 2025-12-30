"""
Tests for blob storage backends (filesystem and database)
"""
import pytest

from identifiers import encode_user_id


def test_fs_blob_upload(fs_blob_store, crypto):
    """Test filesystem blob upload with reference counting"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)
    channel_id = "test_channel"
    user_id = "test_user"

    fs_blob_store.add_blob(blob_id, blob_data, channel_id, user_id)
    retrieved = fs_blob_store.get_blob(blob_id)

    assert retrieved == blob_data


def test_fs_blob_duplicate_reference_rejection(fs_blob_store, crypto):
    """Test that filesystem store rejects duplicate references"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)
    channel_id = "test_channel"
    user_id = "test_user"

    fs_blob_store.add_blob(blob_id, blob_data, channel_id, user_id)

    # Same channel/user reference should be rejected
    with pytest.raises(FileExistsError):
        fs_blob_store.add_blob(blob_id, blob_data, channel_id, user_id)


def test_fs_blob_invalid_id_rejection(fs_blob_store):
    """Test that filesystem store rejects invalid blob IDs"""
    # USER type instead of BLOB
    invalid_id = encode_user_id(b"x" * 32)
    blob_data = b"some data"
    channel_id = "test_channel"
    user_id = "test_user"

    with pytest.raises(ValueError, match="BLOB type"):
        fs_blob_store.add_blob(invalid_id, blob_data, channel_id, user_id)


def test_fs_blob_retrieval_nonexistent(fs_blob_store, crypto):
    """Test retrieval of non-existent blob returns None"""
    non_existent_id = crypto.compute_blob_id(b"different content")
    assert fs_blob_store.get_blob(non_existent_id) is None


def test_fs_blob_reference_removal(fs_blob_store, crypto):
    """Test filesystem blob reference removal"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)
    channel_id = "test_channel"
    user_id = "test_user"

    fs_blob_store.add_blob(blob_id, blob_data, channel_id, user_id)
    # Should return True when blob content is deleted (last reference)
    assert fs_blob_store.remove_blob_reference(blob_id, channel_id, user_id) == True
    assert fs_blob_store.get_blob(blob_id) is None


def test_fs_blob_deletion_nonexistent(fs_blob_store, crypto):
    """Test removing non-existent blob reference returns False"""
    blob_id = crypto.compute_blob_id(b"nonexistent")
    assert fs_blob_store.remove_blob_reference(blob_id, "channel", "user") == False


def test_db_blob_upload(db_blob_store, crypto):
    """Test database blob upload with reference counting"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)
    channel_id = "test_channel"
    user_id = "test_user"

    db_blob_store.add_blob(blob_id, blob_data, channel_id, user_id)
    retrieved = db_blob_store.get_blob(blob_id)

    assert retrieved == blob_data


def test_db_blob_reference_removal(db_blob_store, crypto):
    """Test database blob reference removal"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)
    channel_id = "test_channel"
    user_id = "test_user"

    db_blob_store.add_blob(blob_id, blob_data, channel_id, user_id)
    # Should return True when blob content is deleted (last reference)
    assert db_blob_store.remove_blob_reference(blob_id, channel_id, user_id) == True
    assert db_blob_store.get_blob(blob_id) is None


def test_db_blob_deletion_nonexistent(db_blob_store, crypto):
    """Test removing non-existent blob reference from database returns False"""
    blob_id = crypto.compute_blob_id(b"nonexistent")
    assert db_blob_store.remove_blob_reference(blob_id, "channel", "user") == False


def test_blob_deduplication(fs_blob_store, crypto):
    """Test that multiple channels can reference same blob content"""
    blob_data = b"shared content"
    blob_id = crypto.compute_blob_id(blob_data)

    # First channel uploads
    fs_blob_store.add_blob(blob_id, blob_data, "channel1", "user1")

    # Second channel uploads same content (deduplication)
    fs_blob_store.add_blob(blob_id, blob_data, "channel2", "user2")

    # Blob content should still exist
    assert fs_blob_store.get_blob(blob_id) == blob_data

    # Remove first reference - content should remain
    assert fs_blob_store.remove_blob_reference(blob_id, "channel1", "user1") == False
    assert fs_blob_store.get_blob(blob_id) == blob_data

    # Remove second reference - content should be deleted
    assert fs_blob_store.remove_blob_reference(blob_id, "channel2", "user2") == True
    assert fs_blob_store.get_blob(blob_id) is None
