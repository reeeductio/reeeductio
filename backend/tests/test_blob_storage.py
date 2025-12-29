"""
Tests for blob storage backends (filesystem and database)
"""
import pytest

from identifiers import encode_user_id


def test_fs_blob_upload(fs_blob_store, crypto):
    """Test filesystem blob upload"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)

    fs_blob_store.add_blob(blob_id, blob_data)
    retrieved = fs_blob_store.get_blob(blob_id)

    assert retrieved == blob_data


def test_fs_blob_duplicate_rejection(fs_blob_store, crypto):
    """Test that filesystem store rejects duplicate blobs"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)

    fs_blob_store.add_blob(blob_id, blob_data)

    with pytest.raises(FileExistsError):
        fs_blob_store.add_blob(blob_id, blob_data)


def test_fs_blob_invalid_id_rejection(fs_blob_store):
    """Test that filesystem store rejects invalid blob IDs"""
    # USER type instead of BLOB
    invalid_id = encode_user_id(b"x" * 32)
    blob_data = b"some data"

    with pytest.raises(ValueError, match="BLOB type"):
        fs_blob_store.add_blob(invalid_id, blob_data)


def test_fs_blob_retrieval_nonexistent(fs_blob_store, crypto):
    """Test retrieval of non-existent blob returns None"""
    non_existent_id = crypto.compute_blob_id(b"different content")
    assert fs_blob_store.get_blob(non_existent_id) is None


def test_fs_blob_deletion(fs_blob_store, crypto):
    """Test filesystem blob deletion"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)

    fs_blob_store.add_blob(blob_id, blob_data)
    assert fs_blob_store.delete_blob(blob_id) == True
    assert fs_blob_store.get_blob(blob_id) is None


def test_fs_blob_deletion_nonexistent(fs_blob_store, crypto):
    """Test deleting non-existent blob returns False"""
    blob_id = crypto.compute_blob_id(b"nonexistent")
    assert fs_blob_store.delete_blob(blob_id) == False


def test_db_blob_upload(db_blob_store, crypto):
    """Test database blob upload"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)

    db_blob_store.add_blob(blob_id, blob_data)
    retrieved = db_blob_store.get_blob(blob_id)

    assert retrieved == blob_data


def test_db_blob_deletion(db_blob_store, crypto):
    """Test database blob deletion"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)

    db_blob_store.add_blob(blob_id, blob_data)
    assert db_blob_store.delete_blob(blob_id) == True
    assert db_blob_store.get_blob(blob_id) is None


def test_db_blob_deletion_nonexistent(db_blob_store, crypto):
    """Test deleting non-existent blob from database returns False"""
    blob_id = crypto.compute_blob_id(b"nonexistent")
    assert db_blob_store.delete_blob(blob_id) == False
