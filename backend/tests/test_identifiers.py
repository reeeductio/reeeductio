"""
Tests for typed identifiers

Verifies that the 264-bit (33-byte, 44-char base64) typed identifier
format works correctly with Ed25519 keys and SHA256 hashes.
"""
import pytest
import secrets

from identifiers import (
    TypedIdentifier, IdType,
    encode_space_id, encode_user_id, encode_message_id, encode_blob_id,
    extract_public_key, extract_hash, decode_identifier
)


def test_basic_encoding_decoding():
    """Test basic encoding and decoding of typed identifiers"""
    # Generate some test data (32 bytes)
    test_key = secrets.token_bytes(32)
    test_hash = secrets.token_bytes(32)

    # Test space ID
    space_id = encode_space_id(test_key)
    assert len(space_id) == 44, "Space ID should be 44 characters"

    decoded = decode_identifier(space_id)
    assert decoded.id_type == IdType.SPACE
    assert decoded.data == test_key
    assert decoded.version == 0

    # Test user ID
    user_id = encode_user_id(test_key)
    assert len(user_id) == 44
    decoded = decode_identifier(user_id)
    assert decoded.id_type == IdType.USER

    # Test message ID
    message_id = encode_message_id(test_hash)
    assert len(message_id) == 44
    decoded = decode_identifier(message_id)
    assert decoded.id_type == IdType.MESSAGE

    # Test blob ID
    blob_id = encode_blob_id(test_hash)
    assert len(blob_id) == 44
    decoded = decode_identifier(blob_id)
    assert decoded.id_type == IdType.BLOB


def test_extract_functions():
    """Test extraction of raw bytes from typed identifiers"""
    test_key = secrets.token_bytes(32)
    test_hash = secrets.token_bytes(32)

    # Test extracting public key
    space_id = encode_space_id(test_key)
    extracted_key = extract_public_key(space_id)
    assert extracted_key == test_key

    # Test extracting hash
    message_id = encode_message_id(test_hash)
    extracted_hash = extract_hash(message_id)
    assert extracted_hash == test_hash


def test_type_validation():
    """Test that extraction functions validate types correctly"""
    test_key = secrets.token_bytes(32)
    test_hash = secrets.token_bytes(32)

    space_id = encode_space_id(test_key)
    message_id = encode_message_id(test_hash)

    # Should work
    extract_public_key(space_id)

    # Should fail - message ID is not a public key type
    with pytest.raises(ValueError):
        extract_public_key(message_id)

    # Should work
    extract_hash(message_id)

    # Should fail - space ID is not a hash type
    with pytest.raises(ValueError):
        extract_hash(space_id)


def test_crypto_integration(crypto):
    """Test that CryptoUtils works with typed identifiers"""
    # Test blob ID computation
    test_data = b"Hello, World!"
    blob_id = crypto.compute_blob_id(test_data)
    assert len(blob_id) == 44

    # Verify it's the correct type
    decoded = decode_identifier(blob_id)
    assert decoded.id_type == IdType.BLOB

    # Test message hash computation
    space_id = encode_space_id(secrets.token_bytes(32))
    sender_id = encode_user_id(secrets.token_bytes(32))
    topic = "test-topic"
    payload = crypto.base64_encode(b"encrypted payload")

    message_hash = crypto.compute_message_hash(
        space_id,
        topic,
        "test",  # msg_type
        None,  # First message
        payload,
        sender_id
    )
    assert len(message_hash) == 44

    decoded = decode_identifier(message_hash)
    assert decoded.id_type == IdType.MESSAGE


def test_no_padding():
    """Verify that base64 encoding produces no padding"""
    # 33 bytes should encode to exactly 44 chars with no '=' padding
    test_data = secrets.token_bytes(32)
    space_id = encode_space_id(test_data)

    assert '=' not in space_id, "Base64 should have no padding"
    assert len(space_id) == 44


def test_url_safe():
    """Verify that identifiers are URL-safe (no + or /)"""
    # Generate many identifiers to increase chance of getting + or / if not URL-safe
    for _ in range(100):
        test_data = secrets.token_bytes(32)
        space_id = encode_space_id(test_data)
        user_id = encode_user_id(test_data)
        message_id = encode_message_id(test_data)
        blob_id = encode_blob_id(test_data)

        for identifier in [space_id, user_id, message_id, blob_id]:
            assert '+' not in identifier, f"Found non-URL-safe '+' in {identifier}"
            assert '/' not in identifier, f"Found non-URL-safe '/' in {identifier}"
            # Should only contain A-Z, a-z, 0-9, -, _
            assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in identifier)


def test_different_types_different_ids():
    """Verify that the same data produces different IDs for different types"""
    test_data = secrets.token_bytes(32)

    space_id = encode_space_id(test_data)
    user_id = encode_user_id(test_data)
    message_id = encode_message_id(test_data)
    blob_id = encode_blob_id(test_data)

    # All should be different despite same underlying data
    ids = {space_id, user_id, message_id, blob_id}
    assert len(ids) == 4, "All typed IDs should be different"
