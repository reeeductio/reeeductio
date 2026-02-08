"""
Tests for cryptographic operations
"""
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from identifiers import encode_user_id, decode_identifier


def test_signature_verification(crypto):
    """Test signature verification works correctly"""
    # Generate keypair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()

    # Sign message
    message = b"Hello, world!"
    signature = private_key.sign(message)

    # Verify signature
    assert crypto.verify_signature(message, signature, public_key_bytes)


def test_invalid_signature_rejection(crypto):
    """Test that invalid signatures are rejected"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()

    message = b"Hello, world!"
    signature = private_key.sign(message)

    # Wrong message should fail verification
    assert not crypto.verify_signature(b"Wrong message", signature, public_key_bytes)


def test_base64_encoding(crypto):
    """Test base64 encoding and decoding"""
    data = b"test data"
    encoded = crypto.base64_encode(data)
    decoded = crypto.base64_decode(encoded)
    assert decoded == data


def test_message_hashing(crypto):
    """Test message hash computation with typed identifiers"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes_raw()
    sender_id = encode_user_id(public_key_bytes)

    msg_hash = crypto.compute_message_hash(
        "space1",
        "general-chat",
        "chat.text",
        None,
        "data",
        sender_id
    )

    # Typed message ID is 44 chars base64
    assert len(msg_hash) == 44
    # Message type indicator
    assert msg_hash.startswith('M')


def test_message_signature_verification(crypto):
    """Test message signature verification"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes_raw()
    sender_id = encode_user_id(public_key_bytes)

    msg_hash = crypto.compute_message_hash(
        "space1",
        "general-chat",
        "chat.text",
        None,
        "data",
        sender_id
    )

    # Sign the full typed identifier bytes
    msg_tid = decode_identifier(msg_hash)
    msg_signature = private_key.sign(msg_tid.to_bytes())

    assert crypto.verify_message_signature(msg_hash, msg_signature, public_key_bytes)


def test_blob_id_computation(crypto):
    """Test blob ID computation"""
    test_data = b"Hello, World!"
    blob_id = crypto.compute_blob_id(test_data)

    # Should be 44 chars
    assert len(blob_id) == 44

    # Should be BLOB type
    decoded = decode_identifier(blob_id)
    from identifiers import IdType
    assert decoded.id_type == IdType.BLOB
