"""
Simple test to verify all imports work correctly.
"""

def test_imports():
    """Test that all public API imports work."""

    # Main client
    from reeeductio import Space

    # Authentication
    from reeeductio import AuthSession, AsyncAuthSession

    # Crypto utilities
    from reeeductio import (
        Ed25519KeyPair,
        generate_keypair,
        sign_data,
        verify_signature,
        compute_hash,
        to_message_id,
        to_blob_id,
        get_identifier_type,
        encode_base64,
        decode_base64,
    )

    # Models
    from reeeductio import (
        Message,
        MessageCreated,
        MessageList,
        Capability,
        CapabilityOp,
        Member,
        Role,
        RoleGrant,
        DataEntry,
        BlobCreated,
        AuthChallenge,
        AuthToken,
        Error,
    )

    # Exceptions
    from reeeductio import (
        ReeeductioError,
        AuthenticationError,
        AuthorizationError,
        ValidationError,
        ChainError,
        ConflictError,
        NotFoundError,
        BlobError,
        NetworkError,
        StreamError,
    )

    print("✓ All imports successful!")

    # Test key generation
    keypair = generate_keypair()
    user_id = keypair.to_user_id()
    space_id = keypair.to_space_id()
    tool_id = keypair.to_tool_id()

    print(f"✓ Generated user ID: {user_id}")
    print(f"✓ Generated space ID: {space_id}")
    print(f"✓ Generated tool ID: {tool_id}")

    # Test identifier type detection
    assert get_identifier_type(user_id) == "USER"
    assert get_identifier_type(space_id) == "SPACE"
    assert get_identifier_type(tool_id) == "TOOL"
    print("✓ Identifier type detection working")

    # Test signing
    data = b"test data"
    signature = sign_data(data, keypair.private_key)
    assert verify_signature(data, signature, keypair.public_key)
    print("✓ Signing and verification working")

    # Test hashing
    hash_bytes = compute_hash(data)
    assert len(hash_bytes) == 32
    message_id = to_message_id(hash_bytes)
    assert message_id.startswith("M")
    assert len(message_id) == 44
    print(f"✓ Hashing working, message ID: {message_id}")

    blob_id = to_blob_id(hash_bytes)
    assert blob_id.startswith("B")
    assert len(blob_id) == 44
    print(f"✓ Blob ID generation working: {blob_id}")

    # Test base64 encoding
    encoded = encode_base64(data)
    decoded = decode_base64(encoded)
    assert decoded == data
    print("✓ Base64 encoding/decoding working")

    # Test Space initialization with symmetric_root
    import os
    symmetric_root = os.urandom(32)

    # Test valid symmetric_root (32 bytes)
    try:
        space = Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=symmetric_root,
            base_url="http://localhost:8000",
            auto_authenticate=False,  # Don't auto-authenticate in test
        )
        assert space.symmetric_root == symmetric_root
        print("✓ Space initialization with symmetric_root working")

        # Verify derived keys exist and are 32 bytes each
        assert hasattr(space, "message_key")
        assert hasattr(space, "blob_key")
        assert hasattr(space, "state_key")
        assert hasattr(space, "data_key")
        assert len(space.message_key) == 32
        assert len(space.blob_key) == 32
        assert len(space.state_key) == 32
        assert len(space.data_key) == 32
        print("✓ All derived keys (message, blob, state, data) generated correctly")

        # Verify keys are different from each other
        assert space.message_key != space.blob_key
        assert space.message_key != space.state_key
        assert space.message_key != space.data_key
        assert space.blob_key != space.state_key
        assert space.blob_key != space.data_key
        assert space.state_key != space.data_key
        print("✓ Derived keys are unique from each other")

        # Verify keys are deterministic (same root produces same keys)
        space2 = Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=symmetric_root,
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )
        assert space.message_key == space2.message_key
        assert space.blob_key == space2.blob_key
        assert space.state_key == space2.state_key
        assert space.data_key == space2.data_key
        print("✓ Key derivation is deterministic")

        # Verify different space_ids produce different keys (even with same root)
        different_space_id = keypair.to_tool_id()  # Use a different ID
        space3 = Space(
            space_id=different_space_id,
            keypair=keypair,
            symmetric_root=symmetric_root,  # Same root!
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )
        assert space.message_key != space3.message_key
        assert space.blob_key != space3.blob_key
        assert space.state_key != space3.state_key
        assert space.data_key != space3.data_key
        print("✓ Different space_ids produce different keys (prevents cross-space key reuse)")
    except Exception as e:
        print(f"✗ Failed to initialize Space: {e}")
        raise

    # Test invalid symmetric_root (wrong size)
    try:
        Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=b"too short",  # Only 9 bytes
            base_url="http://localhost:8000",
        )
        print("✗ Should have raised ValueError for invalid symmetric_root")
        raise AssertionError("Expected ValueError for invalid symmetric_root size")
    except ValueError as e:
        assert "must be exactly 32 bytes" in str(e)
        print("✓ Symmetric root validation working")

    print("\n✅ All tests passed!")


if __name__ == "__main__":
    test_imports()
