"""
Tests for HKDF key derivation in reeeductio SDK.

Tests verify:
- Key derivation correctness
- Domain separation (space_id scoping)
- Determinism
- Security properties
"""

import os

import pytest

from reeeductio import Space, derive_key, generate_keypair


class TestDeriveKey:
    """Tests for the derive_key function."""

    def test_derive_key_basic(self):
        """Test basic key derivation."""
        root = os.urandom(32)
        key = derive_key(root, "test context")

        assert len(key) == 32, "Default key length should be 32 bytes"
        assert isinstance(key, bytes), "Derived key should be bytes"

    def test_derive_key_custom_length(self):
        """Test key derivation with custom length."""
        root = os.urandom(32)
        key = derive_key(root, "test context", length=16)

        assert len(key) == 16, "Custom key length should be respected"

    def test_derive_key_deterministic(self):
        """Test that derivation is deterministic."""
        root = os.urandom(32)
        key1 = derive_key(root, "test context")
        key2 = derive_key(root, "test context")

        assert key1 == key2, "Same root + same info should produce same key"

    def test_derive_key_different_contexts(self):
        """Test that different contexts produce different keys."""
        root = os.urandom(32)
        key1 = derive_key(root, "context A")
        key2 = derive_key(root, "context B")

        assert key1 != key2, "Different contexts should produce different keys"

    def test_derive_key_different_roots(self):
        """Test that different roots produce different keys."""
        root1 = os.urandom(32)
        root2 = os.urandom(32)
        key1 = derive_key(root1, "test context")
        key2 = derive_key(root2, "test context")

        assert key1 != key2, "Different roots should produce different keys"


class TestSpaceKeyDerivation:
    """Tests for Space client key derivation."""

    def test_space_derives_all_keys(self):
        """Test that Space derives all required keys on init."""
        keypair = generate_keypair()
        space_id = keypair.to_space_id()
        root = os.urandom(32)

        space = Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=root,
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )

        # Verify all keys exist
        assert hasattr(space, "message_key")
        assert hasattr(space, "blob_key")
        assert hasattr(space, "state_key")
        assert hasattr(space, "data_key")

        # Verify all keys are 32 bytes
        assert len(space.message_key) == 32
        assert len(space.blob_key) == 32
        assert len(space.state_key) == 32
        assert len(space.data_key) == 32

    def test_space_keys_are_unique(self):
        """Test that derived keys are different from each other."""
        keypair = generate_keypair()
        space_id = keypair.to_space_id()
        root = os.urandom(32)

        space = Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=root,
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )

        # All keys should be different
        keys = [space.message_key, space.blob_key, space.state_key, space.data_key]
        assert len(keys) == len(set(keys)), "All derived keys should be unique"

    def test_space_key_derivation_matches_manual(self):
        """Test that Space derivation matches manual derive_key calls."""
        keypair = generate_keypair()
        space_id = keypair.to_space_id()
        root = os.urandom(32)

        # Manual derivation
        message_key = derive_key(root, f"message key | {space_id}")
        blob_key = derive_key(root, f"blob key | {space_id}")
        state_key = derive_key(message_key, "topic key | state")
        data_key = derive_key(root, f"data key | {space_id}")

        # Space derivation
        space = Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=root,
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )

        # Should match
        assert space.message_key == message_key
        assert space.blob_key == blob_key
        assert space.state_key == state_key
        assert space.data_key == data_key

    def test_space_key_derivation_deterministic(self):
        """Test that same inputs always produce same keys."""
        keypair = generate_keypair()
        space_id = keypair.to_space_id()
        root = os.urandom(32)

        space1 = Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=root,
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )

        space2 = Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=root,
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )

        # Keys should be identical
        assert space1.message_key == space2.message_key
        assert space1.blob_key == space2.blob_key
        assert space1.state_key == space2.state_key
        assert space1.data_key == space2.data_key


class TestDomainSeparation:
    """Tests for domain separation (space_id scoping)."""

    def test_different_spaces_different_keys(self):
        """Test that different space_ids produce different keys even with same root.

        This is critical for security: prevents cross-space key reuse.
        """
        keypair = generate_keypair()
        root = os.urandom(32)  # Same root!

        # Two different spaces
        space_id_1 = keypair.to_space_id()
        space_id_2 = keypair.to_tool_id()  # Different ID

        space1 = Space(
            space_id=space_id_1,
            keypair=keypair,
            symmetric_root=root,
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )

        space2 = Space(
            space_id=space_id_2,
            keypair=keypair,
            symmetric_root=root,  # Same root!
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )

        # Keys MUST be different despite same root
        assert space1.message_key != space2.message_key
        assert space1.blob_key != space2.blob_key
        assert space1.state_key != space2.state_key
        assert space1.data_key != space2.data_key

    def test_space_id_included_in_derivation(self):
        """Test that space_id is actually included in the HKDF info parameter."""
        keypair = generate_keypair()
        space_id = keypair.to_space_id()
        root = os.urandom(32)

        # Derive manually without space_id (insecure)
        key_without_space = derive_key(root, "message key")

        # Derive with space_id (secure)
        key_with_space = derive_key(root, f"message key | {space_id}")

        # Derive via Space client (should match secure version)
        space = Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=root,
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )

        # Space should use the secure version
        assert space.message_key == key_with_space
        assert space.message_key != key_without_space


class TestSecurityProperties:
    """Tests for security properties of key derivation."""

    def test_no_key_reuse_across_types(self):
        """Test that message/blob/state/data keys are all different."""
        keypair = generate_keypair()
        space_id = keypair.to_space_id()
        root = os.urandom(32)

        space = Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=root,
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )

        # Create set to check uniqueness
        all_keys = {
            space.message_key,
            space.blob_key,
            space.state_key,
            space.data_key,
        }

        assert len(all_keys) == 4, "All key types should produce unique keys"

    def test_no_key_reuse_across_spaces(self):
        """Test defense against accidental root reuse across spaces."""
        keypair = generate_keypair()
        root = os.urandom(32)

        # Create multiple spaces with same root (user error scenario)
        spaces = []
        for i in range(5):
            # Generate different space IDs
            temp_keypair = generate_keypair()
            space_id = temp_keypair.to_space_id()

            space = Space(
                space_id=space_id,
                keypair=keypair,
                symmetric_root=root,  # Same root!
                base_url="http://localhost:8000",
                auto_authenticate=False,
            )
            spaces.append(space)

        # Collect all message keys
        message_keys = [s.message_key for s in spaces]

        # All should be different despite same root
        assert len(message_keys) == len(set(message_keys)), "Different spaces should have different keys"

    def test_symmetric_root_validation(self):
        """Test that symmetric_root size is validated."""
        keypair = generate_keypair()
        space_id = keypair.to_space_id()

        # Too short
        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            Space(
                space_id=space_id,
                keypair=keypair,
                symmetric_root=b"too short",
                base_url="http://localhost:8000",
            )

        # Too long
        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            Space(
                space_id=space_id,
                keypair=keypair,
                symmetric_root=os.urandom(64),
                base_url="http://localhost:8000",
            )

        # Just right (should not raise)
        Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=os.urandom(32),
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_empty_info_string(self):
        """Test that empty info string is handled."""
        root = os.urandom(32)
        key = derive_key(root, "")

        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_unicode_in_info(self):
        """Test that unicode in info string is handled correctly."""
        root = os.urandom(32)
        key = derive_key(root, "test 🔑 context")

        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_very_long_info(self):
        """Test that very long info strings are handled."""
        root = os.urandom(32)
        long_info = "x" * 10000
        key = derive_key(root, long_info)

        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_special_characters_in_space_id(self):
        """Test that space_id with special characters is handled."""
        keypair = generate_keypair()
        # Use an actual typed ID which may contain special base64 chars
        space_id = keypair.to_space_id()  # Contains -, _, etc.
        root = os.urandom(32)

        space = Space(
            space_id=space_id,
            keypair=keypair,
            symmetric_root=root,
            base_url="http://localhost:8000",
            auto_authenticate=False,
        )

        # Should work fine
        assert len(space.message_key) == 32
