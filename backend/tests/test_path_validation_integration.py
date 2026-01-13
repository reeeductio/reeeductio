"""
Integration tests for path validation in space operations
"""

import pytest
from space import Space
from sqlite_data_store import SqliteDataStore
from sqlite_message_store import SqliteMessageStore
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from identifiers import encode_space_id, encode_user_id
import base64

import sys
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

import conftest
sign_data_entry = conftest.sign_data_entry
sign_and_store_data = conftest.sign_and_store_data
set_space_state = conftest.set_space_state
delete_space_state = conftest.delete_space_state
authenticate_with_challenge = conftest.authenticate_with_challenge


@pytest.fixture
def space(admin_keypair, data_store, message_store):
    """Create a test space"""

    space_id = admin_keypair['space_id']
    space = Space(
        space_id=space_id,
        data_store=data_store,
        message_store=message_store,
        blob_store=None,
        jwt_secret="test_secret_key_for_testing"
    )

    return space


@pytest.fixture
def admin_token(space, admin_keypair):
    """Get JWT token for admin"""
    # Create challenge
    challenge_response = space.create_challenge(admin_keypair['user_id'])
    challenge = challenge_response['challenge']

    # Sign challenge (sign the base64 string encoded as UTF-8)
    message = challenge.encode('utf-8')
    signature = admin_keypair['private'].sign(message)
    signature_b64 = base64.b64encode(signature).decode()

    # Verify challenge
    space.verify_challenge(
        admin_keypair['user_id'],
        challenge,
        signature_b64
    )

    # Create and return JWT token
    token_response = space.create_jwt(admin_keypair['user_id'])
    return token_response['token']


class TestStatePathValidation:
    """Test path validation in state operations"""

    def test_valid_state_paths_accepted(self, space, admin_token, admin_keypair):
        """Test that valid paths are accepted"""
        valid_paths = [
            "state/profiles/alice",
            "topics/general/messages",
            "data/files/photo.jpg",
            "state/api/v1.0/users",
            "data/settings/theme",
        ]

        for path in valid_paths:
            data = {"data": "test"}
            # Should not raise
            set_space_state(space, path, data, admin_token, admin_keypair)

    def test_wildcard_injection_prevented(self, space, admin_token, admin_keypair):
        """Test that wildcards cannot be injected in user paths"""
        invalid_paths = [
            "state/profiles/{self}",
            "topics/{any}/messages",
            "state/auth/users/{other}/roles",
        ]

        for path in invalid_paths:
            data = {"data": "something"}
            with pytest.raises(ValueError) as exc_info:
                set_space_state(space, path, data, admin_token, admin_keypair)
            assert "reserved wildcard" in str(exc_info.value).lower()

    def test_braced_expressions_prevented(self, space, admin_token, admin_keypair):
        """Test that braced expressions cannot be used in paths"""
        invalid_paths = [
            "users/{custom}",
            "data/{id}",
            "files/{foo}/bar",
        ]

        for path in invalid_paths:
            data = {"blah": "blah"}
            with pytest.raises(ValueError) as exc_info:
                set_space_state(space, path, data, admin_token, admin_keypair)
            assert "braces" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()

    def test_special_characters_prevented(self, space, admin_token, admin_keypair):
        """Test that special characters are rejected"""
        invalid_paths = [
            "my file",           # Space
            "user@email/data",   # @
            "test/path?query",   # ?
            "data#anchor",       # #
        ]

        for path in invalid_paths:
            data = {"blah": "blah"}
            with pytest.raises(ValueError) as exc_info:
                set_space_state(space, path, data, admin_token, admin_keypair)
            assert "invalid" in str(exc_info.value).lower()

    def test_dots_allowed_in_paths(self, space, admin_token, admin_keypair):
        """Test that dots are allowed for file extensions and versioning"""
        valid_paths = [
            "files/photo.jpg",
            "documents/report.pdf",
            "api/v1.0/users",
            "config/app.yaml",
        ]

        for path in valid_paths:
            data = {"blah": "blah"}
            set_space_state(space, path, data, admin_token, admin_keypair)

    def test_get_state_validates_path(self, space, admin_token, admin_keypair):
        """Test that get_state also validates paths"""
        # Valid path works
        valid_path = "test/data"
        data = {"test": "data"}
        set_space_state(space, valid_path, data, admin_token, admin_keypair)

        result = space.get_state(valid_path, admin_token)
        assert result is not None

        # Invalid path rejected
        with pytest.raises(ValueError) as exc_info:
            space.get_state("test/{self}", admin_token)
        assert "invalid" in str(exc_info.value).lower()

    def test_delete_state_validates_path(self, space, admin_token, admin_keypair):
        """Test that delete_state also validates paths"""
        # Create valid state
        valid_path = "test/data"
        data = {"test": "data"}
        set_space_state(space, valid_path, data, admin_token, admin_keypair)

        # Valid deletion works
        delete_space_state(space, valid_path, admin_token, admin_keypair)

        # Invalid path rejected
        with pytest.raises(ValueError) as exc_info:
            delete_space_state(space, "test/{any}", admin_token, admin_keypair)
        assert "invalid" in str(exc_info.value).lower()


class TestCapabilityPathValidation:
    """Test path validation for capability grants"""

    def test_capability_with_valid_wildcards_accepted(self, space, admin_keypair, admin_token, crypto):
        """Test that capabilities with valid wildcards are accepted"""

        # Create capability with {self} wildcard
        capability = {
            "op": "write",
            "path": "state/profiles/{self}/"
        }
        cap_path = f"auth/users/{admin_keypair['user_id']}/rights/cap_001"

        # Store capability - should not raise with valid wildcard
        set_space_state(space, cap_path, capability, admin_token, admin_keypair)

    def test_capability_with_unknown_wildcard_rejected(self, space, admin_keypair, admin_token, crypto):
        """Test that capabilities with unknown wildcards are rejected"""

        # Create capability with unknown {custom} wildcard
        capability = {
            "op": "write",
            "path": "state/users/{custom}/"
        }

        # Grant the cap to some random user and try to validate
        import secrets
        cap_path = f"auth/users/{secrets.token_hex(16)}/rights/cap_002"

        with pytest.raises(ValueError) as exc_info:
            set_space_state(space, cap_path, capability, admin_token, admin_keypair)
        assert "invalid capability grant" in str(exc_info.value).lower()
