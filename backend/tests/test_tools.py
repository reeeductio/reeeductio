"""
Tests for Tool functionality in the authorization system

Tools are limited-use keys with NO ambient authority.
They can only perform actions explicitly granted via capabilities.
"""

import pytest
import base64
import json
from authorization import AuthorizationEngine
from sqlite_state_store import SqliteStateStore
from crypto import CryptoUtils
from identifiers import encode_tool_id, encode_user_id, extract_public_key
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


@pytest.fixture
def authz(temp_db_path):
    """Create AuthorizationEngine with temp storage"""
    state_store = SqliteStateStore(temp_db_path)
    crypto = CryptoUtils()
    return AuthorizationEngine(state_store, crypto)


@pytest.fixture
def tool_keypair():
    """Generate a tool Ed25519 keypair"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    tool_id = encode_tool_id(public_bytes)

    return {
        'private': private_key,
        'public': public_key,
        'public_bytes': public_bytes,
        'tool_id': tool_id
    }


class TestToolIdentifiers:
    """Test tool typed identifiers"""

    def test_tool_id_starts_with_T(self, tool_keypair):
        """Tool IDs should start with 'T'"""
        tool_id = tool_keypair['tool_id']
        assert tool_id[0] == 'T'
        assert len(tool_id) == 44  # 44-char base64

    def test_extract_public_key_from_tool_id(self, tool_keypair):
        """extract_public_key should work with tool IDs"""
        tool_id = tool_keypair['tool_id']
        extracted = extract_public_key(tool_id)
        assert extracted == tool_keypair['public_bytes']


class TestToolNoAmbientAuthority:
    """Test that tools have NO ambient authority"""

    def test_tool_cannot_read_without_capability(self, authz, admin_keypair, tool_keypair, temp_db_path):
        """Tools cannot read anything without explicit capability"""
        channel_id = admin_keypair['channel_id']
        tool_id = tool_keypair['tool_id']

        # Create some state
        state_store = SqliteStateStore(temp_db_path)
        state_store.set_state(
            channel_id,
            "test/data",
            base64.b64encode(b"secret").decode(),
            admin_keypair['user_id'],
            1234567890
        )

        # Tool has NO capabilities - should not be able to read
        assert not authz.check_permission(channel_id, tool_id, "read", "test/data")

    def test_tool_cannot_create_without_capability(self, authz, admin_keypair, tool_keypair):
        """Tools cannot create anything without explicit capability"""
        channel_id = admin_keypair['channel_id']
        tool_id = tool_keypair['tool_id']

        # Tool has NO capabilities - should not be able to create
        assert not authz.check_permission(channel_id, tool_id, "create", "test/newdata")

    def test_tool_cannot_write_without_capability(self, authz, admin_keypair, tool_keypair):
        """Tools cannot write anything without explicit capability"""
        channel_id = admin_keypair['channel_id']
        tool_id = tool_keypair['tool_id']

        # Tool has NO capabilities - should not be able to write
        assert not authz.check_permission(channel_id, tool_id, "write", "test/data")


class TestToolWithCapabilities:
    """Test tools with explicit capabilities"""

    def test_tool_can_use_granted_capability(self, authz, admin_keypair, tool_keypair, temp_db_path):
        """Tool can use capabilities explicitly granted"""
        channel_id = admin_keypair['channel_id']
        admin_id = admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']
        admin_private = admin_keypair['private']

        state_store = SqliteStateStore(temp_db_path)
        crypto = CryptoUtils()

        # Grant tool capability to create user entries
        tool_cap = {
            "op": "create",
            "path": "auth/users/{any}",
            "granted_by": admin_id,
            "granted_at": 1234567890
        }

        # Sign capability (recipient is the tool_id)
        cap_msg = crypto.compute_capability_signature_message(
            channel_id, tool_id, tool_cap["op"], tool_cap["path"], tool_cap["granted_at"]
        )
        tool_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))

        # Store capability for tool
        state_store.set_state(
            channel_id,
            f"auth/tools/{tool_id}/rights/cap_create_users",
            base64.b64encode(json.dumps(tool_cap).encode()).decode(),
            admin_id,
            1234567890
        )

        # Tool should now have permission to create users
        assert authz.check_permission(channel_id, tool_id, "create", "auth/users/U_newuser")

    def test_tool_cannot_exceed_capability(self, authz, admin_keypair, tool_keypair, temp_db_path):
        """Tool cannot perform actions outside its capabilities"""
        channel_id = admin_keypair['channel_id']
        admin_id = admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']
        admin_private = admin_keypair['private']

        state_store = SqliteStateStore(temp_db_path)
        crypto = CryptoUtils()

        # Grant tool capability to create user entries ONLY
        tool_cap = {
            "op": "create",
            "path": "auth/users/{any}",
            "granted_by": admin_id,
            "granted_at": 1234567890
        }

        cap_msg = crypto.compute_capability_signature_message(
            channel_id, tool_id, tool_cap["op"], tool_cap["path"], tool_cap["granted_at"]
        )
        tool_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))

        state_store.set_state(
            channel_id,
            f"auth/tools/{tool_id}/rights/cap_create_users",
            base64.b64encode(json.dumps(tool_cap).encode()).decode(),
            admin_id,
            1234567890
        )

        # Tool can create users
        assert authz.check_permission(channel_id, tool_id, "create", "auth/users/U_newuser")

        # But cannot read other data
        assert not authz.check_permission(channel_id, tool_id, "read", "messages/msg1")

        # Cannot write to users (only create)
        assert not authz.check_permission(channel_id, tool_id, "write", "auth/users/U_existing")

    def test_tool_with_role_grant_capability(self, authz, admin_keypair, tool_keypair, temp_db_path):
        """Test tool that can grant roles"""
        channel_id = admin_keypair['channel_id']
        admin_id = admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']
        admin_private = admin_keypair['private']

        state_store = SqliteStateStore(temp_db_path)
        crypto = CryptoUtils()

        # Create a "user" role first
        user_role = {
            "role_id": "user",
            "description": "Standard user role",
            "created_by": admin_id,
            "created_at": 1234567890,
            "signature": "fake_signature"
        }
        state_store.set_state(
            channel_id,
            "auth/roles/user",
            base64.b64encode(json.dumps(user_role).encode()).decode(),
            admin_id,
            1234567890
        )

        # Grant tool capability to create user entries (not deeper paths!)
        tool_cap1 = {
            "op": "create",
            "path": "auth/users/{any}",
            "granted_by": admin_id,
            "granted_at": 1234567890
        }
        cap_msg = crypto.compute_capability_signature_message(
            channel_id, tool_id, tool_cap1["op"], tool_cap1["path"], tool_cap1["granted_at"]
        )
        tool_cap1["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))
        state_store.set_state(
            channel_id,
            f"auth/tools/{tool_id}/rights/cap_create_users",
            base64.b64encode(json.dumps(tool_cap1).encode()).decode(),
            admin_id,
            1234567890
        )

        # Grant tool capability to assign "user" role
        tool_cap2 = {
            "op": "create",
            "path": "auth/users/{any}/roles/user",
            "granted_by": admin_id,
            "granted_at": 1234567890
        }
        cap_msg = crypto.compute_capability_signature_message(
            channel_id, tool_id, tool_cap2["op"], tool_cap2["path"], tool_cap2["granted_at"]
        )
        tool_cap2["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))
        state_store.set_state(
            channel_id,
            f"auth/tools/{tool_id}/rights/cap_grant_user_role",
            base64.b64encode(json.dumps(tool_cap2).encode()).decode(),
            admin_id,
            1234567890
        )

        # Tool can create users
        assert authz.check_permission(channel_id, tool_id, "create", "auth/users/U_alice")

        # Tool can grant "user" role
        assert authz.check_permission(channel_id, tool_id, "create", "auth/users/U_alice/roles/user")

        # But cannot grant other roles
        assert not authz.check_permission(channel_id, tool_id, "create", "auth/users/U_alice/roles/admin")


class TestToolCreationValidation:
    """Test tool creation validation"""

    def test_is_tool_definition_path(self, authz):
        """Test detection of tool definition paths"""
        assert authz.is_tool_definition_path("auth/tools/T_abc123")
        assert not authz.is_tool_definition_path("auth/tools/T_abc123/rights/cap_001")
        assert not authz.is_tool_definition_path("auth/users/U_abc123")

    def test_is_capability_path_includes_tools(self, authz):
        """Test that is_capability_path includes tool capabilities"""
        assert authz.is_capability_path("auth/tools/T_abc123/rights/cap_001")
        assert authz.is_capability_path("auth/users/U_abc123/rights/cap_001")
        assert authz.is_capability_path("auth/roles/moderator/rights/cap_001")

    def test_verify_tool_creation_path_content_consistency(self, authz, admin_keypair, tool_keypair, temp_db_path):
        """Test path-content consistency for tool creation"""
        channel_id = admin_keypair['channel_id']
        admin_id = admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']

        # Valid: tool_id matches path
        tool_data_valid = {
            "tool_id": tool_id,
            "description": "Test tool",
            "created_by": admin_id,
            "created_at": 1234567890
        }
        assert authz.verify_tool_creation(
            channel_id,
            f"auth/tools/{tool_id}",
            tool_data_valid,
            admin_id,
            "fake_signature"
        )

        # Invalid: tool_id mismatch
        tool_data_invalid = {
            "tool_id": "T_wrongid",
            "description": "Test tool",
            "created_by": admin_id,
            "created_at": 1234567890
        }
        assert not authz.verify_tool_creation(
            channel_id,
            f"auth/tools/{tool_id}",
            tool_data_invalid,
            admin_id,
            "fake_signature"
        )

    def test_channel_creator_can_create_tools(self, authz, admin_keypair, tool_keypair):
        """Channel creator can create any tool"""
        channel_id = admin_keypair['channel_id']
        admin_id = admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']

        tool_data = {
            "tool_id": tool_id,
            "description": "Test tool",
            "created_by": admin_id,
            "created_at": 1234567890
        }

        # Channel creator can create tools
        assert authz.verify_tool_creation(
            channel_id,
            f"auth/tools/{tool_id}",
            tool_data,
            admin_id,
            "fake_signature"
        )

    def test_user_needs_permission_to_create_tools(self, authz, admin_keypair, user_keypair, tool_keypair, temp_db_path):
        """Non-creator users need explicit permission to create tools"""
        channel_id = admin_keypair['channel_id']
        user_id = user_keypair['user_id']
        tool_id = tool_keypair['tool_id']

        tool_data = {
            "tool_id": tool_id,
            "description": "Test tool",
            "created_by": user_id,
            "created_at": 1234567890
        }

        # User without permission cannot create tools
        assert not authz.verify_tool_creation(
            channel_id,
            f"auth/tools/{tool_id}",
            tool_data,
            user_id,
            "fake_signature"
        )

        # Grant user permission to create tools
        state_store = SqliteStateStore(temp_db_path)
        crypto = CryptoUtils()

        user_cap = {
            "op": "create",
            "path": "auth/tools/{any}",
            "granted_by": admin_keypair['user_id'],
            "granted_at": 1234567890
        }
        cap_msg = crypto.compute_capability_signature_message(
            channel_id, user_id, user_cap["op"], user_cap["path"], user_cap["granted_at"]
        )
        user_cap["signature"] = crypto.base64_encode(admin_keypair['private'].sign(cap_msg))

        state_store.set_state(
            channel_id,
            f"auth/users/{user_id}/rights/cap_create_tools",
            base64.b64encode(json.dumps(user_cap).encode()).decode(),
            admin_keypair['user_id'],
            1234567890
        )

        # Now user can create tools
        assert authz.verify_tool_creation(
            channel_id,
            f"auth/tools/{tool_id}",
            tool_data,
            user_id,
            "fake_signature"
        )

    def test_cannot_create_tool_more_powerful_than_self(self, authz, admin_keypair, user_keypair, tool_keypair, temp_db_path):
        """Users cannot create tools with capabilities they don't have (privilege escalation prevention)"""
        channel_id = admin_keypair['channel_id']
        admin_id = admin_keypair['user_id']
        user_id = user_keypair['user_id']
        tool_id = tool_keypair['tool_id']
        admin_private = admin_keypair['private']

        state_store = SqliteStateStore(temp_db_path)
        crypto = CryptoUtils()

        # Give user permission to create tool entries
        user_cap = {
            "op": "create",
            "path": "auth/tools/{any}",
            "granted_by": admin_id,
            "granted_at": 1234567890
        }
        cap_msg = crypto.compute_capability_signature_message(
            channel_id, user_id, user_cap["op"], user_cap["path"], user_cap["granted_at"]
        )
        user_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))
        state_store.set_state(
            channel_id,
            f"auth/users/{user_id}/rights/cap_create_tools",
            base64.b64encode(json.dumps(user_cap).encode()).decode(),
            admin_id,
            1234567890
        )

        # Give user only read permission
        user_read_cap = {
            "op": "read",
            "path": "{any}",
            "granted_by": admin_id,
            "granted_at": 1234567890
        }
        cap_msg = crypto.compute_capability_signature_message(
            channel_id, user_id, user_read_cap["op"], user_read_cap["path"], user_read_cap["granted_at"]
        )
        user_read_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))
        state_store.set_state(
            channel_id,
            f"auth/users/{user_id}/rights/cap_read",
            base64.b64encode(json.dumps(user_read_cap).encode()).decode(),
            admin_id,
            1234567890
        )

        # Create tool definition
        tool_data = {
            "tool_id": tool_id,
            "description": "Privilege escalation attempt",
            "created_by": user_id,
            "created_at": 1234567890
        }

        # Add write capability to the tool (user doesn't have write!)
        tool_write_cap = {
            "op": "write",
            "path": "{any}",
            "granted_by": admin_id,  # Fake - user trying to escalate
            "granted_at": 1234567890
        }
        cap_msg = crypto.compute_capability_signature_message(
            channel_id, tool_id, tool_write_cap["op"], tool_write_cap["path"], tool_write_cap["granted_at"]
        )
        tool_write_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))
        state_store.set_state(
            channel_id,
            f"auth/tools/{tool_id}/rights/cap_write",
            base64.b64encode(json.dumps(tool_write_cap).encode()).decode(),
            admin_id,  # Would be validated separately
            1234567890
        )

        # User should NOT be able to create this tool - it has write capability but user only has read
        assert not authz.verify_tool_creation(
            channel_id,
            f"auth/tools/{tool_id}",
            tool_data,
            user_id,
            "fake_signature"
        )


class TestToolAuthentication:
    """Test that tools can authenticate via challenge/verify"""

    def test_tool_can_authenticate(self, admin_keypair, tool_keypair, temp_db_path):
        """Test that a tool can complete challenge/verify flow"""
        from channel import Channel
        from sqlite_message_store import SqliteMessageStore

        channel_id = admin_keypair['channel_id']
        admin_id = admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']
        admin_private = admin_keypair['private']
        tool_private = tool_keypair['private']

        state_store = SqliteStateStore(temp_db_path)
        message_store = SqliteMessageStore(temp_db_path)
        crypto = CryptoUtils()

        # Create channel
        channel = Channel(
            channel_id=channel_id,
            state_store=state_store,
            message_store=message_store,
            blob_store=None,
            jwt_secret="test_secret_key"
        )

        # Add admin as member
        member_data = {
            "public_key": admin_id,
            "added_at": 1234567890,
            "added_by": admin_id
        }
        state_store.set_state(
            channel_id,
            f"members/{admin_id}",
            base64.b64encode(json.dumps(member_data).encode()).decode(),
            admin_id,
            1234567890
        )

        # Create tool in state
        tool_data = {
            "tool_id": tool_id,
            "description": "Test camera tool",
            "created_by": admin_id,
            "created_at": 1234567890
        }
        state_store.set_state(
            channel_id,
            f"auth/tools/{tool_id}",
            base64.b64encode(json.dumps(tool_data).encode()).decode(),
            admin_id,
            1234567890
        )

        # Grant tool capability to create messages
        tool_cap = {
            "op": "create",
            "path": "messages/{...}",
            "granted_by": admin_id,
            "granted_at": 1234567890
        }
        cap_msg = crypto.compute_capability_signature_message(
            channel_id, tool_id, tool_cap["op"], tool_cap["path"], tool_cap["granted_at"]
        )
        tool_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))
        state_store.set_state(
            channel_id,
            f"auth/tools/{tool_id}/rights/cap_messages",
            base64.b64encode(json.dumps(tool_cap).encode()).decode(),
            admin_id,
            1234567890
        )

        # Test authentication flow
        # 1. Create challenge
        challenge_response = channel.create_challenge(tool_id)
        challenge = challenge_response['challenge']

        # 2. Sign challenge with tool's private key
        message = challenge.encode('utf-8')
        signature = tool_private.sign(message)
        signature_b64 = base64.b64encode(signature).decode()

        # 3. Verify challenge - should succeed
        assert channel.verify_challenge(tool_id, challenge, signature_b64)

        # 4. Get JWT token
        token_response = channel.create_jwt(tool_id)
        assert 'token' in token_response
        assert 'expires_at' in token_response

        # 5. Verify tool has permissions via capability (not ambient authority)
        assert channel.authz.check_permission(channel_id, tool_id, "create", "messages/msg1")
        # Tool should NOT have read permission (no ambient authority)
        assert not channel.authz.check_permission(channel_id, tool_id, "read", "messages/msg1")

    def test_tool_not_registered_cannot_authenticate(self, tool_keypair, temp_db_path, admin_keypair):
        """Test that unregistered tools cannot authenticate"""
        from channel import Channel
        from sqlite_message_store import SqliteMessageStore
        import pytest

        channel_id = admin_keypair['channel_id']
        tool_id = tool_keypair['tool_id']
        tool_private = tool_keypair['private']

        state_store = SqliteStateStore(temp_db_path)
        message_store = SqliteMessageStore(temp_db_path)

        # Create channel
        channel = Channel(
            channel_id=channel_id,
            state_store=state_store,
            message_store=message_store,
            blob_store=None,
            jwt_secret="test_secret_key"
        )

        # Try to authenticate without registering tool
        challenge_response = channel.create_challenge(tool_id)
        challenge = challenge_response['challenge']

        message = challenge.encode('utf-8')
        signature = tool_private.sign(message)
        signature_b64 = base64.b64encode(signature).decode()

        # Should fail - tool not registered in channel
        with pytest.raises(ValueError) as exc_info:
            channel.verify_challenge(tool_id, challenge, signature_b64)
        assert "not a member" in str(exc_info.value).lower()
