"""
Tests for Tool functionality in the authorization system

Tools are limited-use keys with NO ambient authority.
They can only perform actions explicitly granted via capabilities.
"""

import pytest
import base64
import json
import sys
import time
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

from authorization import AuthorizationEngine
from identifiers import encode_tool_id, extract_public_key
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import conftest
set_space_state = conftest.set_space_state
authenticate_with_challenge = conftest.authenticate_with_challenge


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
        'tool_id': tool_id,
        'id': tool_id
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

    def test_tool_cannot_read_without_capability(self, unique_space, unique_admin_keypair, tool_keypair):
        """Tools cannot read anything without explicit capability"""
        space_id = unique_admin_keypair['space_id']
        tool_id = tool_keypair['tool_id']
        admin_token = authenticate_with_challenge(unique_space, unique_admin_keypair['user_id'], unique_admin_keypair['private'])

        # Create some state
        set_space_state(
            space=unique_space,
            path="test/data",
            contents={"secret": "12345"},
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Tool has NO capabilities - should not be able to read
        assert not unique_space.authz.check_permission(space_id, tool_id, "read", "test/data")

    def test_tool_cannot_create_without_capability(self, unique_space, unique_admin_keypair, tool_keypair):
        """Tools cannot create anything without explicit capability"""
        space_id = unique_admin_keypair['space_id']
        tool_id = tool_keypair['tool_id']

        # Tool has NO capabilities - should not be able to create
        assert not unique_space.authz.check_permission(space_id, tool_id, "create", "test/newdata")

    def test_tool_cannot_write_without_capability(self, unique_space, unique_admin_keypair, tool_keypair):
        """Tools cannot write anything without explicit capability"""
        space_id = unique_admin_keypair['space_id']
        tool_id = tool_keypair['tool_id']

        # Tool has NO capabilities - should not be able to write
        assert not unique_space.authz.check_permission(space_id, tool_id, "write", "test/data")


class TestToolWithCapabilities:
    """Test tools with explicit capabilities"""

    def test_tool_can_use_granted_capability(self, unique_space, unique_admin_keypair, tool_keypair):
        """Tool can use capabilities explicitly granted"""
        space_id = unique_admin_keypair['space_id']
        admin_id = unique_admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']
        admin_private = unique_admin_keypair['private']

        admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

        # First, register the tool in the space (required for chain of trust)
        tool_info = {"tool_id": tool_id}
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}",
            contents=tool_info,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Grant tool capability to create user entries
        tool_cap = {
            "op": "create",
            "path": "auth/users/{any}"
        }

        # Store capability for tool
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}/rights/cap_create_users",
            contents=tool_cap,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Tool should now have permission to create users
        assert unique_space.authz.check_permission(space_id, tool_id, "create", "auth/users/U_newuser")

    def test_tool_cannot_exceed_capability(self, unique_space, unique_admin_keypair, tool_keypair):
        """Tool cannot perform actions outside its capabilities"""
        space_id = unique_admin_keypair['space_id']
        admin_id = unique_admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']
        admin_private = unique_admin_keypair['private']

        admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

        # First, register the tool in the space
        tool_info = {"tool_id": tool_id}
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}",
            contents=tool_info,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Grant tool capability to create user entries ONLY
        tool_cap = {
            "op": "create",
            "path": "auth/users/{any}"
        }
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}/rights/cap_create_users",
            contents=tool_cap,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Tool can create users
        assert unique_space.authz.check_permission(space_id, tool_id, "create", "auth/users/U_newuser")

        # But cannot read other data
        assert not unique_space.authz.check_permission(space_id, tool_id, "read", "messages/msg1")

        # Cannot write to users (only create)
        assert not unique_space.authz.check_permission(space_id, tool_id, "write", "auth/users/U_existing")

    def test_tool_with_role_grant_capability(self, unique_space, unique_admin_keypair, tool_keypair):
        """Test tool that can grant roles"""
        space_id = unique_admin_keypair['space_id']
        admin_id = unique_admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']
        admin_private = unique_admin_keypair['private']

        admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

        # First, register the tool in the space
        tool_info = {"tool_id": tool_id}
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}",
            contents=tool_info,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Create a "user" role first
        user_role = {
            "role_id": "user",
            "description": "Standard user role"
        }
        set_space_state(
            space=unique_space,
            path="auth/roles/user",
            contents=user_role,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Grant tool capability to create user entries (not deeper paths!)
        tool_cap1 = {
            "op": "create",
            "path": "auth/users/{any}"
        }
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}/rights/cap_create_users",
            contents=tool_cap1,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Grant tool capability to assign "user" role
        tool_cap2 = {
            "op": "create",
            "path": "auth/users/{any}/roles/user"
        }
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}/rights/cap_grant_user_role",
            contents=tool_cap2,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Tool can create users
        assert unique_space.authz.check_permission(space_id, tool_id, "create", "auth/users/U_alice")

        # Tool can grant "user" role
        assert unique_space.authz.check_permission(space_id, tool_id, "create", "auth/users/U_alice/roles/user")

        # But cannot grant other roles
        assert not unique_space.authz.check_permission(space_id, tool_id, "create", "auth/users/U_alice/roles/admin")


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
        space_id = admin_keypair['space_id']
        admin_id = admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']

        # Valid: tool_id matches path
        tool_data_valid = {
            "tool_id": tool_id,
            "description": "Test tool"
        }
        assert authz.verify_tool_creation(
            space_id,
            f"auth/tools/{tool_id}",
            tool_data_valid,
            admin_id,
            "fake_signature"
        )

        # Invalid: tool_id mismatch
        tool_data_invalid = {
            "tool_id": "T_wrongid",
            "description": "Test tool"
        }
        assert not authz.verify_tool_creation(
            space_id,
            f"auth/tools/{tool_id}",
            tool_data_invalid,
            admin_id,
            "fake_signature"
        )

    def test_space_creator_can_create_tools(self, authz, admin_keypair, tool_keypair):
        """Space creator can create any tool"""
        space_id = admin_keypair['space_id']
        admin_id = admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']

        tool_data = {
            "tool_id": tool_id,
            "description": "Test tool"
        }

        # Space creator can create tools
        assert authz.verify_tool_creation(
            space_id,
            f"auth/tools/{tool_id}",
            tool_data,
            admin_id,
            "fake_signature"
        )

    def test_user_needs_permission_to_create_tools(self, unique_space, unique_admin_keypair, user_keypair, tool_keypair):
        """Non-creator users need explicit permission to create tools"""
        space_id = unique_admin_keypair['space_id']
        user_id = user_keypair['user_id']
        tool_id = tool_keypair['tool_id']
        admin_id = unique_admin_keypair['user_id']
        admin_private = unique_admin_keypair['private']

        admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

        # First, add the user to the space (required for chain of trust)
        user_info = {"user_id": user_id}
        set_space_state(
            space=unique_space,
            path=f"auth/users/{user_id}",
            contents=user_info,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        tool_data = {
            "tool_id": tool_id,
            "description": "Test tool"
        }

        # User without permission cannot create tools
        assert not unique_space.authz.verify_tool_creation(
            space_id,
            f"auth/tools/{tool_id}",
            tool_data,
            user_id,
            "fake_signature"
        )

        # Grant user permission to create tools
        user_cap = {
            "op": "create",
            "path": "auth/tools/{any}"
        }
        set_space_state(
            space=unique_space,
            path=f"auth/users/{user_id}/rights/cap_create_tools",
            contents=user_cap,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Now user can create tools
        assert unique_space.authz.verify_tool_creation(
            space_id,
            f"auth/tools/{tool_id}",
            tool_data,
            user_id,
            "fake_signature"
        )

    def test_cannot_create_tool_more_powerful_than_self(self, unique_space, unique_admin_keypair, user_keypair, tool_keypair):
        """Users cannot create tools with capabilities they don't have (privilege escalation prevention)"""
        space_id = unique_admin_keypair['space_id']
        admin_id = unique_admin_keypair['user_id']
        user_id = user_keypair['user_id']
        tool_id = tool_keypair['tool_id']
        admin_private = unique_admin_keypair['private']
        user_private = user_keypair['private']

        admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

        # First, add the user to the space (required for chain of trust)
        user_info = {"user_id": user_id}
        set_space_state(
            space=unique_space,
            path=f"auth/users/{user_id}",
            contents=user_info,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Give user permission to create tool entries
        user_cap = {
            "op": "create",
            "path": "auth/tools/{any}"
        }
        set_space_state(
            space=unique_space,
            path=f"auth/users/{user_id}/rights/cap_create_tools",
            contents=user_cap,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Give user only read permission
        user_read_cap = {
            "op": "read",
            "path": "{any}"
        }
        set_space_state(
            space=unique_space,
            path=f"auth/users/{user_id}/rights/cap_read",
            contents=user_read_cap,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Create tool definition
        tool_info = {
            "tool_id": tool_id,
            "description": "Privilege escalation attempt"
        }
        # User SHOULD be able to create the bare tool with no capabilities
        assert unique_space.authz.verify_tool_creation(
            space_id,
            f"auth/tools/{tool_id}",
            tool_info,
            user_id,
            "fake_signature"
        )
        # Actually create the bare tool (as the user, not the admin)
        user_token = authenticate_with_challenge(unique_space, user_id, user_private)
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}",
            contents=tool_info,
            token=user_token,
            keypair=user_keypair
        )

        # Adding write capability to the tool should fail (user doesn't have write!)
        tool_write_cap = {
            "op": "write",
            "path": "{any}"
        }
        assert not unique_space.authz.verify_capability_grant(
            space_id,
            f"auth/tools/{tool_id}/rights/write_anything",
            tool_write_cap,
            user_id
        )


class TestToolAuthentication:
    """Test that tools can authenticate via challenge/verify"""

    def test_tool_can_authenticate(self, unique_space, unique_admin_keypair, tool_keypair):
        """Test that a tool can complete challenge/verify flow"""
        space_id = unique_admin_keypair['space_id']
        admin_id = unique_admin_keypair['user_id']
        tool_id = tool_keypair['tool_id']
        admin_private = unique_admin_keypair['private']
        tool_private = tool_keypair['private']

        admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

        # Create tool in state, signed by admin
        tool_info = {
            "tool_id": tool_id,
            "description": "Test camera tool"
        }
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}",
            contents=tool_info,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Grant tool capability to create messages
        tool_cap = {
            "op": "create",
            "path": "messages/{...}"
        }
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}/rights/cap_messages",
            contents=tool_cap,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Test authentication flow
        # 1. Create challenge
        challenge_response = unique_space.create_challenge(tool_id)
        challenge = challenge_response['challenge']

        # 2. Sign challenge with tool's private key
        message = challenge.encode('utf-8')
        signature = tool_private.sign(message)
        signature_b64 = base64.b64encode(signature).decode()

        # 3. Verify challenge - should succeed
        assert unique_space.verify_challenge(tool_id, challenge, signature_b64)

        # 4. Get JWT token
        token_response = unique_space.create_jwt(tool_id)
        assert 'token' in token_response
        assert 'expires_at' in token_response

        # 5. Verify tool has permissions via capability (not ambient authority)
        assert unique_space.authz.check_permission(space_id, tool_id, "create", "messages/msg1")
        # Tool should NOT have read permission (no ambient authority)
        assert not unique_space.authz.check_permission(space_id, tool_id, "read", "messages/msg1")

    def test_tool_not_registered_cannot_authenticate(self, unique_space, tool_keypair):
        """Test that unregistered tools cannot authenticate"""
        import pytest

        tool_id = tool_keypair['tool_id']
        tool_private = tool_keypair['private']

        # Try to authenticate without registering tool
        challenge_response = unique_space.create_challenge(tool_id)
        challenge = challenge_response['challenge']

        message = challenge.encode('utf-8')
        signature = tool_private.sign(message)
        signature_b64 = base64.b64encode(signature).decode()

        # Should fail - tool not registered in space
        with pytest.raises(ValueError) as exc_info:
            unique_space.verify_challenge(tool_id, challenge, signature_b64)
        assert "not a member" in str(exc_info.value).lower()


class TestToolUseLimiting:
    """Test tool use-count limiting functionality"""

    @staticmethod
    def authenticate_with_challenge(space, user_id, private_key):
        """Helper to do full challenge/verify/JWT flow and return token"""
        challenge_response = space.create_challenge(user_id)
        challenge = challenge_response['challenge']

        message = challenge.encode('utf-8')
        signature = private_key.sign(message)
        signature_b64 = base64.b64encode(signature).decode()

        space.verify_challenge(user_id, challenge, signature_b64)

        token_response = space.create_jwt(user_id)
        return token_response['token']

    def test_unlimited_tool_can_write_multiple_times(self, unique_space, unique_admin_keypair, tool_keypair):
        """Tools without use_limit can write unlimited times"""
        admin_private = unique_admin_keypair['private']
        admin_id = unique_admin_keypair['user_id']

        tool_id = tool_keypair['tool_id']
        tool_private = tool_keypair['private']

        admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

        # Create tool WITHOUT use_limit
        tool_info = {
            "tool_id": tool_id,
            "description": "Unlimited test tool"
            # No use_limit field
        }
        # Creator adds tool to space
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}",
            contents=tool_info,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Grant tool permission to write to test paths
        cap_info = {
            # TODO FIXME Add "subject" to all capabilities
            "op": "write",
            "path": "test/{...}"
        }
        set_space_state(
            space=unique_space,
            path=f"auth/tools/{tool_id}/rights/cap_001",
            contents=cap_info,
            token=admin_token,
            keypair=unique_admin_keypair
        )

        # Tool authenticates to space
        tool_token = self.authenticate_with_challenge(unique_space, tool_id, tool_private)

        # Tool should be able to write many times (testing 10)
        for i in range(10):
            print(f"Setting state - use #{i}")
            path=f"test/item_{i}"
            contents = {
                "count": i
            }
            set_space_state(unique_space, path, contents, tool_token, tool_keypair)

        # Verify all writes succeeded
        for i in range(10):
            result = unique_space.get_state(f"test/item_{i}", tool_token)
            assert result is not None

    def test_limited_tool_enforces_use_limit(self, unique_space, unique_admin_keypair, tool_keypair):
        """Tools with use_limit should be limited to that many writes"""
        admin_id = unique_admin_keypair['user_id']
        admin_private = unique_admin_keypair['private']

        # Admin authenticates
        # NOTE: We must use the Space API here in order to initialize tool limit tracking on creation
        admin_token = self.authenticate_with_challenge(unique_space, admin_id, admin_private)

        tool_id = tool_keypair['tool_id']
        tool_private = tool_keypair['private']
        # Create tool WITH use_limit=3
        tool_path = f"auth/tools/{tool_id}"
        tool_info = {
            "tool_id": tool_id,
            "description": "Limited test tool",
            "use_limit": 3
        }
        # Creator adds tool to space - This set_state() call should initiate tool use tracking
        set_space_state(unique_space, tool_path, tool_info, admin_token, unique_admin_keypair)
        print(f"Created tool {tool_id}")

        # Grant tool permission to write to test paths
        cap_path=f"auth/tools/{tool_id}/rights/cap_001"
        cap_info = {
            "op": "write",
            "path": "test/{...}"
        }
        set_space_state(unique_space, cap_path, cap_info, admin_token, unique_admin_keypair)

        # Tool authenticates to the space
        tool_token = self.authenticate_with_challenge(unique_space, tool_id, tool_private)

        # First 3 writes should succeed
        for i in range(3):
            path = f"test/item_{i}"
            contents = {
                "count": i
            }
            set_space_state(unique_space, path, contents, tool_token, tool_keypair)

        # 4th write should fail
        with pytest.raises(ValueError) as exc_info:
            path = f"test/item_3"
            contents = {
                "count": 3
            }
            set_space_state(unique_space, path, contents, tool_token, tool_keypair)
        assert "exceeded use limit" in str(exc_info.value).lower()

    def test_tool_limit_only_counts_successful_writes(self, unique_space, unique_admin_keypair, tool_keypair):
        """Failed writes should not increment tool usage counter"""
        admin_id = unique_admin_keypair['user_id']
        admin_private = unique_admin_keypair['private']
        tool_id = tool_keypair['tool_id']
        tool_private = tool_keypair['private']

        # Authenticate the admin to the space
        admin_token = self.authenticate_with_challenge(unique_space, admin_id, admin_private)

        # Create tool WITH use_limit=2
        tool_info = {
            "tool_id": tool_id,
            "description": "Limited test tool",
            "use_limit": 2
        }
        # Creator adds tool to space
        tool_path = f"auth/tools/{tool_id}"
        set_space_state(unique_space, tool_path, tool_info, admin_token, unique_admin_keypair)

        # Grant tool permission to write ONLY to "allowed/{...}"
        cap_path = f"auth/tools/{tool_id}/rights/cap_001"
        cap_info = {
            "op": "write",
            "path": "allowed/{...}"
        }
        set_space_state(unique_space, cap_path, cap_info, admin_token, unique_admin_keypair)

        # Tool authenticates to the space
        tool_token = self.authenticate_with_challenge(unique_space, tool_id, tool_private)

        # Try to write to unauthorized path - should fail AND not count
        with pytest.raises(ValueError):
            set_space_state(unique_space, "forbidden/item", {"bad":"yes"}, tool_token, tool_keypair)

        # Now do 2 successful writes
        set_space_state(unique_space, "allowed/item_0", {"data": 0}, tool_token, tool_keypair)
        set_space_state(unique_space, "allowed/item_1", {"data": 1}, tool_token, tool_keypair)

        # 3rd write should fail (limit is 2)
        with pytest.raises(ValueError) as exc_info:
            set_space_state(unique_space, "allowed/item_2", {"data": 2}, tool_token, tool_keypair)
        assert "exceeded use limit" in str(exc_info.value).lower()

    def test_tool_usage_tracking_in_state_store(self, temp_db_path):
        """Test that message store correctly tracks tool usage"""
        from sqlite_message_store import SqliteMessageStore

        message_store = SqliteMessageStore(temp_db_path)
        space_id = "test_space"
        tool_id = "T_test_tool"

        # Initially no usage
        usage = message_store.get_tool_usage(space_id, tool_id)
        assert usage is None

        # Initialize tracking (this is called when tool is created with use_limit)
        message_store.initialize_tool_usage(space_id, tool_id)

        # Verify initialized
        usage = message_store.get_tool_usage(space_id, tool_id)
        assert usage is not None
        assert usage['use_count'] == 0
        assert usage['last_used_at'] is None

        # Increment once
        now = 1000000
        count = message_store.increment_tool_usage(space_id, tool_id, now)
        assert count == 1

        # Verify stored correctly
        usage = message_store.get_tool_usage(space_id, tool_id)
        assert usage is not None
        assert usage['use_count'] == 1
        assert usage['last_used_at'] == now

        # Increment again
        now2 = 2000000
        count = message_store.increment_tool_usage(space_id, tool_id, now2)
        assert count == 2

        # Verify incremented
        usage = message_store.get_tool_usage(space_id, tool_id)
        assert usage is not None
        assert usage['use_count'] == 2
        assert usage['last_used_at'] == now2

    def test_regular_users_not_subject_to_use_limits(self, unique_space, user_keypair, unique_admin_keypair):
        """Regular users (U_*) should not be subject to use limits"""
        user_id = user_keypair['user_id']
        user_private = user_keypair['private']
        admin_id = unique_admin_keypair['user_id']
        admin_private = unique_admin_keypair['private']
        space_id = unique_admin_keypair['space_id']

        # Creator authenticates
        admin_token = self.authenticate_with_challenge(unique_space, admin_id, admin_private)

        # Creator adds user to the space
        set_space_state(unique_space, f"auth/users/{user_id}", {"user_id": user_id}, admin_token, unique_admin_keypair)

        # Creator grants user write ability on test/
        cap_path = f"auth/users/{user_id}/rights/write_to_test"
        cap_info = {
            "op": "write",
            "path": "test/{any}"
        }
        set_space_state(unique_space, cap_path, cap_info, admin_token, unique_admin_keypair)

        # Creator should be able to write many times without limit
        for i in range(10):
            set_space_state(unique_space, f"test/item_{i}", {"data": i}, admin_token, unique_admin_keypair)

        # Verify all writes succeeded
        for i in range(10):
            result = unique_space.get_state(f"test/item_{i}", admin_token)
            assert result is not None

        # Verify no usage tracking for admin
        admin_usage = unique_space.message_store.get_tool_usage(space_id, admin_id)
        assert admin_usage is None

        # User authenticates
        user_token = self.authenticate_with_challenge(unique_space, user_id, user_private)

        # User should be able to write many times without limit
        for i in range(10, 20):
            set_space_state(unique_space, f"test/item_{i}", {"data": i}, user_token, user_keypair)

        # Verify all writes succeeded
        for i in range(10, 20):
            result = unique_space.get_state(f"test/item_{i}", user_token)
            assert result is not None

        # Verify no usage tracking for user
        user_usage = unique_space.message_store.get_tool_usage(space_id, user_id)
        assert user_usage is None

