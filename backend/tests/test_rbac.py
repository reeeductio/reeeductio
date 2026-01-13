"""
Tests for Role-Based Access Control (RBAC)
"""

import pytest
from authorization import AuthorizationEngine
from sqlite_data_store import SqliteDataStore
from crypto import CryptoUtils
from identifiers import extract_public_key, encode_user_id

import sys
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

import conftest
sign_data_entry = conftest.sign_data_entry
sign_and_store_data = conftest.sign_and_store_data
set_space_state = conftest.set_space_state
authenticate_with_challenge = conftest.authenticate_with_challenge


@pytest.fixture
def space_with_roles(unique_space, unique_admin_keypair):
    """Set up a space with role definitions"""

    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Create "user" role
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

    # Add capabilities to "user" role
    user_read_cap = {
        "op": "read",
        "path": "{...}"  # Can read anything at any depth
    }
    set_space_state(
        space=unique_space,
        path="auth/roles/user/rights/cap_read",
        contents=user_read_cap,
        token=admin_token,
        keypair=unique_admin_keypair
    )
    user_post_cap = {
        "op": "create",
        "path": "topics/{any}/messages/{...}"  # Can create messages at any depth under topics
    }
    set_space_state(
        space=unique_space,
        path="auth/roles/user/rights/cap_post",
        contents=user_post_cap,
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Create "moderator" role
    mod_role = {
        "role_id": "moderator",
        "description": "Moderator role"
    }
    set_space_state(
        space=unique_space,
        path="auth/roles/moderator",
        contents=mod_role,
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Moderators can ban users
    mod_ban_cap = {
        "op": "write",
        "path": "auth/users/{other}/banned"
    }
    set_space_state(
        space=unique_space,
        path="auth/roles/moderator/rights/cap_ban",
        contents=mod_ban_cap,
        token=admin_token,
        keypair=unique_admin_keypair
    )

    return {
        'space': unique_space,
        'space_id': space_id,
        'admin_id': admin_id,
        'admin_token': admin_token,
        'admin_keypair': unique_admin_keypair
    }


def test_load_role_capabilities(space_with_roles, user_keypair):
    """Test loading capabilities from user's roles"""
    space_id = space_with_roles['space_id']
    user_id = user_keypair['user_id']
    space = space_with_roles['space']
    admin_token = space_with_roles['admin_token']
    admin_keypair = space_with_roles['admin_keypair']

    # First, add the user to the space (required for chain of trust)
    user_info = {"user_id": user_id}
    set_space_state(
        space=space,
        path=f"auth/users/{user_id}",
        contents=user_info,
        token=admin_token,
        keypair=admin_keypair
    )

    # Grant "user" role to the user
    role_grant = {
        "user_id": user_id,
        "role_id": "user"
    }
    set_space_state(
        space=space,
        path=f"auth/users/{user_id}/roles/user",
        contents=role_grant,
        token=admin_token,
        keypair=admin_keypair
    )

    # Load role capabilities
    role_caps = space.authz._load_role_capabilities(space_id, user_id)

    # Should have 2 capabilities from "user" role
    assert len(role_caps) == 2

    # Check capabilities are loaded
    ops = {cap['op'] for cap in role_caps}
    assert 'read' in ops
    assert 'create' in ops


def test_permission_check_with_roles(space_with_roles, user_keypair):
    """Test that permission checks include role capabilities"""
    space_id = space_with_roles['space_id']
    user_id = user_keypair['user_id']
    space = space_with_roles['space']
    admin_token = space_with_roles['admin_token']
    admin_keypair = space_with_roles['admin_keypair']

    # Add user as member of the space
    user_info = {
        "user_id": user_id
    }
    set_space_state(
        space=space,
        path=f"auth/users/{user_id}",
        contents=user_info,
        token=admin_token,
        keypair=admin_keypair
    )

    # User has no direct capabilities yet
    assert not space.authz.check_permission(space_id, user_id, "read", "anything")

    # Grant "user" role
    role_grant = {
        "user_id": user_id,
        "role_id": "user"
    }
    set_space_state(
        space=space,
        path=f"auth/users/{user_id}/roles/user",
        contents=role_grant,
        token=admin_token,
        keypair=admin_keypair
    )

    # Now user should have permissions from role
    assert space.authz.check_permission(space_id, user_id, "read", "anything")
    assert space.authz.check_permission(space_id, user_id, "create", "topics/general/messages/msg1")
    assert not space.authz.check_permission(space_id, user_id, "write", "topics/general/messages/msg1")


def test_multiple_roles(space_with_roles, user_keypair):
    """Test user with multiple roles gets all capabilities"""
    space_id = space_with_roles['space_id']
    user_id = user_keypair['user_id']
    space = space_with_roles['space']
    admin_token = space_with_roles['admin_token']
    admin_keypair = space_with_roles['admin_keypair']

    # First, add the user to the space (required for chain of trust)
    user_info = {"user_id": user_id}
    set_space_state(
        space=space,
        path=f"auth/users/{user_id}",
        contents=user_info,
        token=admin_token,
        keypair=admin_keypair
    )

    # Grant both "user" and "moderator" roles
    user_role_grant = {
        "user_id": user_id,
        "role_id": "user"
    }
    set_space_state(
        space=space,
        path=f"auth/users/{user_id}/roles/user",
        contents=user_role_grant,
        token=admin_token,
        keypair=admin_keypair
    )

    mod_role_grant = {
        "user_id": user_id,
        "role_id": "moderator"
    }
    set_space_state(
        space=space,
        path=f"auth/users/{user_id}/roles/moderator",
        contents=mod_role_grant,
        token=admin_token,
        keypair=admin_keypair
    )

    # User should have capabilities from both roles
    role_caps = space.authz._load_role_capabilities(space_id, user_id)
    assert len(role_caps) == 3  # 2 from user + 1 from moderator

    # Check permissions from both roles
    assert space.authz.check_permission(space_id, user_id, "read", "anything")  # from user role
    assert space.authz.check_permission(space_id, user_id, "write", "auth/users/U_other/banned")  # from moderator role


def test_expired_role_grant_ignored(space_with_roles, user_keypair):
    """Test that expired role grants are not loaded"""
    space_id = space_with_roles['space_id']
    user_id = user_keypair['user_id']
    space = space_with_roles['space']
    admin_token = space_with_roles['admin_token']
    admin_keypair = space_with_roles['admin_keypair']

    import time
    past_time = int((time.time() - 3600) * 1000)  # 1 hour ago

    # Grant role with expiry in the past
    role_grant = {
        "user_id": user_id,
        "role_id": "user",
        "expires_at": past_time
    }
    set_space_state(
        space=space,
        path=f"auth/users/{user_id}/roles/user",
        contents=role_grant,
        token=admin_token,
        keypair=admin_keypair
    )

    # Should not load capabilities from expired role
    role_caps = space.authz._load_role_capabilities(space_id, user_id)
    assert len(role_caps) == 0

    # Should not have permissions
    assert not space.authz.check_permission(space_id, user_id, "read", "anything")


def test_verify_role_grant_subset_checking(space_with_roles, user_keypair):
    """Test that role grant validation checks granter has superset"""
    space_id = space_with_roles['space_id']
    admin_id = space_with_roles['admin_id']
    space = space_with_roles['space']
    user_id = user_keypair['user_id']

    # Admin (space creator) can grant any role
    role_grant_data = {
        "user_id": user_id,
        "role_id": "user"
    }
    path = f"auth/users/{user_id}/roles/user"

    assert space.authz.verify_role_grant(
        space_id,
        path,
        role_grant_data,
        admin_id
    )


def test_verify_role_grant_privilege_escalation_prevented(space_with_roles, user_keypair):
    """Test that users cannot grant roles they don't have capabilities for"""
    space_id = space_with_roles['space_id']
    user_id = user_keypair['user_id']
    space = space_with_roles['space']
    admin_token = space_with_roles['admin_token']
    admin_keypair = space_with_roles['admin_keypair']

    # Give user1 only read permission
    user1_cap = {
        "op": "read",
        "path": "{any}"
    }
    set_space_state(
        space=space,
        path=f"auth/users/{user_id}/rights/cap_001",
        contents=user1_cap,
        token=admin_token,
        keypair=admin_keypair
    )

    # Create another user
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    user2_private = ed25519.Ed25519PrivateKey.generate()
    user2_public = user2_private.public_key()
    user2_bytes = user2_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    from identifiers import encode_user_id
    user2_id = encode_user_id(user2_bytes)

    # user1 tries to grant "moderator" role to user2
    # (moderator has write permission, but user1 only has read)
    role_grant_data = {
        "user_id": user2_id,
        "role_id": "moderator"
    }
    path = f"auth/users/{user2_id}/roles/moderator"

    # Should fail - user1 doesn't have capabilities that moderator role provides
    assert not space.authz.verify_role_grant(
        space_id,
        path,
        role_grant_data,
        user_id
    )


def test_is_role_grant_path(authz):
    """Test role grant path detection"""
    assert authz.is_role_grant_path("auth/users/U_abc123/roles/user")
    assert authz.is_role_grant_path("auth/users/U_abc123/roles/moderator")
    assert not authz.is_role_grant_path("auth/users/U_abc123/rights/cap_001")
    assert not authz.is_role_grant_path("auth/roles/user/rights/cap_001")
    assert not authz.is_role_grant_path("members/U_abc123")


def test_is_capability_path_includes_role_capabilities(authz):
    """Test capability path detection includes role capability paths"""
    # User capabilities
    assert authz.is_capability_path("auth/users/U_abc123/rights/cap_001")

    # Role capabilities
    assert authz.is_capability_path("auth/roles/user/rights/cap_001")
    assert authz.is_capability_path("auth/roles/moderator/rights/cap_ban")

    # Not capability paths
    assert not authz.is_capability_path("auth/users/U_abc123/roles/user")
    assert not authz.is_capability_path("members/U_abc123")
