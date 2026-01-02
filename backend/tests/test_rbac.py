"""
Tests for Role-Based Access Control (RBAC)
"""

import pytest
import base64
import json
from authorization import AuthorizationEngine
from sqlite_state_store import SqliteStateStore
from crypto import CryptoUtils
from identifiers import extract_public_key, encode_user_id


@pytest.fixture
def authz(temp_db_path):
    """Create AuthorizationEngine with temp storage"""
    state_store = SqliteStateStore(temp_db_path)
    crypto = CryptoUtils()
    return AuthorizationEngine(state_store, crypto)


@pytest.fixture
def channel_with_roles(temp_db_path, admin_keypair):
    """Set up a channel with role definitions"""
    state_store = SqliteStateStore(temp_db_path)
    crypto = CryptoUtils()
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']

    # Create "user" role
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

    # Add capabilities to "user" role
    user_read_cap = {
        "op": "read",
        "path": "{...}",  # Can read anything at any depth
        "granted_by": admin_id,
        "granted_at": 1234567890
    }
    # Sign capability (recipient is the role_id)
    cap_msg = crypto.compute_capability_signature_message(
        channel_id, "user", user_read_cap["op"], user_read_cap["path"], user_read_cap["granted_at"]
    )
    user_read_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))

    state_store.set_state(
        channel_id,
        "auth/roles/user/rights/cap_read",
        base64.b64encode(json.dumps(user_read_cap).encode()).decode(),
        admin_id,
        1234567890
    )

    user_post_cap = {
        "op": "create",
        "path": "topics/{any}/messages/{...}",  # Can create messages at any depth under topics
        "granted_by": admin_id,
        "granted_at": 1234567890
    }
    # Sign capability (recipient is the role_id)
    cap_msg = crypto.compute_capability_signature_message(
        channel_id, "user", user_post_cap["op"], user_post_cap["path"], user_post_cap["granted_at"]
    )
    user_post_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))

    state_store.set_state(
        channel_id,
        "auth/roles/user/rights/cap_post",
        base64.b64encode(json.dumps(user_post_cap).encode()).decode(),
        admin_id,
        1234567890
    )

    # Create "moderator" role
    mod_role = {
        "role_id": "moderator",
        "description": "Moderator role",
        "created_by": admin_id,
        "created_at": 1234567890,
        "signature": "fake_signature"
    }
    state_store.set_state(
        channel_id,
        "auth/roles/moderator",
        base64.b64encode(json.dumps(mod_role).encode()).decode(),
        admin_id,
        1234567890
    )

    # Moderators can ban users
    mod_ban_cap = {
        "op": "write",
        "path": "auth/users/{other}/banned",
        "granted_by": admin_id,
        "granted_at": 1234567890
    }
    # Sign capability (recipient is the role_id)
    cap_msg = crypto.compute_capability_signature_message(
        channel_id, "moderator", mod_ban_cap["op"], mod_ban_cap["path"], mod_ban_cap["granted_at"]
    )
    mod_ban_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))

    state_store.set_state(
        channel_id,
        "auth/roles/moderator/rights/cap_ban",
        base64.b64encode(json.dumps(mod_ban_cap).encode()).decode(),
        admin_id,
        1234567890
    )

    return {
        'state_store': state_store,
        'channel_id': channel_id,
        'admin_id': admin_id
    }


def test_load_role_capabilities(authz, channel_with_roles, user_keypair):
    """Test loading capabilities from user's roles"""
    channel_id = channel_with_roles['channel_id']
    user_id = user_keypair['user_id']
    state_store = channel_with_roles['state_store']

    # Grant "user" role to the user
    role_grant = {
        "user_id": user_id,
        "role_id": "user",
        "granted_by": channel_with_roles['admin_id'],
        "granted_at": 1234567890,
        "signature": "fake_signature"
    }
    state_store.set_state(
        channel_id,
        f"auth/users/{user_id}/roles/user",
        base64.b64encode(json.dumps(role_grant).encode()).decode(),
        channel_with_roles['admin_id'],
        1234567890
    )

    # Load role capabilities
    role_caps = authz._load_role_capabilities(channel_id, user_id)

    # Should have 2 capabilities from "user" role
    assert len(role_caps) == 2

    # Check capabilities are loaded
    ops = {cap['op'] for cap in role_caps}
    assert 'read' in ops
    assert 'create' in ops


def test_permission_check_with_roles(authz, channel_with_roles, user_keypair):
    """Test that permission checks include role capabilities"""
    channel_id = channel_with_roles['channel_id']
    user_id = user_keypair['user_id']
    state_store = channel_with_roles['state_store']

    # Add user as member
    member_data = {
        "public_key": user_id,
        "added_at": 1234567890,
        "added_by": channel_with_roles['admin_id']
    }
    state_store.set_state(
        channel_id,
        f"members/{user_id}",
        base64.b64encode(json.dumps(member_data).encode()).decode(),
        channel_with_roles['admin_id'],
        1234567890
    )

    # User has no direct capabilities yet
    assert not authz.check_permission(channel_id, user_id, "read", "anything")

    # Grant "user" role
    role_grant = {
        "user_id": user_id,
        "role_id": "user",
        "granted_by": channel_with_roles['admin_id'],
        "granted_at": 1234567890,
        "signature": "fake_signature"
    }
    state_store.set_state(
        channel_id,
        f"auth/users/{user_id}/roles/user",
        base64.b64encode(json.dumps(role_grant).encode()).decode(),
        channel_with_roles['admin_id'],
        1234567890
    )

    # Now user should have permissions from role
    assert authz.check_permission(channel_id, user_id, "read", "anything")
    assert authz.check_permission(channel_id, user_id, "create", "topics/general/messages/msg1")
    assert not authz.check_permission(channel_id, user_id, "write", "topics/general/messages/msg1")


def test_multiple_roles(authz, channel_with_roles, user_keypair):
    """Test user with multiple roles gets all capabilities"""
    channel_id = channel_with_roles['channel_id']
    user_id = user_keypair['user_id']
    state_store = channel_with_roles['state_store']

    # Grant both "user" and "moderator" roles
    user_role_grant = {
        "user_id": user_id,
        "role_id": "user",
        "granted_by": channel_with_roles['admin_id'],
        "granted_at": 1234567890,
        "signature": "fake_signature"
    }
    state_store.set_state(
        channel_id,
        f"auth/users/{user_id}/roles/user",
        base64.b64encode(json.dumps(user_role_grant).encode()).decode(),
        channel_with_roles['admin_id'],
        1234567890
    )

    mod_role_grant = {
        "user_id": user_id,
        "role_id": "moderator",
        "granted_by": channel_with_roles['admin_id'],
        "granted_at": 1234567890,
        "signature": "fake_signature"
    }
    state_store.set_state(
        channel_id,
        f"auth/users/{user_id}/roles/moderator",
        base64.b64encode(json.dumps(mod_role_grant).encode()).decode(),
        channel_with_roles['admin_id'],
        1234567890
    )

    # User should have capabilities from both roles
    role_caps = authz._load_role_capabilities(channel_id, user_id)
    assert len(role_caps) == 3  # 2 from user + 1 from moderator

    # Check permissions from both roles
    assert authz.check_permission(channel_id, user_id, "read", "anything")  # from user role
    assert authz.check_permission(channel_id, user_id, "write", "auth/users/U_other/banned")  # from moderator role


def test_expired_role_grant_ignored(authz, channel_with_roles, user_keypair):
    """Test that expired role grants are not loaded"""
    channel_id = channel_with_roles['channel_id']
    user_id = user_keypair['user_id']
    state_store = channel_with_roles['state_store']

    import time
    past_time = int((time.time() - 3600) * 1000)  # 1 hour ago

    # Grant role with expiry in the past
    role_grant = {
        "user_id": user_id,
        "role_id": "user",
        "granted_by": channel_with_roles['admin_id'],
        "granted_at": 1234567890,
        "expires_at": past_time,
        "signature": "fake_signature"
    }
    state_store.set_state(
        channel_id,
        f"auth/users/{user_id}/roles/user",
        base64.b64encode(json.dumps(role_grant).encode()).decode(),
        channel_with_roles['admin_id'],
        1234567890
    )

    # Should not load capabilities from expired role
    role_caps = authz._load_role_capabilities(channel_id, user_id)
    assert len(role_caps) == 0

    # Should not have permissions
    assert not authz.check_permission(channel_id, user_id, "read", "anything")


def test_verify_role_grant_subset_checking(authz, channel_with_roles, user_keypair):
    """Test that role grant validation checks granter has superset"""
    channel_id = channel_with_roles['channel_id']
    admin_id = channel_with_roles['admin_id']
    user_id = user_keypair['user_id']

    # Admin (channel creator) can grant any role
    role_grant_data = {
        "user_id": user_id,
        "role_id": "user",
        "granted_by": admin_id,
        "granted_at": 1234567890
    }
    path = f"auth/users/{user_id}/roles/user"

    assert authz.verify_role_grant(
        channel_id,
        path,
        role_grant_data,
        admin_id,
        "fake_signature"
    )


def test_verify_role_grant_privilege_escalation_prevented(authz, channel_with_roles, user_keypair):
    """Test that users cannot grant roles they don't have capabilities for"""
    channel_id = channel_with_roles['channel_id']
    user_id = user_keypair['user_id']
    state_store = channel_with_roles['state_store']

    # Give user1 only read permission
    user1_cap = {
        "op": "read",
        "path": "{any}",
        "granted_by": channel_with_roles['admin_id'],
        "granted_at": 1234567890,
        "signature": "fake_signature"
    }
    state_store.set_state(
        channel_id,
        f"auth/users/{user_id}/rights/cap_001",
        base64.b64encode(json.dumps(user1_cap).encode()).decode(),
        channel_with_roles['admin_id'],
        1234567890
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
        "role_id": "moderator",
        "granted_by": user_id,
        "granted_at": 1234567890
    }
    path = f"auth/users/{user2_id}/roles/moderator"

    # Should fail - user1 doesn't have capabilities that moderator role provides
    assert not authz.verify_role_grant(
        channel_id,
        path,
        role_grant_data,
        user_id,
        "fake_signature"
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
