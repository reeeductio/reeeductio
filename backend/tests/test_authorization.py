"""
Tests for authorization engine
"""
import pytest
import json
import base64


def test_channel_creator_god_mode(authz, admin_keypair):
    """Test that channel creator has god mode permissions"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']

    assert authz.check_permission(channel_id, admin_id, "write", "anything")


def test_granted_capability(state_store, authz, crypto, admin_keypair, user_keypair):
    """Test that users can use granted capabilities"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']

    # Create a capability for user (read permission for everything)
    capability = {
        "op": "read",
        "path": "{...}",  # {...} matches everything at any depth
        "granted_by": admin_id,
        "granted_at": 12345000
    }

    # Sign the capability
    cap_message = crypto.compute_capability_signature_message(
        channel_id,
        user_id,
        capability["op"],
        capability["path"],
        capability["granted_at"]
    )
    signature = admin_private.sign(cap_message)
    capability["signature"] = crypto.base64_encode(signature)

    # Store capability in state (as base64-encoded JSON)
    capability_json = json.dumps(capability)
    capability_b64 = base64.b64encode(capability_json.encode()).decode()
    state_store.set_state(
        channel_id,
        f"auth/users/{user_id}/rights/read_all",
        capability_b64,
        updated_by=admin_id,
        updated_at=12345000
    )

    # Test user now has read permission
    assert authz.check_permission(channel_id, user_id, "read", "members/alice")


def test_ungranted_capability_rejection(authz, admin_keypair, user_keypair):
    """Test that users don't have capabilities that weren't granted"""
    channel_id = admin_keypair['channel_id']
    user_id = user_keypair['user_id']

    # User doesn't have write permission (no capability stored)
    assert not authz.check_permission(channel_id, user_id, "write", "members/alice")


def test_path_matching(authz):
    """Test path matching logic with {...} rest wildcard"""
    # {any} matches exactly one segment (exact depth)
    assert authz._path_matches("{any}", "members")
    assert not authz._path_matches("{any}", "members/alice")  # Too many segments

    # {...} matches any depth (prefix match)
    assert authz._path_matches("{...}", "members")
    assert authz._path_matches("{...}", "members/alice")
    assert authz._path_matches("{...}", "members/alice/rights/cap1")

    # {any} with additional segments - exact depth
    assert authz._path_matches("members/{any}", "members/alice")
    assert not authz._path_matches("members/{any}", "members/alice/rights")  # Too deep

    # {any} with {...} - prefix match from that point
    assert authz._path_matches("members/{any}/{...}", "members/alice/rights")
    assert authz._path_matches("members/{any}/{...}", "members/alice/rights/cap1")

    # {self} resolves to user ID - exact depth
    assert authz._path_matches("profiles/{self}", "profiles/U_alice", "U_alice")
    assert not authz._path_matches("profiles/{self}", "profiles/U_alice/settings", "U_alice")  # Too deep
    assert not authz._path_matches("profiles/{self}", "profiles/U_bob", "U_alice")

    # {self} with {...} - prefix match
    assert authz._path_matches("profiles/{self}/{...}", "profiles/U_alice/settings", "U_alice")
    assert authz._path_matches("profiles/{self}/{...}", "profiles/U_alice/settings/theme", "U_alice")
    assert not authz._path_matches("profiles/{self}/{...}", "profiles/U_bob/settings", "U_alice")

    # Different paths don't match
    assert not authz._path_matches("members/alice", "members/bob")


def test_capability_subset_checking(authz):
    """Test capability subset checking with new wildcard syntax"""
    # {any} subsumes everything
    granter_caps = [
        {"op": "write", "path": "{any}"}
    ]
    requested_caps = [
        {"op": "create", "path": "members/"}
    ]
    assert authz._has_capability_superset(granter_caps, requested_caps)

    # profiles/{any}/ subsumes profiles/{self}/
    granter_caps = [
        {"op": "write", "path": "profiles/{any}/"}
    ]
    requested_caps = [
        {"op": "write", "path": "profiles/{self}/"}
    ]
    assert authz._has_capability_superset(granter_caps, requested_caps)

    # profiles/{self}/ does NOT subsume profiles/{any}/
    granter_caps = [
        {"op": "write", "path": "profiles/{self}/"}
    ]
    requested_caps = [
        {"op": "write", "path": "profiles/{any}/"}
    ]
    assert not authz._has_capability_superset(granter_caps, requested_caps)


def test_privilege_escalation_prevention(authz):
    """Test that privilege escalation is prevented"""
    # User with read can't grant write
    granter_caps = [
        {"op": "read", "path": "{any}"}
    ]
    requested_caps = [
        {"op": "write", "path": "{any}"}
    ]
    assert not authz._has_capability_superset(granter_caps, requested_caps)
