"""
Tests for authorization engine
"""
import pytest


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

    # Create a capability for user
    capability = {
        "op": "read",
        "path": "*",
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

    # Store capability in state
    state_store.set_state(
        channel_id,
        f"members/{user_id}/rights/read_all",
        capability,
        encrypted=False,
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
    """Test path matching logic"""
    assert authz._path_matches("*", "members")
    assert authz._path_matches("members/", "members/alice")
    assert not authz._path_matches("members/alice", "members/bob")


def test_capability_subset_checking(authz):
    """Test capability subset checking"""
    granter_caps = [
        {"op": "write", "path": "*"}
    ]
    requested_caps = [
        {"op": "create", "path": "members/"}
    ]
    assert authz._has_capability_superset(granter_caps, requested_caps)


def test_privilege_escalation_prevention(authz):
    """Test that privilege escalation is prevented"""
    # User with read can't grant write
    granter_caps = [
        {"op": "read", "path": "*"}
    ]
    requested_caps = [
        {"op": "write", "path": "*"}
    ]
    assert not authz._has_capability_superset(granter_caps, requested_caps)
