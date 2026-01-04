"""
Tests for authorization engine
"""
import pytest
import json
import base64
import sys
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

import conftest
sign_state_entry = conftest.sign_state_entry
sign_and_store_state = conftest.sign_and_store_state


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

    # Add the user to the channel
    user_info = {
        "user_id": user_id
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    object_path = "test/alice"
    # Create something at the path
    object_contents = {
        "name": "Alice",
        "sizes": ["regular", "big", "small"]
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=object_path,
        contents=object_contents,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Create a capability for user (read permission for everything)
    capability = {
        "op": "read",
        "path": "{...}"  # {...} matches everything at any depth
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}/rights/read_all",
        contents=capability,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Test user now has read permission
    assert authz.check_permission(channel_id, user_id, "read", "test/alice")


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


def test_modify_capability(state_store, authz, admin_keypair, user_keypair):
    """Test that modify capability works correctly"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']

    # Add the user to the channel
    user_info = {
        "user_id": user_id
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Grant user modify permission on test/* path
    capability = {
        "op": "modify",
        "path": "test/{...}"
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}/rights/modify_test",
        contents=capability,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # User should have modify permission
    assert authz.check_permission(channel_id, user_id, "modify", "test/data")

    # User should NOT have create permission (modify doesn't grant create)
    assert not authz.check_permission(channel_id, user_id, "create", "test/data")

    # User should NOT have delete permission (modify doesn't grant delete)
    assert not authz.check_permission(channel_id, user_id, "delete", "test/data")


def test_delete_capability(state_store, authz, admin_keypair, user_keypair):
    """Test that delete capability works correctly"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']

    # Add the user to the channel
    user_info = {
        "user_id": user_id
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Grant user delete permission on test/* path
    capability = {
        "op": "delete",
        "path": "test/{...}"
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}/rights/delete_test",
        contents=capability,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # User should have delete permission
    assert authz.check_permission(channel_id, user_id, "delete", "test/data")

    # User should NOT have create permission (delete doesn't grant create)
    assert not authz.check_permission(channel_id, user_id, "create", "test/data")

    # User should NOT have modify permission (delete doesn't grant modify)
    assert not authz.check_permission(channel_id, user_id, "modify", "test/data")


def test_write_grants_all_operations(state_store, authz, admin_keypair, user_keypair):
    """Test that write capability grants create, modify, delete, and read"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']

    # Add the user to the channel
    user_info = {
        "user_id": user_id
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Grant user write permission
    capability = {
        "op": "write",
        "path": "test/{...}"
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}/rights/write_test",
        contents=capability,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Write should grant all operations
    assert authz.check_permission(channel_id, user_id, "read", "test/data")
    assert authz.check_permission(channel_id, user_id, "create", "test/data")
    assert authz.check_permission(channel_id, user_id, "modify", "test/data")
    assert authz.check_permission(channel_id, user_id, "delete", "test/data")
    assert authz.check_permission(channel_id, user_id, "write", "test/data")


def test_modify_delete_independence(authz):
    """Test that modify and delete are independent operations"""
    # User with modify can't grant delete
    granter_caps = [
        {"op": "modify", "path": "test/{...}"}
    ]
    requested_caps = [
        {"op": "delete", "path": "test/{...}"}
    ]
    assert not authz._has_capability_superset(granter_caps, requested_caps)

    # User with delete can't grant modify
    granter_caps = [
        {"op": "delete", "path": "test/{...}"}
    ]
    requested_caps = [
        {"op": "modify", "path": "test/{...}"}
    ]
    assert not authz._has_capability_superset(granter_caps, requested_caps)

    # User with create can't grant modify
    granter_caps = [
        {"op": "create", "path": "test/{...}"}
    ]
    requested_caps = [
        {"op": "modify", "path": "test/{...}"}
    ]
    assert not authz._has_capability_superset(granter_caps, requested_caps)

    # User with create can't grant delete
    granter_caps = [
        {"op": "create", "path": "test/{...}"}
    ]
    requested_caps = [
        {"op": "delete", "path": "test/{...}"}
    ]
    assert not authz._has_capability_superset(granter_caps, requested_caps)


def test_write_dominates_all_operations(authz):
    """Test that write capability dominates create, modify, and delete"""
    granter_caps = [
        {"op": "write", "path": "test/{...}"}
    ]

    # Write can grant create
    requested_caps = [{"op": "create", "path": "test/{...}"}]
    assert authz._has_capability_superset(granter_caps, requested_caps)

    # Write can grant modify
    requested_caps = [{"op": "modify", "path": "test/{...}"}]
    assert authz._has_capability_superset(granter_caps, requested_caps)

    # Write can grant delete
    requested_caps = [{"op": "delete", "path": "test/{...}"}]
    assert authz._has_capability_superset(granter_caps, requested_caps)

    # Write can grant read
    requested_caps = [{"op": "read", "path": "test/{...}"}]
    assert authz._has_capability_superset(granter_caps, requested_caps)


def test_owned_modify_capability(state_store, authz, admin_keypair, user_keypair):
    """Test that must_be_owner=true restricts modify to owned objects"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']
    user_private = user_keypair['private']

    # Add the user to the channel
    user_info = {"user_id": user_id}
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Grant user ownership-restricted modify permission
    capability = {
        "op": "modify",
        "path": "docs/{...}",
        "must_be_owner": True
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}/rights/modify_owned",
        contents=capability,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Create a document owned by the user
    user_doc = {"title": "User's document"}
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path="docs/user_doc",
        contents=user_doc,
        signer_private_key=user_private,
        signer_user_id=user_id,
        signed_at=12346000
    )

    # Create a document owned by admin
    admin_doc = {"title": "Admin's document"}
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path="docs/admin_doc",
        contents=admin_doc,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12346000
    )

    # User should be able to modify their own document
    assert authz.check_permission(channel_id, user_id, "modify", "docs/user_doc")

    # User should NOT be able to modify admin's document
    assert not authz.check_permission(channel_id, user_id, "modify", "docs/admin_doc")


def test_owned_delete_capability(state_store, authz, admin_keypair, user_keypair):
    """Test that must_be_owner=true restricts delete to owned objects"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']
    user_private = user_keypair['private']

    # Add the user to the channel
    user_info = {"user_id": user_id}
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Grant user ownership-restricted delete permission
    capability = {
        "op": "delete",
        "path": "files/{...}",
        "must_be_owner": True
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}/rights/delete_owned",
        contents=capability,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Create a file owned by the user
    user_file = {"name": "user_file.txt"}
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path="files/user_file",
        contents=user_file,
        signer_private_key=user_private,
        signer_user_id=user_id,
        signed_at=12346000
    )

    # Create a file owned by admin
    admin_file = {"name": "admin_file.txt"}
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path="files/admin_file",
        contents=admin_file,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12346000
    )

    # User should be able to delete their own file
    assert authz.check_permission(channel_id, user_id, "delete", "files/user_file")

    # User should NOT be able to delete admin's file
    assert not authz.check_permission(channel_id, user_id, "delete", "files/admin_file")


def test_owned_create_always_allowed(state_store, authz, admin_keypair, user_keypair):
    """Test that must_be_owner=true doesn't restrict create operations"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']

    # Add the user to the channel
    user_info = {"user_id": user_id}
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Grant user ownership-restricted create permission
    capability = {
        "op": "create",
        "path": "posts/{...}",
        "must_be_owner": True  # Should be ignored for create
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}/rights/create_owned",
        contents=capability,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # User should be able to create (ownership check skipped for create)
    assert authz.check_permission(channel_id, user_id, "create", "posts/new_post")


def test_owned_nonexistent_entry(state_store, authz, admin_keypair, user_keypair):
    """Test that must_be_owner=true denies access to non-existent entries"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']

    # Add the user to the channel
    user_info = {"user_id": user_id}
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Grant user ownership-restricted modify permission
    capability = {
        "op": "modify",
        "path": "items/{...}",
        "must_be_owner": True
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}/rights/modify_owned_items",
        contents=capability,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # User should NOT be able to modify non-existent entry
    # (no entry exists, so can't verify ownership)
    assert not authz.check_permission(channel_id, user_id, "modify", "items/nonexistent")


def test_ownership_dominance_unrestricted_over_restricted(authz):
    """Test that must_be_owner=false dominates must_be_owner=true"""
    # Unrestricted capability can grant restricted capability (same op)
    granter_caps = [
        {"op": "modify", "path": "docs/{...}", "must_be_owner": False}
    ]
    requested_caps = [
        {"op": "modify", "path": "docs/{...}", "must_be_owner": True}
    ]
    assert authz._has_capability_superset(granter_caps, requested_caps)

    # Unrestricted capability can grant unrestricted capability (same op)
    requested_caps = [
        {"op": "modify", "path": "docs/{...}", "must_be_owner": False}
    ]
    assert authz._has_capability_superset(granter_caps, requested_caps)


def test_ownership_restricted_cannot_grant_unrestricted(authz):
    """Test that must_be_owner=true cannot grant must_be_owner=false"""
    # Restricted capability CANNOT grant unrestricted capability
    granter_caps = [
        {"op": "modify", "path": "docs/{...}", "must_be_owner": True}
    ]
    requested_caps = [
        {"op": "modify", "path": "docs/{...}", "must_be_owner": False}
    ]
    assert not authz._has_capability_superset(granter_caps, requested_caps)

    # Restricted capability CAN grant restricted capability
    requested_caps = [
        {"op": "modify", "path": "docs/{...}", "must_be_owner": True}
    ]
    assert authz._has_capability_superset(granter_caps, requested_caps)


def test_ownership_with_write_operation(authz):
    """Test ownership dominance with write operation"""
    # write + unrestricted can grant modify + restricted
    granter_caps = [
        {"op": "write", "path": "data/{...}", "must_be_owner": False}
    ]
    requested_caps = [
        {"op": "modify", "path": "data/{...}", "must_be_owner": True}
    ]
    assert authz._has_capability_superset(granter_caps, requested_caps)

    # write + unrestricted can grant modify + unrestricted
    requested_caps = [
        {"op": "modify", "path": "data/{...}", "must_be_owner": False}
    ]
    assert authz._has_capability_superset(granter_caps, requested_caps)

    # write + restricted CANNOT grant modify + unrestricted
    granter_caps = [
        {"op": "write", "path": "data/{...}", "must_be_owner": True}
    ]
    requested_caps = [
        {"op": "modify", "path": "data/{...}", "must_be_owner": False}
    ]
    assert not authz._has_capability_superset(granter_caps, requested_caps)

    # write + restricted CAN grant modify + restricted
    requested_caps = [
        {"op": "modify", "path": "data/{...}", "must_be_owner": True}
    ]
    assert authz._has_capability_superset(granter_caps, requested_caps)


def test_ownership_default_is_unrestricted(authz):
    """Test that missing must_be_owner field defaults to false (unrestricted)"""
    # Capability without must_be_owner field is unrestricted
    granter_caps = [
        {"op": "modify", "path": "docs/{...}"}  # No must_be_owner field
    ]
    requested_caps = [
        {"op": "modify", "path": "docs/{...}", "must_be_owner": True}
    ]
    # Should work because missing must_be_owner defaults to false (unrestricted)
    assert authz._has_capability_superset(granter_caps, requested_caps)

    # Can also grant unrestricted
    requested_caps = [
        {"op": "modify", "path": "docs/{...}", "must_be_owner": False}
    ]
    assert authz._has_capability_superset(granter_caps, requested_caps)

    # Can also grant capability without must_be_owner field
    requested_caps = [
        {"op": "modify", "path": "docs/{...}"}
    ]
    assert authz._has_capability_superset(granter_caps, requested_caps)
