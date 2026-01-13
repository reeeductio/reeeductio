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
sign_data_entry = conftest.sign_data_entry
sign_and_store_data = conftest.sign_and_store_data
authenticate_with_challenge = conftest.authenticate_with_challenge
set_space_state = conftest.set_space_state

def test_space_creator_god_mode(authz, admin_keypair):
    """Test that space creator has god mode permissions"""
    space_id = admin_keypair['space_id']
    admin_id = admin_keypair['user_id']

    assert authz.check_permission(space_id, admin_id, "write", "anything")


def test_granted_capability(unique_space, unique_admin_keypair, user_keypair):
    """Test that users can use granted capabilities"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Add the user to the space
    print("Adding user to the space")
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents={
            "user_id": user_id
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Create something in the state
    print("Creating test/alice state entry")
    set_space_state(
        space=unique_space,
        path="test/alice",
        contents={
            "name": "Alice",
            "sizes": ["regular", "big", "small"]
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Create a capability for user (read permission for everything)
    print("Granting user read access to ...")
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/read_all",
        contents={
            "op": "read",
            "path": "{...}"  # {...} matches everything at any depth
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Test user now has read permission
    print("Checking permissions")
    assert unique_space.authz.check_permission(space_id, user_id, "read", "test/alice")


def test_ungranted_capability_rejection(authz, admin_keypair, user_keypair):
    """Test that users don't have capabilities that weren't granted"""
    space_id = admin_keypair['space_id']
    user_id = user_keypair['user_id']

    # User doesn't have write permission (no capability stored)
    assert not authz.check_permission(space_id, user_id, "write", "members/alice")


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


def test_modify_capability(unique_space, unique_admin_keypair, user_keypair):
    """Test that modify capability works correctly"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Add the user to the space
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents={
            "user_id": user_id
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Grant user modify permission on test/* path
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/modify_test",
        contents={
            "op": "modify",
            "path": "state/test/{...}"
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # User should have modify permission
    assert unique_space.authz.check_permission(space_id, user_id, "modify", "state/test/data")

    # User should NOT have create permission (modify doesn't grant create)
    assert not unique_space.authz.check_permission(space_id, user_id, "create", "state/test/data")

    # User should NOT have delete permission (modify doesn't grant delete)
    assert not unique_space.authz.check_permission(space_id, user_id, "delete", "state/test/data")


def test_delete_capability(unique_space, unique_admin_keypair, user_keypair):
    """Test that delete capability works correctly"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Add the user to the space
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents={
            "user_id": user_id
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Grant user delete permission on test/* path
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/delete_test",
        contents={
            "op": "delete",
            "path": "state/test/{...}"
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # User should have delete permission
    assert unique_space.authz.check_permission(space_id, user_id, "delete", "state/test/data")

    # User should NOT have create permission (delete doesn't grant create)
    assert not unique_space.authz.check_permission(space_id, user_id, "create", "state/test/data")

    # User should NOT have modify permission (delete doesn't grant modify)
    assert not unique_space.authz.check_permission(space_id, user_id, "modify", "state/test/data")


def test_write_grants_all_operations(unique_space, unique_admin_keypair, user_keypair):
    """Test that write capability grants create, modify, delete, and read"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Add the user to the space
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents={
            "user_id": user_id
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Grant user write permission
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/write_test",
        contents={
            "op": "write",
            "path": "state/test/{...}"
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Write should grant all operations
    assert unique_space.authz.check_permission(space_id, user_id, "read", "state/test/data")
    assert unique_space.authz.check_permission(space_id, user_id, "create", "state/test/data")
    assert unique_space.authz.check_permission(space_id, user_id, "modify", "state/test/data")
    assert unique_space.authz.check_permission(space_id, user_id, "delete", "state/test/data")
    assert unique_space.authz.check_permission(space_id, user_id, "write", "state/test/data")


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


def test_owned_modify_capability(unique_space, unique_admin_keypair, user_keypair):
    """Test that must_be_owner=true restricts modify to owned objects"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']
    user_private = user_keypair['private']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Add the user to the space
    print("Adding user to the space")
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents={
            "user_id": user_id
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Grant user (non-owner-restricted) create permission
    print("Granting user create permission")
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/create_docs",
        contents={
            "op": "create",
            "path": "state/docs/{...}",
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Grant user ownership-restricted modify permission
    print("Granting user modify permission")
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/modify_owned_docs",
        contents={
            "op": "modify",
            "path": "state/docs/{...}",
            "must_be_owner": True
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Authenticate the user to create their own document
    user_token = authenticate_with_challenge(unique_space, user_id, user_private)

    # Create a document owned by the user
    print("Creating document owned by user")
    set_space_state(
        space=unique_space,
        path="docs/user_doc",
        contents={
            "title": "User's document"
        },
        token=user_token,
        keypair=user_keypair
    )

    # Create a document owned by admin
    print("Creating document owned by admin")
    set_space_state(
        space=unique_space,
        path="docs/admin_doc",
        contents={
            "title": "Admin's document"
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # User should be able to modify their own document
    print("Checking access to user's doc")
    assert unique_space.authz.check_permission(space_id, user_id, "modify", "state/docs/user_doc")

    # User should NOT be able to modify admin's document
    print("Checking access to admin's doc")
    assert not unique_space.authz.check_permission(space_id, user_id, "modify", "state/docs/admin_doc")


def test_owned_delete_capability(unique_space, unique_admin_keypair, user_keypair):
    """Test that must_be_owner=true restricts delete to owned objects"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']
    user_private = user_keypair['private']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Add the user to the space
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents={
            "user_id": user_id
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Grant user create permission
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/create_files",
        contents={
            "op": "create",
            "path": "state/files/{...}"
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Grant user ownership-restricted delete permission
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/delete_owned",
        contents={
            "op": "delete",
            "path": "state/files/{...}",
            "must_be_owner": True
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Authenticate the user to create their own file
    user_token = authenticate_with_challenge(unique_space, user_id, user_private)

    # Create a file owned by the user
    set_space_state(
        space=unique_space,
        path="files/user_file",
        contents={
            "name": "user_file.txt"
        },
        token=user_token,
        keypair=user_keypair
    )

    # Create a file owned by admin
    set_space_state(
        space=unique_space,
        path="files/admin_file",
        contents={
            "name": "admin_file.txt"
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # User should be able to delete their own file
    assert unique_space.authz.check_permission(space_id, user_id, "delete", "state/files/user_file")

    # User should NOT be able to delete admin's file
    assert not unique_space.authz.check_permission(space_id, user_id, "delete", "state/files/admin_file")


def test_owned_create_always_allowed(unique_space, unique_admin_keypair, user_keypair):
    """Test that must_be_owner=true doesn't restrict create operations"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Add the user to the space
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents={
            "user_id": user_id
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Grant user ownership-restricted create permission
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/create_owned",
        contents={
            "op": "create",
            "path": "state/posts/{...}",
            "must_be_owner": True  # Should be ignored for create
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # User should be able to create (ownership check skipped for create)
    assert unique_space.authz.check_permission(space_id, user_id, "create", "state/posts/new_post")


def test_owned_nonexistent_entry(unique_space, unique_admin_keypair, user_keypair):
    """Test that must_be_owner=true denies access to non-existent entries"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Add the user to the space
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents={
            "user_id": user_id
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Grant user ownership-restricted modify permission
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/modify_owned_items",
        contents={
            "op": "modify",
            "path": "state/items/{...}",
            "must_be_owner": True
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # User should NOT be able to modify non-existent entry
    # (no entry exists, so can't verify ownership)
    assert not unique_space.authz.check_permission(space_id, user_id, "modify", "state/items/nonexistent")


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
