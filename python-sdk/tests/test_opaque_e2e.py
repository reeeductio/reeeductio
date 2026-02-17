"""
E2E tests for OPAQUE password-based key recovery.

Run with: pytest -m e2e tests/test_opaque_e2e.py
Requires: docker compose -f backend/docker-compose.e2e.yml up -d
"""

import json
import os
import uuid

import pytest

from reeeductio import (
    Space,
    generate_keypair,
    opaque_login,
    OpaqueCredentials,
    AuthenticationError,
)
from reeeductio.opaque import (
    OPAQUE_SERVER_SETUP_PATH,
    OPAQUE_USER_ROLE_ID,
    OPAQUE_USER_CAP_ID,
)

pytestmark = pytest.mark.e2e


def random_username() -> str:
    """Generate a random username for test isolation."""
    return f"test-user-{uuid.uuid4().hex[:8]}"


class TestEnableOpaque:
    """Tests for the enable_opaque method."""

    def test_create_server_setup_role_and_capability_on_first_call(
        self, fresh_keypair, symmetric_root, base_url
    ):
        """enable_opaque should create all required resources on first call."""
        space_id = fresh_keypair.to_space_id()

        with Space(
            space_id=space_id,
            member_id=fresh_keypair.to_user_id(),
            private_key=fresh_keypair.private_key,
            symmetric_root=symmetric_root,
            base_url=base_url,
        ) as space:
            # Enable OPAQUE
            result = space.enable_opaque()

            assert result["server_setup_created"] is True
            assert result["role_created"] is True
            assert result["capability_created"] is True

            # Verify server setup was stored
            server_setup = space.get_plaintext_data(OPAQUE_SERVER_SETUP_PATH)
            assert isinstance(server_setup, bytes)
            assert len(server_setup) > 0

            # Verify role was created
            role_data = space.get_plaintext_state(f"auth/roles/{OPAQUE_USER_ROLE_ID}")
            role = json.loads(role_data)
            assert role["role_id"] == OPAQUE_USER_ROLE_ID

            # Verify capability was created
            cap_data = space.get_plaintext_state(
                f"auth/roles/{OPAQUE_USER_ROLE_ID}/rights/{OPAQUE_USER_CAP_ID}"
            )
            cap = json.loads(cap_data)
            assert cap["op"] == "create"
            assert cap["path"] == "data/opaque/users/{any}"

    def test_should_be_idempotent_on_second_call(
        self, fresh_keypair, symmetric_root, base_url
    ):
        """enable_opaque should be idempotent - second call should not recreate."""
        space_id = fresh_keypair.to_space_id()

        with Space(
            space_id=space_id,
            member_id=fresh_keypair.to_user_id(),
            private_key=fresh_keypair.private_key,
            symmetric_root=symmetric_root,
            base_url=base_url,
        ) as space:
            # First call - should create everything
            result1 = space.enable_opaque()
            assert result1["server_setup_created"] is True
            assert result1["role_created"] is True
            assert result1["capability_created"] is True

            # Second call - should find everything already exists
            result2 = space.enable_opaque()
            assert result2["server_setup_created"] is False
            assert result2["role_created"] is False
            assert result2["capability_created"] is False


class TestOpaqueRegistrationAndLogin:
    """Tests for OPAQUE registration and login flow."""

    def test_register_and_login_with_opaque_credentials(
        self, fresh_keypair, symmetric_root, base_url
    ):
        """Full round-trip: register OPAQUE credentials, then login to recover them."""
        space_id = fresh_keypair.to_space_id()

        with Space(
            space_id=space_id,
            member_id=fresh_keypair.to_user_id(),
            private_key=fresh_keypair.private_key,
            symmetric_root=symmetric_root,
            base_url=base_url,
        ) as space:
            # Enable OPAQUE first
            space.enable_opaque()

            # Register OPAQUE credentials
            username = random_username()
            password = "test-password-123!"

            reg_result = space.opaque_register(username, password)
            assert reg_result == username

            # Now login with OPAQUE to recover credentials
            credentials = opaque_login(
                base_url=base_url,
                space_id=space_id,
                username=username,
                password=password,
            )

            # Verify the recovered credentials
            assert isinstance(credentials, OpaqueCredentials)
            assert credentials.keypair.to_user_id() == fresh_keypair.to_user_id()
            assert credentials.symmetric_root == symmetric_root

            # Create a new Space with the recovered credentials
            with Space(
                space_id=space_id,
                member_id=credentials.keypair.to_user_id(),
                private_key=credentials.keypair.private_key,
                symmetric_root=credentials.symmetric_root,
                base_url=base_url,
            ) as recovered_space:
                # Verify the recovered space can perform operations
                test_path = f"test/opaque/{uuid.uuid4().hex[:8]}"
                test_data = "Hello from recovered space!"
                recovered_space.set_plaintext_state(test_path, test_data)

                # Read it back
                retrieved = recovered_space.get_plaintext_state(test_path)
                assert retrieved == test_data

    def test_allow_multiple_opaque_registrations(
        self, fresh_keypair, symmetric_root, base_url
    ):
        """A user can register multiple OPAQUE usernames for the same keypair."""
        space_id = fresh_keypair.to_space_id()

        with Space(
            space_id=space_id,
            member_id=fresh_keypair.to_user_id(),
            private_key=fresh_keypair.private_key,
            symmetric_root=symmetric_root,
            base_url=base_url,
        ) as space:
            # Enable OPAQUE
            space.enable_opaque()

            # Register first set of credentials
            username1 = random_username()
            password1 = "first-password-123!"
            reg_result1 = space.opaque_register(username1, password1)
            assert reg_result1 == username1

            # Register second set of credentials with different username
            username2 = random_username()
            password2 = "second-password-456!"
            reg_result2 = space.opaque_register(username2, password2)
            assert reg_result2 == username2

            # Both credentials should work for login
            credentials1 = opaque_login(
                base_url=base_url,
                space_id=space_id,
                username=username1,
                password=password1,
            )
            assert credentials1.keypair.to_user_id() == fresh_keypair.to_user_id()

            credentials2 = opaque_login(
                base_url=base_url,
                space_id=space_id,
                username=username2,
                password=password2,
            )
            assert credentials2.keypair.to_user_id() == fresh_keypair.to_user_id()

    def test_fail_login_with_wrong_password(
        self, fresh_keypair, symmetric_root, base_url
    ):
        """OPAQUE login should fail with incorrect password."""
        space_id = fresh_keypair.to_space_id()

        with Space(
            space_id=space_id,
            member_id=fresh_keypair.to_user_id(),
            private_key=fresh_keypair.private_key,
            symmetric_root=symmetric_root,
            base_url=base_url,
        ) as space:
            # Enable OPAQUE and register
            space.enable_opaque()

            username = random_username()
            password = "correct-password"

            space.opaque_register(username, password)

            # Try to login with wrong password
            with pytest.raises(AuthenticationError):
                opaque_login(
                    base_url=base_url,
                    space_id=space_id,
                    username=username,
                    password="wrong-password",
                )

    def test_fail_login_with_nonexistent_username(
        self, fresh_keypair, symmetric_root, base_url
    ):
        """OPAQUE login should fail with non-existent username."""
        space_id = fresh_keypair.to_space_id()

        with Space(
            space_id=space_id,
            member_id=fresh_keypair.to_user_id(),
            private_key=fresh_keypair.private_key,
            symmetric_root=symmetric_root,
            base_url=base_url,
        ) as space:
            # Enable OPAQUE (but don't register any user)
            space.enable_opaque()

            # Try to login with non-existent username
            with pytest.raises(AuthenticationError):
                opaque_login(
                    base_url=base_url,
                    space_id=space_id,
                    username="non-existent-user",
                    password="any-password",
                )


class TestAuthorizationUtilities:
    """Tests for authorization utility methods (roles, users, capabilities)."""

    def test_create_and_manage_roles(
        self, fresh_keypair, symmetric_root, base_url
    ):
        """create_role should store role data at the correct path."""
        space_id = fresh_keypair.to_space_id()

        with Space(
            space_id=space_id,
            member_id=fresh_keypair.to_user_id(),
            private_key=fresh_keypair.private_key,
            symmetric_root=symmetric_root,
            base_url=base_url,
        ) as space:
            # Create a role
            role_name = f"test-role-{uuid.uuid4().hex[:8]}"
            result = space.create_role(role_name, "Test role description")

            assert result.message_hash is not None
            assert result.message_hash.startswith("M")

            # Verify the role was created
            role_data = space.get_plaintext_state(f"auth/roles/{role_name}")
            role = json.loads(role_data)
            assert role["role_id"] == role_name
            assert role["description"] == "Test role description"

    def test_create_and_manage_users(
        self, fresh_keypair, symmetric_root, base_url
    ):
        """add_user should store user data at the correct path."""
        space_id = fresh_keypair.to_space_id()

        with Space(
            space_id=space_id,
            member_id=fresh_keypair.to_user_id(),
            private_key=fresh_keypair.private_key,
            symmetric_root=symmetric_root,
            base_url=base_url,
        ) as space:
            # Create a user entry
            user_id = fresh_keypair.to_user_id()
            result = space.add_user(user_id, "Test user")

            assert result.message_hash is not None

            # Verify the user was created
            user_data = space.get_plaintext_state(f"auth/users/{user_id}")
            user = json.loads(user_data)
            assert user["user_id"] == user_id
            assert user["description"] == "Test user"

    def test_grant_capabilities_to_roles(
        self, fresh_keypair, symmetric_root, base_url
    ):
        """grant_capability_to_role should store capability at correct path."""
        space_id = fresh_keypair.to_space_id()

        with Space(
            space_id=space_id,
            member_id=fresh_keypair.to_user_id(),
            private_key=fresh_keypair.private_key,
            symmetric_root=symmetric_root,
            base_url=base_url,
        ) as space:
            # Create a role
            role_name = f"cap-test-role-{uuid.uuid4().hex[:8]}"
            space.create_role(role_name)

            # Grant a capability to the role
            space.grant_capability_to_role(
                role_name,
                "read_all",
                {"op": "read", "path": "state/{...}"},
            )

            # Verify the capability was granted
            cap_data = space.get_plaintext_state(
                f"auth/roles/{role_name}/rights/read_all"
            )
            cap = json.loads(cap_data)
            assert cap["op"] == "read"
            assert cap["path"] == "state/{...}"

    def test_assign_roles_to_users(
        self, fresh_keypair, symmetric_root, base_url
    ):
        """assign_role_to_user should store role assignment at correct path."""
        space_id = fresh_keypair.to_space_id()

        with Space(
            space_id=space_id,
            member_id=fresh_keypair.to_user_id(),
            private_key=fresh_keypair.private_key,
            symmetric_root=symmetric_root,
            base_url=base_url,
        ) as space:
            # Create a role
            role_name = f"assign-test-role-{uuid.uuid4().hex[:8]}"
            space.create_role(role_name)

            # Create a user
            user_id = fresh_keypair.to_user_id()
            space.add_user(user_id)

            # Assign the role to the user
            space.assign_role_to_user(user_id, role_name)

            # Verify the role was assigned
            role_assignment = space.get_plaintext_state(
                f"auth/users/{user_id}/roles/{role_name}"
            )
            assignment = json.loads(role_assignment)
            assert assignment["role_id"] == role_name
