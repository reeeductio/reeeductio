"""
Tests for AdminSpace validation and functionality

Tests the special validation rules for the admin space:
1. Space registration requires valid space_signature
2. created_by must match authenticated user
3. Path-content consistency for space registry entries
4. User space index validation
"""

import sys
import os
import base64
import json
import time
import asyncio

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from admin_space import AdminSpace, AdminSpaceValidationError
from crypto import CryptoUtils
from identifiers import encode_space_id, encode_user_id, decode_identifier


def set_space_state(space, path, contents, token, keypair):
    """
    Convenience function to sign and set state in a Space using message format.
    """
    crypto = CryptoUtils()

    data = CryptoUtils.base64_encode_object(contents)

    # Get current chain head for prev_hash
    head = space.message_store.get_chain_head(space.space_id, "state")
    prev_hash = head["message_hash"] if head else None

    # Compute message hash
    message_hash = crypto.compute_message_hash(
        space.space_id,
        "state",
        path,
        prev_hash,
        data,
        keypair['id']
    )

    # Sign the message hash
    message_tid = decode_identifier(message_hash)
    message_bytes = message_tid.to_bytes()
    signature_bytes = keypair['private'].sign(message_bytes)
    signature = crypto.base64_encode(signature_bytes)

    # Call async function from sync context
    return asyncio.run(space.set_state(path, prev_hash, data, message_hash, signature, token))


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


def generate_keypair():
    """Generate an Ed25519 keypair for testing"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()
    return {
        'private': private_key,
        'public': public_key,
        'public_bytes': public_key_bytes,
        'user_id': encode_user_id(public_key_bytes),
        'space_id': encode_space_id(public_key_bytes),
        'id': encode_user_id(public_key_bytes)
    }


@pytest.fixture
def admin_space_keypair():
    """Generate a keypair for the admin space itself"""
    return generate_keypair()


@pytest.fixture
def server_user_keypair():
    """Generate a keypair for a server user"""
    return generate_keypair()


@pytest.fixture
def new_space_keypair():
    """Generate a keypair for a new space being registered"""
    return generate_keypair()


@pytest.fixture
def admin_space(admin_space_keypair, message_store, data_store):
    """Create an AdminSpace instance for testing"""
    space_id = admin_space_keypair['space_id']
    secret = base64.b64encode(CryptoUtils.sha256_hash_str("test secret")).decode('utf-8')
    return AdminSpace(space_id, message_store, data_store, None, secret)


def create_user_in_space(space, user_keypair, admin_keypair, token):
    """Helper to add a user to the space"""
    user_id = user_keypair['id']
    user_entry = {
        "user_id": user_id,
        "created_at": int(time.time() * 1000)
    }
    set_space_state(
        space=space,
        path=f"auth/users/{user_id}",
        contents=user_entry,
        token=token,
        keypair=admin_keypair
    )


def grant_space_creator_role(space, user_keypair, admin_keypair, token):
    """Helper to grant the space-creator role to a user"""
    user_id = user_keypair['id']
    now = int(time.time() * 1000)

    # First create the role definition
    role_def = AdminSpace.get_space_creator_role_definition()
    set_space_state(
        space=space,
        path=f"auth/roles/{AdminSpace.SPACE_CREATOR_ROLE}",
        contents=role_def,
        token=token,
        keypair=admin_keypair
    )

    # Create role capabilities
    capabilities = AdminSpace.get_space_creator_capabilities()
    for i, cap in enumerate(capabilities):
        cap_id = f"cap_{i:03d}"
        cap_data = {
            **cap,
            "granted_by": admin_keypair['id'],
            "granted_at": now
        }
        cap_data.pop("description", None)
        set_space_state(
            space=space,
            path=f"auth/roles/{AdminSpace.SPACE_CREATOR_ROLE}/rights/{cap_id}",
            contents=cap_data,
            token=token,
            keypair=admin_keypair
        )

    # Grant role to user
    role_grant = {
        "user_id": user_id,
        "role_id": AdminSpace.SPACE_CREATOR_ROLE,
        "granted_by": admin_keypair['id'],
        "granted_at": now
    }
    set_space_state(
        space=space,
        path=f"auth/users/{user_id}/roles/{AdminSpace.SPACE_CREATOR_ROLE}",
        contents=role_grant,
        token=token,
        keypair=admin_keypair
    )


def create_space_signature(space_keypair, created_by, created_at):
    """Create a valid space_signature for registration"""
    space_id = space_keypair['space_id']
    canonical_message = f"{space_id}|{created_by}|{created_at}"
    message_bytes = canonical_message.encode('utf-8')
    signature_bytes = space_keypair['private'].sign(message_bytes)
    return base64.b64encode(signature_bytes).decode('utf-8')


class TestAdminSpaceValidation:
    """Tests for AdminSpace-specific validation"""

    def test_valid_space_registration(
        self, admin_space, admin_space_keypair, server_user_keypair, new_space_keypair
    ):
        """Test that valid space registration succeeds"""
        # Setup: authenticate admin and create server user with space-creator role
        admin_token = authenticate_with_challenge(
            admin_space, admin_space_keypair['id'], admin_space_keypair['private']
        )
        create_user_in_space(admin_space, server_user_keypair, admin_space_keypair, admin_token)
        grant_space_creator_role(admin_space, server_user_keypair, admin_space_keypair, admin_token)

        # Now authenticate as server user
        user_token = authenticate_with_challenge(
            admin_space, server_user_keypair['id'], server_user_keypair['private']
        )

        # Create valid registration data
        created_at = int(time.time() * 1000)
        space_signature = create_space_signature(
            new_space_keypair,
            server_user_keypair['id'],
            created_at
        )
        registration = {
            "space_id": new_space_keypair['space_id'],
            "created_by": server_user_keypair['id'],
            "created_at": created_at,
            "space_signature": space_signature
        }

        # Register the space
        set_space_state(
            space=admin_space,
            path=f"spaces/{new_space_keypair['space_id']}",
            contents=registration,
            token=user_token,
            keypair=server_user_keypair
        )

        # Verify registration was stored
        stored = admin_space.state_store.get_state(
            admin_space.space_id,
            f"spaces/{new_space_keypair['space_id']}"
        )
        assert stored is not None
        stored_data = json.loads(base64.b64decode(stored['data']))
        assert stored_data['space_id'] == new_space_keypair['space_id']
        assert stored_data['created_by'] == server_user_keypair['id']

    def test_space_registration_wrong_created_by(
        self, admin_space, admin_space_keypair, server_user_keypair, new_space_keypair
    ):
        """Test that registration fails if created_by doesn't match authenticated user"""
        # Setup
        admin_token = authenticate_with_challenge(
            admin_space, admin_space_keypair['id'], admin_space_keypair['private']
        )
        create_user_in_space(admin_space, server_user_keypair, admin_space_keypair, admin_token)
        grant_space_creator_role(admin_space, server_user_keypair, admin_space_keypair, admin_token)

        user_token = authenticate_with_challenge(
            admin_space, server_user_keypair['id'], server_user_keypair['private']
        )

        # Create registration with wrong created_by (admin's ID instead of user's)
        created_at = int(time.time() * 1000)
        space_signature = create_space_signature(
            new_space_keypair,
            admin_space_keypair['id'],  # Wrong! Should be server_user_keypair['id']
            created_at
        )
        registration = {
            "space_id": new_space_keypair['space_id'],
            "created_by": admin_space_keypair['id'],  # Wrong!
            "created_at": created_at,
            "space_signature": space_signature
        }

        # Should fail with validation error
        with pytest.raises(ValueError) as exc_info:
            set_space_state(
                space=admin_space,
                path=f"spaces/{new_space_keypair['space_id']}",
                contents=registration,
                token=user_token,
                keypair=server_user_keypair
            )
        assert "created_by must match authenticated user" in str(exc_info.value)

    def test_space_registration_invalid_space_signature(
        self, admin_space, admin_space_keypair, server_user_keypair, new_space_keypair
    ):
        """Test that registration fails with invalid space_signature"""
        # Setup
        admin_token = authenticate_with_challenge(
            admin_space, admin_space_keypair['id'], admin_space_keypair['private']
        )
        create_user_in_space(admin_space, server_user_keypair, admin_space_keypair, admin_token)
        grant_space_creator_role(admin_space, server_user_keypair, admin_space_keypair, admin_token)

        user_token = authenticate_with_challenge(
            admin_space, server_user_keypair['id'], server_user_keypair['private']
        )

        # Create registration with wrong signature (signed by user, not space)
        created_at = int(time.time() * 1000)
        # Sign with user's key instead of space's key
        canonical_message = f"{new_space_keypair['space_id']}|{server_user_keypair['id']}|{created_at}"
        message_bytes = canonical_message.encode('utf-8')
        wrong_signature_bytes = server_user_keypair['private'].sign(message_bytes)
        wrong_signature = base64.b64encode(wrong_signature_bytes).decode('utf-8')

        registration = {
            "space_id": new_space_keypair['space_id'],
            "created_by": server_user_keypair['id'],
            "created_at": created_at,
            "space_signature": wrong_signature  # Wrong! Signed by user, not space
        }

        # Should fail with validation error
        with pytest.raises(ValueError) as exc_info:
            set_space_state(
                space=admin_space,
                path=f"spaces/{new_space_keypair['space_id']}",
                contents=registration,
                token=user_token,
                keypair=server_user_keypair
            )
        assert "Invalid space_signature" in str(exc_info.value)

    def test_space_registration_missing_space_signature(
        self, admin_space, admin_space_keypair, server_user_keypair, new_space_keypair
    ):
        """Test that registration fails without space_signature"""
        # Setup
        admin_token = authenticate_with_challenge(
            admin_space, admin_space_keypair['id'], admin_space_keypair['private']
        )
        create_user_in_space(admin_space, server_user_keypair, admin_space_keypair, admin_token)
        grant_space_creator_role(admin_space, server_user_keypair, admin_space_keypair, admin_token)

        user_token = authenticate_with_challenge(
            admin_space, server_user_keypair['id'], server_user_keypair['private']
        )

        # Create registration without space_signature
        created_at = int(time.time() * 1000)
        registration = {
            "space_id": new_space_keypair['space_id'],
            "created_by": server_user_keypair['id'],
            "created_at": created_at
            # Missing space_signature!
        }

        # Should fail with validation error
        with pytest.raises(ValueError) as exc_info:
            set_space_state(
                space=admin_space,
                path=f"spaces/{new_space_keypair['space_id']}",
                contents=registration,
                token=user_token,
                keypair=server_user_keypair
            )
        assert "space_signature is required" in str(exc_info.value)

    def test_space_registration_space_id_mismatch(
        self, admin_space, admin_space_keypair, server_user_keypair, new_space_keypair
    ):
        """Test that registration fails if space_id in data doesn't match path"""
        # Setup
        admin_token = authenticate_with_challenge(
            admin_space, admin_space_keypair['id'], admin_space_keypair['private']
        )
        create_user_in_space(admin_space, server_user_keypair, admin_space_keypair, admin_token)
        grant_space_creator_role(admin_space, server_user_keypair, admin_space_keypair, admin_token)

        user_token = authenticate_with_challenge(
            admin_space, server_user_keypair['id'], server_user_keypair['private']
        )

        # Create registration with mismatched space_id
        other_space = generate_keypair()
        created_at = int(time.time() * 1000)
        space_signature = create_space_signature(
            new_space_keypair,
            server_user_keypair['id'],
            created_at
        )
        registration = {
            "space_id": other_space['space_id'],  # Wrong! Doesn't match path
            "created_by": server_user_keypair['id'],
            "created_at": created_at,
            "space_signature": space_signature
        }

        # Should fail with validation error
        with pytest.raises(ValueError) as exc_info:
            set_space_state(
                space=admin_space,
                path=f"spaces/{new_space_keypair['space_id']}",  # Path uses new_space_keypair
                contents=registration,
                token=user_token,
                keypair=server_user_keypair
            )
        assert "space_id mismatch" in str(exc_info.value)


class TestUserSpaceIndex:
    """Tests for user space index validation"""

    def test_valid_user_space_index(
        self, admin_space, admin_space_keypair, server_user_keypair, new_space_keypair
    ):
        """Test that valid user space index write succeeds"""
        # Setup
        admin_token = authenticate_with_challenge(
            admin_space, admin_space_keypair['id'], admin_space_keypair['private']
        )
        create_user_in_space(admin_space, server_user_keypair, admin_space_keypair, admin_token)
        grant_space_creator_role(admin_space, server_user_keypair, admin_space_keypair, admin_token)

        user_token = authenticate_with_challenge(
            admin_space, server_user_keypair['id'], server_user_keypair['private']
        )

        # First register the space
        created_at = int(time.time() * 1000)
        space_signature = create_space_signature(
            new_space_keypair,
            server_user_keypair['id'],
            created_at
        )
        registration = {
            "space_id": new_space_keypair['space_id'],
            "created_by": server_user_keypair['id'],
            "created_at": created_at,
            "space_signature": space_signature
        }
        set_space_state(
            space=admin_space,
            path=f"spaces/{new_space_keypair['space_id']}",
            contents=registration,
            token=user_token,
            keypair=server_user_keypair
        )

        # Now create the user space index entry
        index_entry = {
            "space_id": new_space_keypair['space_id']
        }
        set_space_state(
            space=admin_space,
            path=f"users/{server_user_keypair['id']}/spaces/{new_space_keypair['space_id']}",
            contents=index_entry,
            token=user_token,
            keypair=server_user_keypair
        )

        # Verify index entry was stored
        stored = admin_space.state_store.get_state(
            admin_space.space_id,
            f"users/{server_user_keypair['id']}/spaces/{new_space_keypair['space_id']}"
        )
        assert stored is not None

    def test_user_space_index_space_id_mismatch(
        self, admin_space, admin_space_keypair, server_user_keypair, new_space_keypair
    ):
        """Test that user space index fails if space_id in data doesn't match path"""
        # Setup
        admin_token = authenticate_with_challenge(
            admin_space, admin_space_keypair['id'], admin_space_keypair['private']
        )
        create_user_in_space(admin_space, server_user_keypair, admin_space_keypair, admin_token)
        grant_space_creator_role(admin_space, server_user_keypair, admin_space_keypair, admin_token)

        user_token = authenticate_with_challenge(
            admin_space, server_user_keypair['id'], server_user_keypair['private']
        )

        # Try to write index entry with mismatched space_id
        other_space = generate_keypair()
        index_entry = {
            "space_id": other_space['space_id']  # Wrong! Doesn't match path
        }

        with pytest.raises(ValueError) as exc_info:
            set_space_state(
                space=admin_space,
                path=f"users/{server_user_keypair['id']}/spaces/{new_space_keypair['space_id']}",
                contents=index_entry,
                token=user_token,
                keypair=server_user_keypair
            )
        assert "space_id mismatch" in str(exc_info.value)


class TestBootstrapMethods:
    """Tests for AdminSpace bootstrap methods"""

    def test_get_space_creator_role_definition(self):
        """Test that role definition has expected structure"""
        role_def = AdminSpace.get_space_creator_role_definition()
        assert role_def['role_id'] == 'space-creator'
        assert 'description' in role_def

    def test_get_space_creator_capabilities(self):
        """Test that capabilities have expected structure"""
        caps = AdminSpace.get_space_creator_capabilities()
        assert len(caps) == 2

        # Check first capability (create spaces)
        assert caps[0]['op'] == 'create'
        assert 'spaces' in caps[0]['path']

        # Check second capability (create user space index)
        assert caps[1]['op'] == 'create'
        assert 'users' in caps[1]['path']
        assert '{self}' in caps[1]['path']

    def test_get_bootstrap_state_entries(self, admin_space, admin_space_keypair):
        """Test that bootstrap entries are generated correctly"""
        now = int(time.time() * 1000)
        entries = admin_space.get_bootstrap_state_entries(admin_space_keypair['id'], now)

        # Should have role definition + 2 capabilities
        assert len(entries) == 3

        # First entry should be role definition
        path, data = entries[0]
        assert path == f"auth/roles/{AdminSpace.SPACE_CREATOR_ROLE}"
        assert data['role_id'] == AdminSpace.SPACE_CREATOR_ROLE

        # Remaining entries should be capabilities
        for path, data in entries[1:]:
            assert 'rights' in path
            assert 'op' in data
            assert 'path' in data
            assert data['granted_by'] == admin_space_keypair['id']
            assert data['granted_at'] == now
            assert 'description' not in data  # Should be stripped

    def test_is_bootstrapped_false_initially(self, admin_space):
        """Test that is_bootstrapped returns False for fresh admin space"""
        assert admin_space.is_bootstrapped() is False

    def test_is_bootstrapped_true_after_setup(
        self, admin_space, admin_space_keypair
    ):
        """Test that is_bootstrapped returns True after role is created"""
        admin_token = authenticate_with_challenge(
            admin_space, admin_space_keypair['id'], admin_space_keypair['private']
        )

        # Create the role definition
        role_def = AdminSpace.get_space_creator_role_definition()
        set_space_state(
            space=admin_space,
            path=f"auth/roles/{AdminSpace.SPACE_CREATOR_ROLE}",
            contents=role_def,
            token=admin_token,
            keypair=admin_space_keypair
        )

        assert admin_space.is_bootstrapped() is True


class TestRegularOperationsUnaffected:
    """Tests that regular space operations still work normally"""

    def test_regular_state_write_still_works(self, admin_space, admin_space_keypair):
        """Test that normal state writes (not space registration) work"""
        admin_token = authenticate_with_challenge(
            admin_space, admin_space_keypair['id'], admin_space_keypair['private']
        )

        # Write to a regular path (not spaces/{id})
        set_space_state(
            space=admin_space,
            path="config/settings",
            contents={"key": "value"},
            token=admin_token,
            keypair=admin_space_keypair
        )

        # Should succeed
        stored = admin_space.state_store.get_state(admin_space.space_id, "config/settings")
        assert stored is not None

    def test_auth_operations_still_work(self, admin_space, admin_space_keypair, server_user_keypair):
        """Test that auth operations like adding users still work"""
        admin_token = authenticate_with_challenge(
            admin_space, admin_space_keypair['id'], admin_space_keypair['private']
        )

        # Create a user
        create_user_in_space(admin_space, server_user_keypair, admin_space_keypair, admin_token)

        # Should succeed
        stored = admin_space.state_store.get_state(
            admin_space.space_id,
            f"auth/users/{server_user_keypair['id']}"
        )
        assert stored is not None
