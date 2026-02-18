"""
Tests for OPAQUE password-based key recovery endpoints.

OPAQUE is used to recover Ed25519 keys from a password. The protocol:
1. Registration (requires auth): Stores password_file and encrypted credentials
2. Login (no auth): Recovers credentials using password

See LOGIN-AND-SSO.md for design details.
"""
import pytest
import json
import base64
import time
import sys
import os
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))
# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import conftest
authenticate_with_challenge = conftest.authenticate_with_challenge
sign_and_store_data = conftest.sign_and_store_data

from opaque_snake import (
    OpaqueServer,
    OpaqueClient,
    RegistrationRequest,
    RegistrationResponse,
    RegistrationUpload,
    CredentialRequest,
    CredentialResponse,
    CredentialFinalization,
    PasswordFile,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def opaque_server():
    """Create an OPAQUE server instance for testing."""
    return OpaqueServer()


@pytest.fixture
def opaque_enabled_space(unique_space, unique_admin_keypair, opaque_server):
    """
    Create a space with OPAQUE enabled (server setup uploaded).

    Returns tuple of (space, admin_token, admin_keypair).
    """
    space = unique_space
    admin_keypair = unique_admin_keypair

    # Authenticate as admin
    admin_token = authenticate_with_challenge(
        space, admin_keypair['user_id'], admin_keypair['private']
    )

    # Upload OPAQUE server setup to enable OPAQUE for this space
    # The server setup needs to be stored as raw base64 (not wrapped in JSON)
    setup_bytes = opaque_server.export_setup()
    setup_b64 = base64.b64encode(setup_bytes).decode('ascii')

    # Use data_store.set_data directly to avoid JSON encoding issues
    # The setup is stored as raw base64 bytes
    signed_at = int(time.time() * 1000)
    message = f"{space.space_id}|opaque/server/setup|{setup_b64}|{signed_at}"
    signature_bytes = admin_keypair['private'].sign(message.encode('utf-8'))
    signature = base64.b64encode(signature_bytes).decode('utf-8')

    space.data_store.set_data(
        space_id=space.space_id,
        path="opaque/server/setup",
        data=setup_b64,  # Store raw base64, not JSON-encoded
        signature=signature,
        signed_by=admin_keypair['user_id'],
        signed_at=signed_at
    )

    # Clear the cached server to force reload from data store
    space._opaque_server = None

    return space, admin_token, admin_keypair


# ============================================================================
# Basic Tests
# ============================================================================

class TestOpaqueServerSetup:
    """Tests for OPAQUE server setup and availability."""

    def test_opaque_not_enabled_without_setup(self, unique_space):
        """OPAQUE endpoints should fail if server setup is not uploaded."""
        space = unique_space

        with pytest.raises(ValueError, match="OPAQUE is not enabled"):
            space._get_opaque_server()

    def test_opaque_enabled_with_setup(self, opaque_enabled_space):
        """OPAQUE server should be available after setup is uploaded."""
        space, _, _ = opaque_enabled_space

        server = space._get_opaque_server()
        assert server is not None

    def test_opaque_server_cached(self, opaque_enabled_space):
        """OPAQUE server instance should be cached."""
        space, _, _ = opaque_enabled_space

        server1 = space._get_opaque_server()
        server2 = space._get_opaque_server()

        assert server1 is server2


# ============================================================================
# Registration Tests
# ============================================================================

class TestOpaqueRegistration:
    """Tests for OPAQUE registration (register/init and register/finish)."""

    def test_register_init_requires_auth(self, opaque_enabled_space):
        """Registration init should require authentication."""
        space, _, admin_keypair = opaque_enabled_space

        # Create a client and registration request
        client = OpaqueClient()
        registration_request, client_state = client.start_registration("test-password")
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        # Should fail without a valid token
        with pytest.raises(ValueError):
            space.opaque_register_init(
                username="testuser",
                registration_request_b64=request_b64,
                token="invalid-token"
            )

    def test_register_init_success(self, opaque_enabled_space):
        """Registration init should return a registration response."""
        space, admin_token, _ = opaque_enabled_space

        # Create registration request
        client = OpaqueClient()
        registration_request, client_reg_state = client.start_registration("test-password")
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        # Call register/init
        result = space.opaque_register_init(
            username="testuser",
            registration_request_b64=request_b64,
            token=admin_token
        )

        # Should return base64-encoded registration response
        assert "registration_response" in result
        response_bytes = base64.b64decode(result["registration_response"])
        response = RegistrationResponse.from_bytes(response_bytes)
        assert response is not None

    def test_register_finish_requires_init(self, opaque_enabled_space):
        """Registration finish should fail if init was not called."""
        space, admin_token, _ = opaque_enabled_space

        # Try to finish without calling init first
        with pytest.raises(ValueError, match="No pending registration"):
            space.opaque_register_finish(
                username="testuser",
                registration_record_b64=base64.b64encode(b"fake-data").decode('ascii'),
                token=admin_token
            )

    def test_register_finish_requires_same_user(self, opaque_enabled_space, user_keypair):
        """Registration finish must be called by the same user who called init."""
        from conftest import set_space_state

        space, admin_token, admin_keypair = opaque_enabled_space

        # Add a second user to the space
        set_space_state = conftest.set_space_state
        set_space_state(
            space=space,
            path=f"auth/users/{user_keypair['user_id']}",
            contents={"user_id": user_keypair['user_id']},
            token=admin_token,
            keypair=admin_keypair
        )
        user_token = authenticate_with_challenge(
            space, user_keypair['user_id'], user_keypair['private']
        )

        # Admin calls register/init
        client = OpaqueClient()
        registration_request, client_reg_state = client.start_registration("test-password")
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        space.opaque_register_init(
            username="testuser",
            registration_request_b64=request_b64,
            token=admin_token
        )

        # Different user tries to call register/finish - should fail
        with pytest.raises(ValueError, match="same user who initiated"):
            space.opaque_register_finish(
                username="testuser",
                registration_record_b64=base64.b64encode(b"fake-data").decode('ascii'),
                token=user_token
            )

    def test_register_full_flow(self, opaque_enabled_space):
        """Test complete registration flow: init -> finish."""
        space, admin_token, _ = opaque_enabled_space
        password = "secure-password-123"
        username = "alice"

        # Client-side: create registration request
        client = OpaqueClient()
        registration_request, client_reg_state = client.start_registration(password)
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        # Server-side: register/init
        init_result = space.opaque_register_init(
            username=username,
            registration_request_b64=request_b64,
            token=admin_token
        )

        # Client-side: process response and create registration record
        response_bytes = base64.b64decode(init_result["registration_response"])
        registration_response = RegistrationResponse.from_bytes(response_bytes)
        registration_result = client.finish_registration(
            registration_response, client_reg_state, password
        )
        registration_record = registration_result.upload
        export_key = registration_result.export_key

        # Server-side: register/finish
        record_b64 = base64.b64encode(registration_record.to_bytes()).decode('ascii')
        finish_result = space.opaque_register_finish(
            username=username,
            registration_record_b64=record_b64,
            token=admin_token
        )

        # Should return password_file for client to store
        assert "password_file" in finish_result
        password_file_bytes = base64.b64decode(finish_result["password_file"])
        password_file = PasswordFile.from_bytes(password_file_bytes)
        assert password_file is not None

    def test_register_duplicate_username_rejected(self, opaque_enabled_space):
        """Registering the same username twice should fail."""
        space, admin_token, admin_keypair = opaque_enabled_space
        password = "test-password"
        username = "duplicate-user"

        # Complete first registration
        client = OpaqueClient()
        registration_request, client_reg_state = client.start_registration(password)
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        init_result = space.opaque_register_init(
            username=username,
            registration_request_b64=request_b64,
            token=admin_token
        )

        response_bytes = base64.b64decode(init_result["registration_response"])
        registration_response = RegistrationResponse.from_bytes(response_bytes)
        registration_result = client.finish_registration(
            registration_response, client_reg_state, password
        )
        registration_record = registration_result.upload
        export_key = registration_result.export_key

        record_b64 = base64.b64encode(registration_record.to_bytes()).decode('ascii')
        finish_result = space.opaque_register_finish(
            username=username,
            registration_record_b64=record_b64,
            token=admin_token
        )

        # Store the OPAQUE record (simulating client behavior)
        opaque_record = {
            "password_file": finish_result["password_file"],
            "encrypted_credentials": base64.b64encode(b"fake-encrypted-creds").decode('ascii'),
            "public_key": admin_keypair['user_id']
        }

        # Store directly to data store
        record_b64_for_storage = base64.b64encode(json.dumps(opaque_record).encode()).decode()
        signed_at = int(time.time() * 1000)
        message = f"{space.space_id}|opaque/users/{username}|{record_b64_for_storage}|{signed_at}"
        signature_bytes = admin_keypair['private'].sign(message.encode('utf-8'))
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        space.data_store.set_data(
            space_id=space.space_id,
            path=f"opaque/users/{username}",
            data=record_b64_for_storage,
            signature=signature,
            signed_by=admin_keypair['user_id'],
            signed_at=signed_at
        )

        # Try to register same username again - should fail at init
        client2 = OpaqueClient()
        registration_request2, _ = client2.start_registration("different-password")
        request_b64_2 = base64.b64encode(registration_request2.to_bytes()).decode('ascii')

        with pytest.raises(ValueError, match="already registered"):
            space.opaque_register_init(
                username=username,
                registration_request_b64=request_b64_2,
                token=admin_token
            )


# ============================================================================
# Login Tests
# ============================================================================

class TestOpaqueLogin:
    """Tests for OPAQUE login (login/init and login/finish)."""

    def test_login_init_user_not_found(self, opaque_enabled_space):
        """Login init should fail for non-existent user."""
        space, _, _ = opaque_enabled_space

        client = OpaqueClient()
        credential_request, _ = client.start_login("any-password")
        request_b64 = base64.b64encode(credential_request.to_bytes()).decode('ascii')

        with pytest.raises(ValueError, match="not found"):
            space.opaque_login_init(
                username="nonexistent-user",
                credential_request_b64=request_b64
            )

    def test_login_finish_requires_init(self, opaque_enabled_space):
        """Login finish should fail if init was not called."""
        space, _, _ = opaque_enabled_space

        with pytest.raises(ValueError, match="No pending login"):
            space.opaque_login_finish(
                username="testuser",
                credential_finalization_b64=base64.b64encode(b"fake-data").decode('ascii')
            )

    def test_login_full_flow_wrong_password(self, opaque_enabled_space):
        """Login with wrong password should fail at finish step."""
        space, admin_token, admin_keypair = opaque_enabled_space
        correct_password = "correct-password"
        wrong_password = "wrong-password"
        username = "login-test-user"

        # First, complete registration
        client = OpaqueClient()
        registration_request, client_reg_state = client.start_registration(correct_password)
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        init_result = space.opaque_register_init(
            username=username,
            registration_request_b64=request_b64,
            token=admin_token
        )

        response_bytes = base64.b64decode(init_result["registration_response"])
        registration_response = RegistrationResponse.from_bytes(response_bytes)
        registration_result = client.finish_registration(
            registration_response, client_reg_state, correct_password
        )
        registration_record = registration_result.upload
        export_key = registration_result.export_key

        record_b64 = base64.b64encode(registration_record.to_bytes()).decode('ascii')
        finish_result = space.opaque_register_finish(
            username=username,
            registration_record_b64=record_b64,
            token=admin_token
        )

        # Store the OPAQUE record
        opaque_record = {
            "password_file": finish_result["password_file"],
            "encrypted_credentials": base64.b64encode(b"fake-encrypted-creds").decode('ascii'),
            "public_key": admin_keypair['user_id']
        }
        record_b64_for_storage = base64.b64encode(json.dumps(opaque_record).encode()).decode()
        signed_at = int(time.time() * 1000)
        message = f"{space.space_id}|opaque/users/{username}|{record_b64_for_storage}|{signed_at}"
        signature_bytes = admin_keypair['private'].sign(message.encode('utf-8'))
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        space.data_store.set_data(
            space_id=space.space_id,
            path=f"opaque/users/{username}",
            data=record_b64_for_storage,
            signature=signature,
            signed_by=admin_keypair['user_id'],
            signed_at=signed_at
        )

        # Now try to login with wrong password
        login_client = OpaqueClient()
        credential_request, client_login_state = login_client.start_login(wrong_password)
        request_b64 = base64.b64encode(credential_request.to_bytes()).decode('ascii')

        # Login init should succeed (server doesn't know password yet)
        login_init_result = space.opaque_login_init(
            username=username,
            credential_request_b64=request_b64
        )

        # Process response
        credential_response_bytes = base64.b64decode(login_init_result["credential_response"])
        credential_response = CredentialResponse.from_bytes(credential_response_bytes)

        # Client finishes login - this will fail because password is wrong
        # The exception happens client-side in the OPAQUE library
        with pytest.raises(Exception):
            login_result = login_client.finish_login(
                credential_response, client_login_state, wrong_password
            )


class TestOpaqueFullFlow:
    """End-to-end tests for complete OPAQUE registration and login."""

    def test_register_then_login_success(self, opaque_enabled_space):
        """Test complete flow: register with password, then login to recover credentials."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        space, admin_token, admin_keypair = opaque_enabled_space
        password = "my-secure-password"
        username = "full-flow-user"

        # Generate a user keypair and symmetric root
        user_private_key = ed25519.Ed25519PrivateKey.generate()
        user_public_key = user_private_key.public_key()
        private_key_bytes = user_private_key.private_bytes_raw()
        public_key_bytes = user_public_key.public_bytes_raw()
        symmetric_root = os.urandom(32)

        from identifiers import encode_user_id
        user_id = encode_user_id(public_key_bytes)

        # === REGISTRATION ===

        # Client: create registration request
        reg_client = OpaqueClient()
        registration_request, client_reg_state = reg_client.start_registration(password)
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        # Server: register/init
        init_result = space.opaque_register_init(
            username=username,
            registration_request_b64=request_b64,
            token=admin_token
        )

        # Client: process response and create registration record
        response_bytes = base64.b64decode(init_result["registration_response"])
        registration_response = RegistrationResponse.from_bytes(response_bytes)
        registration_result = reg_client.finish_registration(
            registration_response, client_reg_state, password
        )
        registration_record = registration_result.upload
        export_key = registration_result.export_key

        # Server: register/finish
        record_b64 = base64.b64encode(registration_record.to_bytes()).decode('ascii')
        finish_result = space.opaque_register_finish(
            username=username,
            registration_record_b64=record_b64,
            token=admin_token
        )

        # Client: wrap credentials with export_key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"reeeductio-credential-wrap"
        )
        wrap_key = hkdf.derive(export_key)

        nonce = os.urandom(12)
        aesgcm = AESGCM(wrap_key)
        plaintext = private_key_bytes + symmetric_root  # 64 bytes
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        encrypted_credentials = nonce + ciphertext

        # Store the complete OPAQUE record
        opaque_record = {
            "password_file": finish_result["password_file"],
            "encrypted_credentials": base64.b64encode(encrypted_credentials).decode('ascii'),
            "public_key": user_id
        }
        record_b64_for_storage = base64.b64encode(json.dumps(opaque_record).encode()).decode()
        signed_at = int(time.time() * 1000)
        message = f"{space.space_id}|opaque/users/{username}|{record_b64_for_storage}|{signed_at}"
        signature_bytes = admin_keypair['private'].sign(message.encode('utf-8'))
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        space.data_store.set_data(
            space_id=space.space_id,
            path=f"opaque/users/{username}",
            data=record_b64_for_storage,
            signature=signature,
            signed_by=admin_keypair['user_id'],
            signed_at=signed_at
        )

        # === LOGIN ===

        # Client: create credential request
        login_client = OpaqueClient()
        credential_request, client_login_state = login_client.start_login(password)
        request_b64 = base64.b64encode(credential_request.to_bytes()).decode('ascii')

        # Server: login/init
        login_init_result = space.opaque_login_init(
            username=username,
            credential_request_b64=request_b64
        )

        # Client: process response and create finalization
        credential_response_bytes = base64.b64decode(login_init_result["credential_response"])
        credential_response = CredentialResponse.from_bytes(credential_response_bytes)
        login_result = login_client.finish_login(
            credential_response, client_login_state, password
        )
        credential_finalization = login_result.finalization
        login_export_key = login_result.session_keys.export_key

        # Server: login/finish
        finalization_b64 = base64.b64encode(credential_finalization.to_bytes()).decode('ascii')
        login_finish_result = space.opaque_login_finish(
            username=username,
            credential_finalization_b64=finalization_b64
        )

        # Should return encrypted_credentials and public_key
        assert "encrypted_credentials" in login_finish_result
        assert "public_key" in login_finish_result
        assert login_finish_result["public_key"] == user_id

        # Client: unwrap credentials
        login_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"reeeductio-credential-wrap"
        )
        login_wrap_key = login_hkdf.derive(login_export_key)

        encrypted_creds = base64.b64decode(login_finish_result["encrypted_credentials"])
        nonce = encrypted_creds[:12]
        ciphertext = encrypted_creds[12:]

        login_aesgcm = AESGCM(login_wrap_key)
        recovered_plaintext = login_aesgcm.decrypt(nonce, ciphertext, None)

        recovered_private_key = recovered_plaintext[:32]
        recovered_symmetric_root = recovered_plaintext[32:]

        # Verify we recovered the correct credentials
        assert recovered_private_key == private_key_bytes
        assert recovered_symmetric_root == symmetric_root


# ============================================================================
# State Expiration Tests
# ============================================================================

class TestOpaqueStateExpiration:
    """Tests for OPAQUE state cleanup and expiration."""

    def test_registration_state_expires(self, opaque_enabled_space):
        """Registration state should expire after timeout."""
        space, admin_token, _ = opaque_enabled_space

        # Set a very short expiry for testing
        space._opaque_state_expiry_seconds = 0  # Immediate expiry

        # Start registration
        client = OpaqueClient()
        registration_request, client_reg_state = client.start_registration("test-password")
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        space.opaque_register_init(
            username="expiring-user",
            registration_request_b64=request_b64,
            token=admin_token
        )

        # Wait a moment and cleanup should expire the state
        time.sleep(0.01)
        space._cleanup_expired_opaque_state()

        # Try to finish - should fail as state expired
        with pytest.raises(ValueError, match="No pending registration"):
            space.opaque_register_finish(
                username="expiring-user",
                registration_record_b64=base64.b64encode(b"fake").decode('ascii'),
                token=admin_token
            )

    def test_login_state_expires(self, opaque_enabled_space):
        """Login state should expire after timeout."""
        space, admin_token, admin_keypair = opaque_enabled_space
        username = "login-expiry-user"
        password = "test-password"

        # First register a user
        client = OpaqueClient()
        registration_request, client_reg_state = client.start_registration(password)
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        init_result = space.opaque_register_init(
            username=username,
            registration_request_b64=request_b64,
            token=admin_token
        )

        response_bytes = base64.b64decode(init_result["registration_response"])
        registration_response = RegistrationResponse.from_bytes(response_bytes)
        registration_result = client.finish_registration(
            registration_response, client_reg_state, password
        )
        registration_record = registration_result.upload
        export_key = registration_result.export_key

        record_b64 = base64.b64encode(registration_record.to_bytes()).decode('ascii')
        finish_result = space.opaque_register_finish(
            username=username,
            registration_record_b64=record_b64,
            token=admin_token
        )

        # Store the OPAQUE record
        opaque_record = {
            "password_file": finish_result["password_file"],
            "encrypted_credentials": base64.b64encode(b"fake-creds").decode('ascii'),
            "public_key": admin_keypair['user_id']
        }
        record_b64_for_storage = base64.b64encode(json.dumps(opaque_record).encode()).decode()
        signed_at = int(time.time() * 1000)
        message = f"{space.space_id}|opaque/users/{username}|{record_b64_for_storage}|{signed_at}"
        signature_bytes = admin_keypair['private'].sign(message.encode('utf-8'))
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        space.data_store.set_data(
            space_id=space.space_id,
            path=f"opaque/users/{username}",
            data=record_b64_for_storage,
            signature=signature,
            signed_by=admin_keypair['user_id'],
            signed_at=signed_at
        )

        # Set a very short expiry for testing
        space._opaque_state_expiry_seconds = 0

        # Start login
        login_client = OpaqueClient()
        credential_request, _ = login_client.start_login("test-password")
        request_b64 = base64.b64encode(credential_request.to_bytes()).decode('ascii')

        space.opaque_login_init(
            username=username,
            credential_request_b64=request_b64
        )

        # Wait a moment and cleanup should expire the state
        time.sleep(0.01)
        space._cleanup_expired_opaque_state()

        # Try to finish - should fail as state expired
        with pytest.raises(ValueError, match="No pending login"):
            space.opaque_login_finish(
                username=username,
                credential_finalization_b64=base64.b64encode(b"fake").decode('ascii')
            )


# ============================================================================
# Invalid Input Tests
# ============================================================================

class TestOpaqueInvalidInput:
    """Tests for handling invalid input to OPAQUE endpoints."""

    def test_register_init_invalid_request(self, opaque_enabled_space):
        """Registration init should reject invalid registration request."""
        space, admin_token, _ = opaque_enabled_space

        with pytest.raises(ValueError, match="Invalid registration request"):
            space.opaque_register_init(
                username="testuser",
                registration_request_b64=base64.b64encode(b"not-valid-opaque-data").decode('ascii'),
                token=admin_token
            )

    def test_register_finish_invalid_record(self, opaque_enabled_space):
        """Registration finish should reject invalid registration record."""
        space, admin_token, _ = opaque_enabled_space

        # First do a valid init
        client = OpaqueClient()
        registration_request, client_reg_state = client.start_registration("test-password")
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        space.opaque_register_init(
            username="testuser",
            registration_request_b64=request_b64,
            token=admin_token
        )

        # Try to finish with invalid data
        with pytest.raises(ValueError, match="Invalid registration record"):
            space.opaque_register_finish(
                username="testuser",
                registration_record_b64=base64.b64encode(b"not-valid-opaque-data").decode('ascii'),
                token=admin_token
            )

    def test_login_init_invalid_request(self, opaque_enabled_space):
        """Login init should reject invalid credential request."""
        space, admin_token, admin_keypair = opaque_enabled_space
        username = "invalid-login-user"
        password = "test-password"

        # First register a user
        client = OpaqueClient()
        registration_request, client_reg_state = client.start_registration(password)
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        init_result = space.opaque_register_init(
            username=username,
            registration_request_b64=request_b64,
            token=admin_token
        )

        response_bytes = base64.b64decode(init_result["registration_response"])
        registration_response = RegistrationResponse.from_bytes(response_bytes)
        registration_result = client.finish_registration(
            registration_response, client_reg_state, password
        )
        registration_record = registration_result.upload
        export_key = registration_result.export_key

        record_b64 = base64.b64encode(registration_record.to_bytes()).decode('ascii')
        finish_result = space.opaque_register_finish(
            username=username,
            registration_record_b64=record_b64,
            token=admin_token
        )

        # Store the OPAQUE record
        opaque_record = {
            "password_file": finish_result["password_file"],
            "encrypted_credentials": base64.b64encode(b"fake-creds").decode('ascii'),
            "public_key": admin_keypair['user_id']
        }
        record_b64_for_storage = base64.b64encode(json.dumps(opaque_record).encode()).decode()
        signed_at = int(time.time() * 1000)
        message = f"{space.space_id}|opaque/users/{username}|{record_b64_for_storage}|{signed_at}"
        signature_bytes = admin_keypair['private'].sign(message.encode('utf-8'))
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        space.data_store.set_data(
            space_id=space.space_id,
            path=f"opaque/users/{username}",
            data=record_b64_for_storage,
            signature=signature,
            signed_by=admin_keypair['user_id'],
            signed_at=signed_at
        )

        # Try login with invalid request
        with pytest.raises(ValueError, match="Invalid credential request"):
            space.opaque_login_init(
                username=username,
                credential_request_b64=base64.b64encode(b"not-valid-opaque-data").decode('ascii')
            )

    def test_login_finish_invalid_finalization(self, opaque_enabled_space):
        """Login finish should reject invalid credential finalization."""
        space, admin_token, admin_keypair = opaque_enabled_space
        username = "invalid-finish-user"
        password = "test-password"

        # First register a user
        client = OpaqueClient()
        registration_request, client_reg_state = client.start_registration(password)
        request_b64 = base64.b64encode(registration_request.to_bytes()).decode('ascii')

        init_result = space.opaque_register_init(
            username=username,
            registration_request_b64=request_b64,
            token=admin_token
        )

        response_bytes = base64.b64decode(init_result["registration_response"])
        registration_response = RegistrationResponse.from_bytes(response_bytes)
        registration_result = client.finish_registration(
            registration_response, client_reg_state, password
        )
        registration_record = registration_result.upload
        export_key = registration_result.export_key

        record_b64 = base64.b64encode(registration_record.to_bytes()).decode('ascii')
        finish_result = space.opaque_register_finish(
            username=username,
            registration_record_b64=record_b64,
            token=admin_token
        )

        # Store the OPAQUE record
        opaque_record = {
            "password_file": finish_result["password_file"],
            "encrypted_credentials": base64.b64encode(b"fake-creds").decode('ascii'),
            "public_key": admin_keypair['user_id']
        }
        record_b64_for_storage = base64.b64encode(json.dumps(opaque_record).encode()).decode()
        signed_at = int(time.time() * 1000)
        message = f"{space.space_id}|opaque/users/{username}|{record_b64_for_storage}|{signed_at}"
        signature_bytes = admin_keypair['private'].sign(message.encode('utf-8'))
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        space.data_store.set_data(
            space_id=space.space_id,
            path=f"opaque/users/{username}",
            data=record_b64_for_storage,
            signature=signature,
            signed_by=admin_keypair['user_id'],
            signed_at=signed_at
        )

        # Do valid login init
        login_client = OpaqueClient()
        credential_request, _ = login_client.start_login("test-password")
        request_b64 = base64.b64encode(credential_request.to_bytes()).decode('ascii')

        space.opaque_login_init(
            username=username,
            credential_request_b64=request_b64
        )

        # Try to finish with invalid data
        with pytest.raises(ValueError, match="Invalid credential finalization"):
            space.opaque_login_finish(
                username=username,
                credential_finalization_b64=base64.b64encode(b"not-valid-opaque-data").decode('ascii')
            )
