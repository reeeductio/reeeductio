"""
OPAQUE protocol client implementation for reeeductio.

Provides password-based key recovery using OPAQUE (Oblivious Pseudo-Random Function
+ Authenticated Key Exchange). OPAQUE enables password-based login without exposing
passwords or derived keys to the server.

Key design points:
- OPAQUE is for key recovery only, not authentication
- Ed25519 keypairs are randomly generated, not derived from passwords
- Credentials are wrapped using OPAQUE's export_key with HKDF + AES-GCM
- After OPAQUE login, the client must still authenticate via Ed25519 challenge-response
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
import httpx

from .crypto import Ed25519KeyPair, decode_base64, derive_key, encrypt_aes_gcm, decrypt_aes_gcm, encode_base64
from opaque_snake import (
    OpaqueClient,
    RegistrationRequest,
    RegistrationResponse,
    CredentialRequest,
    CredentialResponse,
    CredentialFinalization,
    ClientRegistrationState,
    ClientLoginState,
)

from .exceptions import (
    AuthenticationError,
    OpaqueError,
    OpaqueNotEnabledError,
    ValidationError,
)

# HKDF info string for credential wrapping (must match backend)
CREDENTIAL_WRAP_INFO = "reeeductio-credential-wrap"


@dataclass
class OpaqueCredentials:
    """
    Credentials recovered from OPAQUE login.

    Attributes:
        keypair: Ed25519 key pair for authentication and signing
        symmetric_root: 256-bit root key for HKDF derivation
        public_key: User's public key identifier (44-char base64)
    """
    keypair: Ed25519KeyPair
    symmetric_root: bytes
    public_key: str


def wrap_credentials(export_key: bytes, private_key: bytes, symmetric_root: bytes) -> bytes:
    """
    Wrap credentials using a key derived from OPAQUE's export_key.

    Args:
        export_key: OPAQUE export_key from registration/login
        private_key: 32-byte Ed25519 private key
        symmetric_root: 32-byte symmetric root key

    Returns:
        AES-GCM encrypted credentials (nonce + ciphertext + tag)
    """
    # Derive wrapping key from export_key
    wrap_key = derive_key(export_key, CREDENTIAL_WRAP_INFO)

    # Concatenate credentials: privateKey (32) || symmetricRoot (32) = 64 bytes
    plaintext = private_key + symmetric_root

    # Encrypt with AES-GCM
    return encrypt_aes_gcm(plaintext, wrap_key)


def unwrap_credentials(export_key: bytes, encrypted_credentials: bytes) -> tuple[bytes, bytes]:
    """
    Unwrap credentials using a key derived from OPAQUE's export_key.

    Args:
        export_key: OPAQUE export_key from login
        encrypted_credentials: AES-GCM encrypted credentials

    Returns:
        Tuple of (private_key, symmetric_root)

    Raises:
        ValueError: If decryption fails
    """
    # Derive wrapping key from export_key
    wrap_key = derive_key(export_key, CREDENTIAL_WRAP_INFO)

    # Decrypt
    plaintext = decrypt_aes_gcm(encrypted_credentials, wrap_key)

    # Split: privateKey (32) || symmetricRoot (32)
    if len(plaintext) != 64:
        raise ValueError(f"Invalid credential length: expected 64 bytes, got {len(plaintext)}")

    private_key = plaintext[:32]
    symmetric_root = plaintext[32:]

    return private_key, symmetric_root


def opaque_login(
    base_url: str,
    space_id: str,
    username: str,
    password: str,
) -> OpaqueCredentials:
    """
    Perform OPAQUE login to recover credentials from a password.

    This is a standalone function that does not require authentication.
    After OPAQUE login, use the returned credentials to authenticate
    via the standard Ed25519 challenge-response flow.

    Args:
        base_url: Base URL of the reeeductio server
        space_id: Space identifier
        username: OPAQUE username
        password: User's password

    Returns:
        OpaqueCredentials containing keypair, symmetric_root, and public_key

    Raises:
        OpaqueNotEnabledError: If OPAQUE is not enabled for this space
        OpaqueError: If OPAQUE protocol fails
        AuthenticationError: If password is incorrect

    Example:
        credentials = opaque_login(
            base_url="http://localhost:8000",
            space_id="C...",
            username="alice",
            password="secret123"
        )

        # Use recovered credentials to create a Space client
        space = Space(
            space_id=space_id,
            member_id=credentials.keypair.to_user_id(),
            private_key=credentials.keypair.private_key,
            symmetric_root=credentials.symmetric_root,
            base_url=base_url,
        )
    """

    with httpx.Client(base_url=base_url) as client:
        # Step 1: Create client-side OPAQUE state and credential request
        opaque_client = OpaqueClient()
        credential_request, client_login_state = opaque_client.start_login(password)

        # Step 2: Send credential request to server
        try:
            response = client.post(
                f"/spaces/{space_id}/opaque/login/init",
                json={
                    "username": username,
                    "credential_request": base64.b64encode(credential_request.to_bytes()).decode("ascii"),
                },
            )
            response.raise_for_status()
            init_data = response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 501:
                raise OpaqueNotEnabledError(f"OPAQUE is not enabled for space {space_id}") from e
            elif e.response.status_code == 401:
                raise AuthenticationError(f"User '{username}' not found") from e
            elif e.response.status_code == 429:
                raise OpaqueError(f"Too many login attempts: {e.response.text}") from e
            raise OpaqueError(f"OPAQUE login/init failed: {e.response.text}") from e

        # Step 3: Process server response to get export_key and finalization
        try:
            credential_response_bytes = base64.b64decode(init_data["credential_response"])
            credential_response = CredentialResponse.from_bytes(credential_response_bytes)
        except Exception as e:
            raise OpaqueError(f"Invalid credential response: {e}") from e

        try:
            login_result = opaque_client.finish_login(
                credential_response, client_login_state, password
            )
            credential_finalization = login_result.finalization
            export_key = login_result.session_keys.export_key
        except Exception as e:
            raise AuthenticationError(f"OPAQUE authentication failed: {e}") from e

        # Step 4: Send finalization to server and get encrypted credentials
        try:
            response = client.post(
                f"/spaces/{space_id}/opaque/login/finish",
                json={
                    "username": username,
                    "credential_finalization": base64.b64encode(credential_finalization.to_bytes()).decode("ascii"),
                },
            )
            response.raise_for_status()
            finish_data = response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise AuthenticationError("OPAQUE authentication failed: invalid password") from e
            elif e.response.status_code == 404:
                raise OpaqueError(f"Login session expired: {e.response.text}") from e
            elif e.response.status_code == 429:
                raise OpaqueError(f"Too many failed attempts: {e.response.text}") from e
            raise OpaqueError(f"OPAQUE login/finish failed: {e.response.text}") from e

        # Step 5: Unwrap credentials using export_key
        encrypted_credentials = base64.b64decode(finish_data["encrypted_credentials"])
        public_key = finish_data["public_key"]

        try:
            private_key, symmetric_root = unwrap_credentials(export_key, encrypted_credentials)
        except Exception as e:
            raise OpaqueError(f"Failed to unwrap credentials: {e}") from e

        # Extract raw public key from typed identifier for keypair
        from .crypto import Ed25519KeyPair
        raw_public_key = Ed25519KeyPair.from_typed_public_key(public_key)

        return OpaqueCredentials(
            keypair=Ed25519KeyPair(private_key=private_key, public_key=raw_public_key),
            symmetric_root=symmetric_root,
            public_key=public_key,
        )


async def opaque_login_async(
    base_url: str,
    space_id: str,
    username: str,
    password: str,
) -> OpaqueCredentials:
    """
    Async version of opaque_login.

    See opaque_login for full documentation.
    """

    async with httpx.AsyncClient(base_url=base_url) as client:
        # Step 1: Create client-side OPAQUE state and credential request
        opaque_client = OpaqueClient()
        credential_request, client_login_state = opaque_client.start_login(password)

        # Step 2: Send credential request to server
        try:
            response = await client.post(
                f"/spaces/{space_id}/opaque/login/init",
                json={
                    "username": username,
                    "credential_request": base64.b64encode(credential_request.to_bytes()).decode("ascii"),
                },
            )
            response.raise_for_status()
            init_data = response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 501:
                raise OpaqueNotEnabledError(f"OPAQUE is not enabled for space {space_id}") from e
            elif e.response.status_code == 401:
                raise AuthenticationError(f"User '{username}' not found") from e
            elif e.response.status_code == 429:
                raise OpaqueError(f"Too many login attempts: {e.response.text}") from e
            raise OpaqueError(f"OPAQUE login/init failed: {e.response.text}") from e

        # Step 3: Process server response
        try:
            credential_response_bytes = base64.b64decode(init_data["credential_response"])
            credential_response = CredentialResponse.from_bytes(credential_response_bytes)
        except Exception as e:
            raise OpaqueError(f"Invalid credential response: {e}") from e

        try:
            login_result = opaque_client.finish_login(
                credential_response, client_login_state, password
            )
            credential_finalization = login_result.finalization
            export_key = login_result.session_keys.export_key
        except Exception as e:
            raise AuthenticationError(f"OPAQUE authentication failed: {e}") from e

        # Step 4: Send finalization
        try:
            response = await client.post(
                f"/spaces/{space_id}/opaque/login/finish",
                json={
                    "username": username,
                    "credential_finalization": base64.b64encode(credential_finalization.to_bytes()).decode("ascii"),
                },
            )
            response.raise_for_status()
            finish_data = response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise AuthenticationError("OPAQUE authentication failed: invalid password") from e
            elif e.response.status_code == 404:
                raise OpaqueError(f"Login session expired: {e.response.text}") from e
            elif e.response.status_code == 429:
                raise OpaqueError(f"Too many failed attempts: {e.response.text}") from e
            raise OpaqueError(f"OPAQUE login/finish failed: {e.response.text}") from e

        # Step 5: Unwrap credentials
        encrypted_credentials = base64.b64decode(finish_data["encrypted_credentials"])
        public_key = finish_data["public_key"]

        try:
            private_key, symmetric_root = unwrap_credentials(export_key, encrypted_credentials)
        except Exception as e:
            raise OpaqueError(f"Failed to unwrap credentials: {e}") from e

        from .crypto import Ed25519KeyPair
        raw_public_key = Ed25519KeyPair.from_typed_public_key(public_key)

        return OpaqueCredentials(
            keypair=Ed25519KeyPair(private_key=private_key, public_key=raw_public_key),
            symmetric_root=symmetric_root,
            public_key=public_key,
        )


def opaque_register(
    client: httpx.Client,
    space_id: str,
    username: str,
    password: str,
    user_id: str,
    private_key: bytes,
    symmetric_root: bytes,
) -> str:
    """
    Register OPAQUE credentials for password-based login.

    This function requires authentication - the caller must have a valid JWT token
    in the provided httpx.Client. Typically called from Space.opaque_register().

    The registration flow:
    1. Verify user_id encodes the correct public key for the private_key
    2. Send registration request to server
    3. Process server response to get export_key and registration record
    4. Server returns password_file
    5. Wrap credentials with export_key
    6. Store complete record via /data API

    Args:
        client: Authenticated httpx.Client
        space_id: Space identifier
        username: OPAQUE username to register
        password: Password for future logins
        user_id: Typed identifier string (USER or TOOL) for the public key
        private_key: 32-byte Ed25519 private key matching user_id
        symmetric_root: Symmetric root key to wrap

    Returns:
        The username that was registered

    Raises:
        OpaqueNotEnabledError: If OPAQUE is not enabled for this space
        OpaqueError: If registration fails
        ValidationError: If username already exists or user_id doesn't match private_key
    """

    # Verify user_id matches private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    try:
        expected_public_key = Ed25519KeyPair.from_typed_public_key(user_id)
    except ValueError as e:
        raise ValidationError(f"Invalid user_id: {e}") from e

    try:
        private_key_obj = Ed25519PrivateKey.from_private_bytes(private_key)
        derived_public_key = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except Exception as e:
        raise ValidationError(f"Invalid private_key: {e}") from e

    if derived_public_key != expected_public_key:
        raise ValidationError("user_id does not match the provided private_key")

    # Step 1: Create client-side registration request
    opaque_client = OpaqueClient()
    registration_request, client_reg_state = opaque_client.start_registration(password)

    # Step 2: Send registration request to server
    try:
        response = client.post(
            f"/spaces/{space_id}/opaque/register/init",
            json={
                "username": username,
                "registration_request": base64.b64encode(registration_request.to_bytes()).decode("ascii"),
            },
        )
        response.raise_for_status()
        init_data = response.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 501:
            raise OpaqueNotEnabledError(f"OPAQUE is not enabled for space {space_id}") from e
        elif e.response.status_code == 409:
            raise ValidationError(f"Username '{username}' is already registered") from e
        elif e.response.status_code == 401:
            raise AuthenticationError(f"Authentication required for OPAQUE registration") from e
        raise OpaqueError(f"OPAQUE register/init failed: {e.response.text}") from e

    # Step 3: Process server response
    try:
        registration_response_bytes = base64.b64decode(init_data["registration_response"])
        registration_response = RegistrationResponse.from_bytes(registration_response_bytes)
    except Exception as e:
        raise OpaqueError(f"Invalid registration response: {e}") from e

    # Step 4: Finish client-side registration to get export_key and registration record
    try:
        reg_result = opaque_client.finish_registration(
            registration_response, client_reg_state, password
        )
        registration_record = reg_result.upload
        export_key = reg_result.export_key
    except Exception as e:
        raise OpaqueError(f"Failed to complete registration: {e}") from e

    # Step 5: Send registration record to server to get password_file
    try:
        response = client.post(
            f"/spaces/{space_id}/opaque/register/finish",
            json={
                "username": username,
                "registration_record": base64.b64encode(registration_record.to_bytes()).decode("ascii"),
            },
        )
        response.raise_for_status()
        finish_data = response.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            raise AuthenticationError(f"Authentication failed or session mismatch") from e
        elif e.response.status_code == 404:
            raise OpaqueError(f"Registration session expired") from e
        elif e.response.status_code == 409:
            raise ValidationError(f"Username '{username}' is already registered") from e
        raise OpaqueError(f"OPAQUE register/finish failed: {e.response.text}") from e

    password_file = finish_data["password_file"]

    # Step 7: Wrap credentials with export_key
    encrypted_credentials = wrap_credentials(export_key, private_key, symmetric_root)
    encrypted_credentials_b64 = base64.b64encode(encrypted_credentials).decode("ascii")

    # Step 8: Assemble complete OPAQUE record
    opaque_record = {
        "password_file": password_file,
        "encrypted_credentials": encrypted_credentials_b64,
        "public_key": user_id,
    }

    # Step 9: Store via /data API
    from . import kvdata

    kvdata.set_data(
        client=client,
        space_id=space_id,
        path=f"opaque/users/{username}",
        data=json.dumps(opaque_record).encode("utf-8"),
        signed_by=user_id,
        private_key=private_key,
    )

    return username


async def opaque_register_async(
    client: httpx.AsyncClient,
    space_id: str,
    username: str,
    password: str,
    user_id: str,
    private_key: bytes,
    symmetric_root: bytes,
) -> str:
    """
    Async version of opaque_register.

    See opaque_register for full documentation.
    """

    # Verify user_id matches private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    try:
        expected_public_key = Ed25519KeyPair.from_typed_public_key(user_id)
    except ValueError as e:
        raise ValidationError(f"Invalid user_id: {e}") from e

    try:
        private_key_obj = Ed25519PrivateKey.from_private_bytes(private_key)
        derived_public_key = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except Exception as e:
        raise ValidationError(f"Invalid private_key: {e}") from e

    if derived_public_key != expected_public_key:
        raise ValidationError("user_id does not match the provided private_key")

    # Step 1: Create client-side registration request
    opaque_client = OpaqueClient()
    registration_request, client_reg_state = opaque_client.start_registration(password)

    # Step 2: Send registration request to server
    try:
        response = await client.post(
            f"/spaces/{space_id}/opaque/register/init",
            json={
                "username": username,
                "registration_request": base64.b64encode(registration_request.to_bytes()).decode("ascii"),
            },
        )
        response.raise_for_status()
        init_data = response.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 501:
            raise OpaqueNotEnabledError(f"OPAQUE is not enabled for space {space_id}") from e
        elif e.response.status_code == 409:
            raise ValidationError(f"Username '{username}' is already registered") from e
        elif e.response.status_code == 401:
            raise AuthenticationError(f"Authentication required for OPAQUE registration") from e
        raise OpaqueError(f"OPAQUE register/init failed: {e.response.text}") from e

    # Step 3: Process server response
    try:
        registration_response_bytes = base64.b64decode(init_data["registration_response"])
        registration_response = RegistrationResponse.from_bytes(registration_response_bytes)
    except Exception as e:
        raise OpaqueError(f"Invalid registration response: {e}") from e

    # Step 4: Finish client-side registration
    try:
        reg_result = opaque_client.finish_registration(
            registration_response, client_reg_state, password
        )
        registration_record = reg_result.upload
        export_key = reg_result.export_key
    except Exception as e:
        raise OpaqueError(f"Failed to complete registration: {e}") from e

    # Step 5: Send registration record to server
    try:
        response = await client.post(
            f"/spaces/{space_id}/opaque/register/finish",
            json={
                "username": username,
                "registration_record": base64.b64encode(registration_record.to_bytes()).decode("ascii"),
            },
        )
        response.raise_for_status()
        finish_data = response.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            raise AuthenticationError(f"Authentication failed or session mismatch") from e
        elif e.response.status_code == 404:
            raise OpaqueError(f"Registration session expired") from e
        elif e.response.status_code == 409:
            raise ValidationError(f"Username '{username}' is already registered") from e
        raise OpaqueError(f"OPAQUE register/finish failed: {e.response.text}") from e

    password_file = finish_data["password_file"]

    # Step 7: Wrap credentials
    encrypted_credentials = wrap_credentials(export_key, private_key, symmetric_root)
    encrypted_credentials_b64 = base64.b64encode(encrypted_credentials).decode("ascii")

    # Step 8: Assemble record
    opaque_record = {
        "password_file": password_file,
        "encrypted_credentials": encrypted_credentials_b64,
        "public_key": user_id,
    }

    # Step 9: Store via /data API
    from . import kvdata

    await kvdata.set_data_async(
        client=client,
        space_id=space_id,
        path=f"opaque/users/{username}",
        data=json.dumps(opaque_record).encode("utf-8"),
        signed_by=user_id,
        private_key=private_key,
    )

    return username


# Constants for OPAQUE setup
OPAQUE_SERVER_SETUP_PATH = "opaque/server/setup"
OPAQUE_USER_ROLE_ID = "opaque-user"
OPAQUE_USER_CAP_ID = "cap_create_opaque_user"
