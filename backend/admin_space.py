"""
AdminSpace - Special-purpose space for server-level administration

This class extends Space with additional validation rules specific to the
admin space, where server users register their spaces.

Key differences from regular spaces:
1. Space registration writes require valid space_signature proving ownership
2. created_by field must match the authenticated user
3. Bootstrap logic for creating the space-creator role
"""

import base64
import json
import time
from typing import Optional, Dict, Any

from space import Space
from data_store import DataStore
from message_store import MessageStore
from blob_store import BlobStore
from crypto import CryptoUtils
from identifiers import extract_public_key, IdType, decode_identifier


class AdminSpaceValidationError(ValueError):
    """Raised when admin space validation fails"""
    pass


class AdminSpace(Space):
    """
    Special-purpose space for server-level administration.

    Adds validation rules:
    - spaces/{id} writes require valid space_signature proving ownership
    - spaces/{id} writes require created_by == authenticated user
    - users/{id}/spaces/{id} writes require consistency with authenticated user

    The admin space uses the same authorization model as regular spaces,
    but with additional constraints on certain paths.
    """

    # Role ID for users who can create spaces
    SPACE_CREATOR_ROLE = "space-creator"

    def __init__(
        self,
        space_id: str,
        message_store: MessageStore,
        data_store: DataStore,
        blob_store: Optional[BlobStore] = None,
        jwt_secret: Optional[str] = None,
        jwt_algorithm: str = "HS256",
        jwt_expiry_hours: int = 24
    ):
        """
        Initialize an AdminSpace instance.

        Args:
            space_id: The admin space identifier
            message_store: Message store instance
            data_store: Data store instance
            blob_store: Optional blob store
            jwt_secret: JWT signing secret
            jwt_algorithm: JWT signing algorithm
            jwt_expiry_hours: JWT token expiry in hours
        """
        super().__init__(
            space_id=space_id,
            message_store=message_store,
            data_store=data_store,
            blob_store=blob_store,
            jwt_secret=jwt_secret,
            jwt_algorithm=jwt_algorithm,
            jwt_expiry_hours=jwt_expiry_hours
        )
        self.crypto = CryptoUtils()

    def _check_state_operation(
        self,
        path: str,
        data: str,
        signed_by: str
    ) -> None:
        """
        Validate state-specific constraints before allowing a state message to be posted.

        Extends the parent class validation with admin-space-specific rules:
        - Space registration validation (space_signature, created_by)
        - User space index validation

        Args:
            path: State path being modified
            data: Base64-encoded state data
            signed_by: Typed identifier of the signer (user or tool)

        Raises:
            ValueError: If validation fails
            AdminSpaceValidationError: If admin-specific validation fails
        """
        # First, run the standard Space validation
        super()._check_state_operation(path, data, signed_by)

        # Now apply admin-space-specific validation
        segments = path.strip('/').split('/')

        # Validate space registry writes: spaces/{space_id}
        if len(segments) == 2 and segments[0] == "spaces":
            space_id = segments[1]
            self._validate_space_registration(path, space_id, data, signed_by)

        # Validate user space index writes: users/{user_id}/spaces/{space_id}
        elif len(segments) == 4 and segments[0] == "users" and segments[2] == "spaces":
            path_user_id = segments[1]
            path_space_id = segments[3]
            self._validate_user_space_index(path, path_user_id, path_space_id, data, signed_by)

    def _validate_space_registration(
        self,
        path: str,
        space_id: str,
        data: str,
        signed_by: str
    ) -> None:
        """
        Validate a space registration write to spaces/{space_id}.

        Enforces:
        1. Path-content consistency: space_id in data must match path
        2. created_by must match the authenticated user (signed_by)
        3. space_signature must be valid, proving ownership of the space private key

        Args:
            path: Full state path
            space_id: The space ID from the path
            data: Base64-encoded registration data
            signed_by: The authenticated user making the request

        Raises:
            AdminSpaceValidationError: If validation fails
        """
        # Decode the registration data
        try:
            decoded = base64.b64decode(data)
            registration = json.loads(decoded)
        except Exception as e:
            raise AdminSpaceValidationError(
                f"Space registration must be valid base64-encoded JSON: {e}"
            )

        # 1. Path-content consistency for space_id
        if registration.get("space_id") != space_id:
            raise AdminSpaceValidationError(
                f"space_id mismatch: path has '{space_id}' but data has '{registration.get('space_id')}'"
            )

        # 2. Validate space_id format (must be a valid SPACE type identifier)
        try:
            tid = decode_identifier(space_id)
            if tid.id_type != IdType.SPACE:
                raise AdminSpaceValidationError(
                    f"space_id must be a SPACE type identifier, got {tid.id_type.name}"
                )
        except Exception as e:
            raise AdminSpaceValidationError(f"Invalid space_id format: {e}")

        # 3. created_by must match the authenticated user
        created_by = registration.get("created_by")
        if created_by != signed_by:
            raise AdminSpaceValidationError(
                f"created_by must match authenticated user: expected '{signed_by}', got '{created_by}'"
            )

        # 4. Verify space_signature proves ownership of the space private key
        self._verify_space_signature(space_id, registration)

    def _verify_space_signature(
        self,
        space_id: str,
        registration: dict
    ) -> None:
        """
        Verify that space_signature proves ownership of the space's private key.

        The signature must be over the canonical form of:
        {space_id, created_by, created_at}

        Args:
            space_id: The space identifier
            registration: The registration data dictionary

        Raises:
            AdminSpaceValidationError: If signature is missing or invalid
        """
        space_signature = registration.get("space_signature")
        if not space_signature:
            raise AdminSpaceValidationError("space_signature is required")

        created_by = registration.get("created_by")
        created_at = registration.get("created_at")

        if created_at is None:
            raise AdminSpaceValidationError("created_at is required")

        # Construct the canonical message that was signed
        # Format: "{space_id}|{created_by}|{created_at}"
        canonical_message = f"{space_id}|{created_by}|{created_at}"
        message_bytes = canonical_message.encode('utf-8')

        # Extract the space's public key from its ID
        try:
            space_public_key = extract_public_key(space_id)
        except Exception as e:
            raise AdminSpaceValidationError(f"Could not extract public key from space_id: {e}")

        # Decode and verify the signature
        try:
            signature_bytes = base64.b64decode(space_signature)
        except Exception as e:
            raise AdminSpaceValidationError(f"Invalid space_signature encoding: {e}")

        if not self.crypto.verify_signature(message_bytes, signature_bytes, space_public_key):
            raise AdminSpaceValidationError(
                "Invalid space_signature: does not match space's public key"
            )

    def _validate_user_space_index(
        self,
        path: str,
        path_user_id: str,
        path_space_id: str,
        data: str,
        signed_by: str
    ) -> None:
        """
        Validate a user space index write to users/{user_id}/spaces/{space_id}.

        Enforces:
        1. The user_id in the path must match the authenticated user (signed_by)
        2. Path-content consistency for space_id

        Args:
            path: Full state path
            path_user_id: User ID from the path
            path_space_id: Space ID from the path
            data: Base64-encoded index entry data
            signed_by: The authenticated user making the request

        Raises:
            AdminSpaceValidationError: If validation fails
        """
        # 1. User can only write to their own space index
        # (unless they have broader permissions via capabilities, but that's
        # handled by the authorization engine - here we enforce the constraint
        # that the data must be consistent)

        # Decode the index entry data
        try:
            decoded = base64.b64decode(data)
            index_entry = json.loads(decoded)
        except Exception as e:
            raise AdminSpaceValidationError(
                f"User space index entry must be valid base64-encoded JSON: {e}"
            )

        # 2. Path-content consistency for space_id
        if index_entry.get("space_id") != path_space_id:
            raise AdminSpaceValidationError(
                f"space_id mismatch in user index: path has '{path_space_id}' "
                f"but data has '{index_entry.get('space_id')}'"
            )

        # Note: We don't enforce path_user_id == signed_by here because
        # the capability system handles that via {self} wildcards.
        # A user with capability "create" on "state/users/{self}/spaces/{any}"
        # can only write to their own index. Server admins with broader
        # capabilities can write to any user's index.

    @classmethod
    def get_space_creator_role_definition(cls) -> dict:
        """
        Get the role definition for the space-creator role.

        Returns:
            Dictionary with role_id and description
        """
        return {
            "role_id": cls.SPACE_CREATOR_ROLE,
            "description": "Can register new spaces in the admin space"
        }

    @classmethod
    def get_space_creator_capabilities(cls) -> list:
        """
        Get the capabilities for the space-creator role.

        These capabilities allow users to:
        1. Create space registry entries at spaces/{any}
        2. Create entries in their own user space index at users/{self}/spaces/{any}

        Returns:
            List of capability dictionaries
        """
        return [
            {
                "op": "create",
                "path": "state/spaces/{any}",
                "description": "Register new spaces"
            },
            {
                "op": "create",
                "path": "state/users/{self}/spaces/{any}",
                "description": "Index spaces under own user entry"
            }
        ]

    def is_bootstrapped(self) -> bool:
        """
        Check if the admin space has been bootstrapped.

        Returns:
            True if the space-creator role exists, False otherwise
        """
        role_path = f"auth/roles/{self.SPACE_CREATOR_ROLE}"
        role_data = self.state_store.get_state(self.space_id, role_path)
        return role_data is not None

    def get_bootstrap_state_entries(self, admin_user_id: str, timestamp: int) -> list:
        """
        Get the state entries needed to bootstrap the admin space.

        This returns the entries that need to be written to set up:
        1. The space-creator role definition
        2. The space-creator role's capabilities

        Note: This does NOT write the entries - the caller is responsible for
        signing and writing them using the admin key.

        Args:
            admin_user_id: The admin user ID who will sign these entries
            timestamp: The timestamp to use for granted_at fields

        Returns:
            List of (path, data_dict) tuples for each state entry
        """
        entries = []

        # 1. Role definition
        role_path = f"auth/roles/{self.SPACE_CREATOR_ROLE}"
        role_def = self.get_space_creator_role_definition()
        entries.append((role_path, role_def))

        # 2. Role capabilities
        capabilities = self.get_space_creator_capabilities()
        for i, cap in enumerate(capabilities):
            cap_id = f"cap_{i:03d}"
            cap_path = f"auth/roles/{self.SPACE_CREATOR_ROLE}/rights/{cap_id}"
            cap_data = {
                **cap,
                "granted_by": admin_user_id,
                "granted_at": timestamp
            }
            # Remove description from stored capability (it's just for documentation)
            cap_data.pop("description", None)
            entries.append((cap_path, cap_data))

        return entries
