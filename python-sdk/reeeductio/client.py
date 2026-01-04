"""
High-level Space client for reeeductio.

Provides convenient methods for interacting with spaces, handling
authentication, messages, state, and blobs.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from reeeductio_client import AuthenticatedClient
from reeeductio_client.api.state import (
    get_spaces_space_id_state_path,
    put_spaces_space_id_state_path,
    delete_spaces_space_id_state_path,
)
from reeeductio_client.api.messages import (
    get_spaces_space_id_topics_topic_id_messages,
    post_spaces_space_id_topics_topic_id_messages,
    get_spaces_space_id_topics_topic_id_messages_message_hash,
)
from reeeductio_client.api.blobs import (
    get_spaces_space_id_blobs_blob_id,
    put_spaces_space_id_blobs_blob_id,
    delete_spaces_space_id_blobs_blob_id,
)
from reeeductio_client.models import (
    StateEntry,
    Message,
    PutSpacesSpaceIdStatePathBody,
    DeleteSpacesSpaceIdStatePathBody,
)

from .auth import AuthSession
from .crypto import Ed25519KeyPair, sign_data, encode_base64, decode_base64


class Space:
    """
    High-level client for interacting with a reeeductio space.

    Handles authentication, state management, messaging, and blob storage.
    """

    def __init__(
        self,
        space_id: str,
        keypair: Ed25519KeyPair,
        base_url: str = "http://localhost:8000",
        auto_authenticate: bool = True,
    ):
        """
        Initialize Space client.

        Args:
            space_id: Typed space identifier (44-char base64)
            keypair: Ed25519 key pair for authentication and signing
            base_url: Base URL of the reeeductio server
            auto_authenticate: Whether to authenticate automatically on first request
        """
        self.space_id = space_id
        self.keypair = keypair
        self.base_url = base_url
        self._auto_authenticate = auto_authenticate

        # Create authentication session
        self.auth = AuthSession(
            space_id=space_id,
            public_key_typed=keypair.to_typed_public_key(),
            private_key=keypair.private_key,
            base_url=base_url,
        )

        self._client: Optional[AuthenticatedClient] = None

    @property
    def client(self) -> AuthenticatedClient:
        """
        Get authenticated client, ensuring valid authentication.

        Returns:
            Authenticated HTTP client

        Raises:
            AuthenticationError: If authentication fails
        """
        if self._auto_authenticate:
            token = self.auth.ensure_authenticated()
        elif self.auth.token:
            token = self.auth.token
        else:
            raise ValueError(
                "Not authenticated. Call authenticate() or set auto_authenticate=True"
            )

        # Create or update client with current token
        if not self._client or self._client.token != token:
            self._client = AuthenticatedClient(
                base_url=self.base_url,
                token=token,
            )

        return self._client

    def authenticate(self) -> str:
        """
        Perform authentication.

        Returns:
            JWT bearer token
        """
        return self.auth.authenticate()

    # ============================================================
    # State Management
    # ============================================================

    def get_state(self, path: str) -> Optional[StateEntry]:
        """
        Get state value at path.

        Args:
            path: State path (e.g., "profiles/alice")

        Returns:
            StateEntry if found, None otherwise
        """
        return get_spaces_space_id_state_path.sync(
            client=self.client,
            space_id=self.space_id,
            path=path,
        )

    def set_state(self, path: str, data: bytes) -> bool:
        """
        Set state value at path.

        Args:
            path: State path (e.g., "profiles/alice")
            data: Data to store (will be base64-encoded)

        Returns:
            True if successful
        """
        # Sign the state entry
        signed_at = int(datetime.now(timezone.utc).timestamp() * 1000)

        # Signature is over: space_id|path|data|signed_at
        sig_data = f"{self.space_id}|{path}|{encode_base64(data)}|{signed_at}".encode('utf-8')
        signature = sign_data(sig_data, self.keypair.private_key)

        body = PutSpacesSpaceIdStatePathBody(
            data=encode_base64(data),
            signature=encode_base64(signature),
            signed_by=self.keypair.to_typed_public_key(),
            signed_at=signed_at,
        )

        response = put_spaces_space_id_state_path.sync(
            client=self.client,
            space_id=self.space_id,
            path=path,
            body=body,
        )

        return response is not None

    def delete_state(self, path: str) -> bool:
        """
        Delete state value at path.

        Args:
            path: State path (e.g., "profiles/alice")

        Returns:
            True if successful
        """
        signed_at = int(datetime.now(timezone.utc).timestamp() * 1000)

        # Signature is over: path|DELETE|signed_at
        sig_data = f"{path}|DELETE|{signed_at}".encode('utf-8')
        signature = sign_data(sig_data, self.keypair.private_key)

        body = DeleteSpacesSpaceIdStatePathBody(
            signature=encode_base64(signature),
            signed_by=self.keypair.to_typed_public_key(),
            signed_at=signed_at,
        )

        # DELETE returns 204 on success, so we check for no error
        try:
            delete_spaces_space_id_state_path.sync(
                client=self.client,
                space_id=self.space_id,
                path=path,
                body=body,
            )
            return True
        except Exception:
            return False

    # ============================================================
    # Message Management
    # ============================================================

    def get_messages(
        self,
        topic_id: str,
        from_timestamp: Optional[int] = None,
        to_timestamp: Optional[int] = None,
        limit: int = 100,
    ) -> List[Message]:
        """
        Get messages from a topic.

        Args:
            topic_id: Topic identifier
            from_timestamp: Optional start timestamp (milliseconds)
            to_timestamp: Optional end timestamp (milliseconds)
            limit: Maximum number of messages to return

        Returns:
            List of messages
        """
        response = get_spaces_space_id_topics_topic_id_messages.sync(
            client=self.client,
            space_id=self.space_id,
            topic_id=topic_id,
            from_=from_timestamp,
            to=to_timestamp,
            limit=limit,
        )

        return response.messages if response else []

    def get_message(self, topic_id: str, message_hash: str) -> Optional[Message]:
        """
        Get a specific message by hash.

        Args:
            topic_id: Topic identifier
            message_hash: Typed message identifier (44-char base64)

        Returns:
            Message if found, None otherwise
        """
        return get_spaces_space_id_topics_topic_id_messages_message_hash.sync(
            client=self.client,
            space_id=self.space_id,
            topic_id=topic_id,
            message_hash=message_hash,
        )

    # Note: Message posting with encryption is handled in messages.py helper

    # ============================================================
    # Blob Management
    # ============================================================

    def upload_blob(self, blob_id: str, data: bytes) -> bool:
        """
        Upload encrypted blob.

        Args:
            blob_id: Typed blob identifier (SHA256 hash with header)
            data: Encrypted blob data

        Returns:
            True if successful
        """
        response = put_spaces_space_id_blobs_blob_id.sync(
            client=self.client,
            space_id=self.space_id,
            blob_id=blob_id,
            body=data,
        )

        return response is not None

    def download_blob(self, blob_id: str) -> Optional[bytes]:
        """
        Download encrypted blob.

        Args:
            blob_id: Typed blob identifier

        Returns:
            Encrypted blob data if found, None otherwise
        """
        return get_spaces_space_id_blobs_blob_id.sync(
            client=self.client,
            space_id=self.space_id,
            blob_id=blob_id,
        )

    def delete_blob(self, blob_id: str) -> bool:
        """
        Delete blob.

        Args:
            blob_id: Typed blob identifier

        Returns:
            True if successful
        """
        try:
            delete_spaces_space_id_blobs_blob_id.sync(
                client=self.client,
                space_id=self.space_id,
                blob_id=blob_id,
            )
            return True
        except Exception:
            return False

    # ============================================================
    # Convenience Methods
    # ============================================================

    def get_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user profile from state.

        Args:
            user_id: Typed user identifier

        Returns:
            Decoded profile data if found, None otherwise
        """
        import json

        state = self.get_state(f"profiles/{user_id}")
        if not state:
            return None

        try:
            data = decode_base64(state.data)
            return json.loads(data)
        except Exception:
            return None

    def set_profile(self, user_id: str, profile: Dict[str, Any]) -> bool:
        """
        Set user profile in state.

        Args:
            user_id: Typed user identifier
            profile: Profile data (will be JSON-encoded)

        Returns:
            True if successful
        """
        import json

        data = json.dumps(profile).encode('utf-8')
        return self.set_state(f"profiles/{user_id}", data)
