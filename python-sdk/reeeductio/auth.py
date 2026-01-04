"""
Authentication helpers for reeeductio spaces.

Handles the challenge-response authentication flow.
"""

from typing import Optional
from datetime import datetime, timezone

from reeeductio_client import Client
from reeeductio_client.api.authentication import (
    post_spaces_space_id_auth_challenge,
    post_spaces_space_id_auth_verify,
    post_spaces_space_id_auth_refresh,
)
from reeeductio_client.models import (
    PostSpacesSpaceIdAuthChallengeBody,
    PostSpacesSpaceIdAuthVerifyBody,
)

from .crypto import sign_data, decode_base64


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class AuthSession:
    """
    Manages authentication session for a space.

    Handles challenge-response flow and token refresh.
    """

    def __init__(
        self,
        space_id: str,
        public_key_typed: str,
        private_key: bytes,
        base_url: str = "http://localhost:8000",
    ):
        """
        Initialize authentication session.

        Args:
            space_id: Typed space identifier (44-char base64)
            public_key_typed: Typed public key identifier (44-char base64)
            private_key: Raw 32-byte Ed25519 private key
            base_url: Base URL of the reeeductio server
        """
        self.space_id = space_id
        self.public_key_typed = public_key_typed
        self.private_key = private_key
        self.base_url = base_url

        self._token: Optional[str] = None
        self._token_expires_at: Optional[int] = None

    @property
    def token(self) -> Optional[str]:
        """Get current JWT token."""
        return self._token

    @property
    def is_authenticated(self) -> bool:
        """Check if session has a valid token."""
        if not self._token:
            return False

        if self._token_expires_at:
            # Check if token is expired (with 60s buffer)
            now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
            return now_ms < (self._token_expires_at - 60_000)

        return True

    def authenticate(self) -> str:
        """
        Perform challenge-response authentication.

        Returns:
            JWT bearer token

        Raises:
            AuthenticationError: If authentication fails
        """
        client = Client(base_url=self.base_url)

        # Step 1: Request challenge
        challenge_body = PostSpacesSpaceIdAuthChallengeBody(
            public_key=self.public_key_typed
        )

        challenge_response = post_spaces_space_id_auth_challenge.sync(
            client=client,
            space_id=self.space_id,
            body=challenge_body,
        )

        if not challenge_response:
            raise AuthenticationError("Failed to get authentication challenge")

        # Step 2: Sign the challenge
        challenge_bytes = decode_base64(challenge_response.challenge)
        signature = sign_data(challenge_bytes, self.private_key)

        # Step 3: Verify signature and get token
        verify_body = PostSpacesSpaceIdAuthVerifyBody(
            public_key=self.public_key_typed,
            signature=signature.hex() if isinstance(signature, bytes) else signature,
            challenge=challenge_response.challenge,
        )

        verify_response = post_spaces_space_id_auth_verify.sync(
            client=client,
            space_id=self.space_id,
            body=verify_body,
        )

        if not verify_response:
            raise AuthenticationError("Authentication verification failed")

        # Store token and expiration
        self._token = verify_response.token
        self._token_expires_at = verify_response.expires_at

        return self._token

    def refresh_token(self) -> str:
        """
        Refresh the current JWT token.

        Returns:
            New JWT bearer token

        Raises:
            AuthenticationError: If refresh fails or no token exists
        """
        if not self._token:
            raise AuthenticationError("No token to refresh. Call authenticate() first.")

        from reeeductio_client import AuthenticatedClient

        client = AuthenticatedClient(
            base_url=self.base_url,
            token=self._token,
        )

        refresh_response = post_spaces_space_id_auth_refresh.sync(
            client=client,
            space_id=self.space_id,
        )

        if not refresh_response:
            raise AuthenticationError("Token refresh failed")

        # Update token and expiration
        self._token = refresh_response.token
        self._token_expires_at = refresh_response.expires_at

        return self._token

    def ensure_authenticated(self) -> str:
        """
        Ensure session has a valid token, refreshing or re-authenticating if needed.

        Returns:
            Valid JWT bearer token

        Raises:
            AuthenticationError: If authentication fails
        """
        if self.is_authenticated:
            return self._token

        # Try to refresh if we have a token
        if self._token:
            try:
                return self.refresh_token()
            except AuthenticationError:
                # Fall through to re-authenticate
                pass

        # Full re-authentication
        return self.authenticate()
