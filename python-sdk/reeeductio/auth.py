"""
Authentication helpers for reeeductio spaces.

Handles the challenge-response authentication flow using httpx.
"""

import asyncio
import threading
from datetime import datetime, timezone

import httpx

from .crypto import encode_base64, sign_data
from .exceptions import AuthenticationError
from .models import AuthChallenge, AuthToken


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

        self._token: str | None = None
        self._token_expires_at: int | None = None

        # Serializes challenge/verify and refresh flows across threads.
        self._lock = threading.Lock()

    @property
    def token(self) -> str | None:
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

        Concurrent callers are serialized so they cannot invalidate each
        other's challenge.

        Returns:
            JWT bearer token

        Raises:
            AuthenticationError: If authentication fails
        """
        with self._lock:
            return self._authenticate_locked()

    def _authenticate_locked(self) -> str:
        """Run the challenge/verify handshake. Caller must hold ``_lock``."""
        with httpx.Client(base_url=self.base_url) as client:
            # Step 1: Request challenge
            try:
                response = client.post(
                    f"/spaces/{self.space_id}/auth/challenge",
                    json={"public_key": self.public_key_typed},
                )
                response.raise_for_status()
                challenge_data = response.json()
                challenge = AuthChallenge(
                    challenge=challenge_data["challenge"],
                    expires_at=challenge_data["expires_at"],
                )
            except httpx.HTTPStatusError as e:
                raise AuthenticationError(f"Failed to get challenge: {e.response.text}") from e
            except Exception as e:
                raise AuthenticationError(f"Failed to get challenge: {e}") from e

            # Step 2: Sign the challenge string (UTF-8 encoded, not base64-decoded)
            challenge_bytes = challenge.challenge.encode("utf-8")
            signature = sign_data(challenge_bytes, self.private_key)

            # Step 3: Verify signature and get token
            try:
                response = client.post(
                    f"/spaces/{self.space_id}/auth/verify",
                    json={
                        "public_key": self.public_key_typed,
                        "signature": encode_base64(signature),
                        "challenge": challenge.challenge,
                    },
                )
                response.raise_for_status()
                token_data = response.json()
                auth_token = AuthToken(
                    token=token_data["token"],
                    expires_at=token_data["expires_at"],
                )
            except httpx.HTTPStatusError as e:
                raise AuthenticationError(f"Authentication verification failed: {e.response.text}") from e
            except Exception as e:
                raise AuthenticationError(f"Authentication verification failed: {e}") from e

            # Store token and expiration
            self._token = auth_token.token
            self._token_expires_at = auth_token.expires_at

            return self._token

    def refresh_token(self) -> str:
        """
        Refresh the current JWT token.

        Concurrent callers are serialized so a single expiring token does not
        burn several refreshes.

        Returns:
            New JWT bearer token

        Raises:
            AuthenticationError: If refresh fails or no token exists
        """
        with self._lock:
            return self._refresh_token_locked()

    def _refresh_token_locked(self) -> str:
        """Refresh the token. Caller must hold ``_lock``."""
        if not self._token:
            raise AuthenticationError("No token to refresh. Call authenticate() first.")

        with httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self._token}"},
        ) as client:
            try:
                response = client.post(f"/spaces/{self.space_id}/auth/refresh")
                response.raise_for_status()
                token_data = response.json()
                auth_token = AuthToken(
                    token=token_data["token"],
                    expires_at=token_data["expires_at"],
                )
            except httpx.HTTPStatusError as e:
                raise AuthenticationError(f"Token refresh failed: {e.response.text}") from e
            except Exception as e:
                raise AuthenticationError(f"Token refresh failed: {e}") from e

            # Update token and expiration
            self._token = auth_token.token
            self._token_expires_at = auth_token.expires_at

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
            return self._token  # type: ignore

        with self._lock:
            # A concurrent caller may have finished the handshake while we
            # waited for the lock; reuse its token instead of starting our own.
            if self.is_authenticated:
                return self._token  # type: ignore

            # Try to refresh if we have a token
            if self._token:
                try:
                    return self._refresh_token_locked()
                except AuthenticationError:
                    # Fall through to re-authenticate
                    pass

            # Full re-authentication
            return self._authenticate_locked()


class AsyncAuthSession:
    """
    Async version of AuthSession for use with async httpx clients.

    Handles challenge-response flow and token refresh asynchronously.
    """

    def __init__(
        self,
        space_id: str,
        public_key_typed: str,
        private_key: bytes,
        base_url: str = "http://localhost:8000",
    ):
        """
        Initialize async authentication session.

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

        self._token: str | None = None
        self._token_expires_at: int | None = None

        # Created lazily so the session is not bound to an event loop at
        # construction time. See `_get_lock`.
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        """
        Get the per-session lock, creating it on first use.

        Building it here rather than in `__init__` keeps the session usable
        when it is constructed outside a running loop. This is safe because
        there is no await between the check and the assignment, so concurrent
        coroutines on the same loop cannot both create one.
        """
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    @property
    def token(self) -> str | None:
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

    async def authenticate(self) -> str:
        """
        Perform challenge-response authentication.

        Concurrent callers are serialized so they cannot invalidate each
        other's challenge.

        Returns:
            JWT bearer token

        Raises:
            AuthenticationError: If authentication fails
        """
        async with self._get_lock():
            return await self._authenticate_locked()

    async def _authenticate_locked(self) -> str:
        """Run the challenge/verify handshake. Caller must hold the lock."""
        async with httpx.AsyncClient(base_url=self.base_url) as client:
            # Step 1: Request challenge
            try:
                response = await client.post(
                    f"/spaces/{self.space_id}/auth/challenge",
                    json={"public_key": self.public_key_typed},
                )
                response.raise_for_status()
                challenge_data = response.json()
                challenge = AuthChallenge(
                    challenge=challenge_data["challenge"],
                    expires_at=challenge_data["expires_at"],
                )
            except httpx.HTTPStatusError as e:
                raise AuthenticationError(f"Failed to get challenge: {e.response.text}") from e
            except Exception as e:
                raise AuthenticationError(f"Failed to get challenge: {e}") from e

            # Step 2: Sign the challenge string (UTF-8 encoded, not base64-decoded)
            challenge_bytes = challenge.challenge.encode("utf-8")
            signature = sign_data(challenge_bytes, self.private_key)

            # Step 3: Verify signature and get token
            try:
                response = await client.post(
                    f"/spaces/{self.space_id}/auth/verify",
                    json={
                        "public_key": self.public_key_typed,
                        "signature": encode_base64(signature),
                        "challenge": challenge.challenge,
                    },
                )
                response.raise_for_status()
                token_data = response.json()
                auth_token = AuthToken(
                    token=token_data["token"],
                    expires_at=token_data["expires_at"],
                )
            except httpx.HTTPStatusError as e:
                raise AuthenticationError(f"Authentication verification failed: {e.response.text}") from e
            except Exception as e:
                raise AuthenticationError(f"Authentication verification failed: {e}") from e

            # Store token and expiration
            self._token = auth_token.token
            self._token_expires_at = auth_token.expires_at

            return self._token

    async def refresh_token(self) -> str:
        """
        Refresh the current JWT token.

        Concurrent callers are serialized so a single expiring token does not
        burn several refreshes.

        Returns:
            New JWT bearer token

        Raises:
            AuthenticationError: If refresh fails or no token exists
        """
        async with self._get_lock():
            return await self._refresh_token_locked()

    async def _refresh_token_locked(self) -> str:
        """Refresh the token. Caller must hold the lock."""
        if not self._token:
            raise AuthenticationError("No token to refresh. Call authenticate() first.")

        async with httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self._token}"},
        ) as client:
            try:
                response = await client.post(f"/spaces/{self.space_id}/auth/refresh")
                response.raise_for_status()
                token_data = response.json()
                auth_token = AuthToken(
                    token=token_data["token"],
                    expires_at=token_data["expires_at"],
                )
            except httpx.HTTPStatusError as e:
                raise AuthenticationError(f"Token refresh failed: {e.response.text}") from e
            except Exception as e:
                raise AuthenticationError(f"Token refresh failed: {e}") from e

            # Update token and expiration
            self._token = auth_token.token
            self._token_expires_at = auth_token.expires_at

            return self._token

    async def ensure_authenticated(self) -> str:
        """
        Ensure session has a valid token, refreshing or re-authenticating if needed.

        Returns:
            Valid JWT bearer token

        Raises:
            AuthenticationError: If authentication fails
        """
        if self.is_authenticated:
            return self._token  # type: ignore

        async with self._get_lock():
            # A concurrent caller may have finished the handshake while we
            # waited for the lock; reuse its token instead of starting our own.
            if self.is_authenticated:
                return self._token  # type: ignore

            # Try to refresh if we have a token
            if self._token:
                try:
                    return await self._refresh_token_locked()
                except AuthenticationError:
                    # Fall through to re-authenticate
                    pass

            # Full re-authentication
            return await self._authenticate_locked()
