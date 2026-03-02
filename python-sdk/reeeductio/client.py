"""
High-level Space client for reeeductio.

Provides convenient methods for interacting with spaces, handling
authentication, messages, state, blobs, and data.
"""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import websockets
from websockets.asyncio.client import ClientConnection

from . import blobs, kvdata, messages, state
from .auth import AsyncAuthSession, AuthSession
from .crypto import Ed25519KeyPair, decrypt_aes_gcm, encrypt_aes_gcm, derive_key, generate_keypair
from .exceptions import ChainError, NotFoundError, StreamError, ValidationError
from .messages import validate_message_chain_with_anchor, verify_message_hash
from .local_store import LocalMessageStore
from .models import BlobCreated, EncryptedBlobCreated, DataEntry, Message, MessageCreated


class Space:
    """
    High-level client for interacting with a reeeductio space.

    Handles authentication, state management, messaging, blob storage, and key-value data.
    Uses httpx for HTTP operations with support for both sync usage.

    Attributes:
        space_id: Typed space identifier
        member_id: Typed member identifier (U_... for users, T_... for tools)
        private_key: Raw 32-byte Ed25519 private key
        symmetric_root: 256-bit root key for HKDF derivation
        user_symmetric_key: Optional 256-bit user-private key (not shared with space)
        message_key: Derived key for message encryption (32 bytes)
        state_key: Derived key for state encryption (32 bytes)
        data_key: Derived key for data encryption (32 bytes)
        user_message_key: User-private message key (None if no user_symmetric_key)
        user_data_key: User-private data key (None if no user_symmetric_key)
        base_url: Base URL of the reeeductio server
        auth: Authentication session manager
    """

    def __init__(
        self,
        space_id: str,
        member_id: str,
        private_key: bytes,
        symmetric_root: bytes,
        base_url: str = "http://localhost:8000",
        auto_authenticate: bool = True,
        local_store: LocalMessageStore | None = None,
        user_symmetric_key: bytes | None = None,
    ):
        """
        Initialize Space client.

        Args:
            space_id: Typed space identifier (44-char base64)
            member_id: Typed member identifier (U_... for users, T_... for tools)
            private_key: Raw 32-byte Ed25519 private key for authentication and signing
            symmetric_root: 256-bit (32-byte) root key for HKDF key derivation
            base_url: Base URL of the reeeductio server
            auto_authenticate: Whether to authenticate automatically on first request
            local_store: Optional local message store for caching. When provided,
                messages are cached locally and retrieved from cache when available.
            user_symmetric_key: Optional 256-bit (32-byte) user-private key for
                encrypting data that is confidential against other space members.
                When provided, used to derive user_message_key and user_data_key
                for user-private encryption.

        Raises:
            ValueError: If symmetric_root is not exactly 32 bytes
            ValueError: If user_symmetric_key is provided but not exactly 32 bytes
        """
        if len(symmetric_root) != 32:
            raise ValueError(f"symmetric_root must be exactly 32 bytes, got {len(symmetric_root)}")
        if user_symmetric_key is not None and len(user_symmetric_key) != 32:
            raise ValueError(f"user_symmetric_key must be exactly 32 bytes, got {len(user_symmetric_key)}")

        self.space_id = space_id
        self.member_id = member_id
        self.private_key = private_key
        self.symmetric_root = symmetric_root
        self.user_symmetric_key = user_symmetric_key
        self.base_url = base_url
        self._auto_authenticate = auto_authenticate
        self._local_store = local_store

        # Derive encryption keys from symmetric_root using HKDF
        # Include space_id in info for domain separation (prevents key reuse across spaces)
        self.message_key = derive_key(symmetric_root, f"message key | {space_id}")
        self.data_key = derive_key(symmetric_root, f"data key | {space_id}")
        # State key is actually just a topic key for the "state" topic
        self.state_key = derive_key(self.message_key, "topic key | state")
        # Keys for other topics can be derived as `topic_key = derive_key(self.message_key, f"topic key | {topic_id}")`

        # Derive user-private encryption keys if a user_symmetric_key was provided.
        # These are confidential against other space members (including admins) because
        # user_symmetric_key is not shared with the space.
        if user_symmetric_key is not None:
            self.user_message_key: bytes | None = derive_key(user_symmetric_key, f"user message key | {space_id}")
            self.user_data_key: bytes | None = derive_key(user_symmetric_key, f"user data key | {space_id}")
        else:
            self.user_message_key = None
            self.user_data_key = None

        # Create authentication session
        self.auth = AuthSession(
            space_id=space_id,
            public_key_typed=member_id,
            private_key=private_key,
            base_url=base_url,
        )

        self._client: httpx.Client | None = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close client."""
        self.close()

    def close(self):
        """Close the HTTP client."""
        if self._client:
            self._client.close()
            self._client = None

    @property
    def client(self) -> httpx.Client:
        """
        Get authenticated HTTP client, ensuring valid authentication.

        Returns:
            Authenticated httpx.Client

        Raises:
            AuthenticationError: If authentication fails
        """
        if self._auto_authenticate:
            token = self.auth.ensure_authenticated()
        elif self.auth.token:
            token = self.auth.token
        else:
            raise ValueError("Not authenticated. Call authenticate() or set auto_authenticate=True")

        # Create or update client with current token
        if not self._client:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers={"Authorization": f"Bearer {token}"},
            )
        else:
            # Update token if changed
            self._client.headers["Authorization"] = f"Bearer {token}"

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
    
    def get_plaintext_state(self, path: str) -> str:
        """
        Get current state value at path.

        Args:
            path: State path (e.g., "auth/users/U_abc123", "profiles/alice")

        Returns:
            Message containing the current state at this path

        Raises:
            NotFoundError: If no state exists at this path
        """
        message = state.get_state(self.client, self.space_id, path)
        return base64.b64decode(message.data).decode("utf-8")
    
    def get_encrypted_state(self, path: str, key: bytes | None = None) -> str:
        """
        Get encrypted state value at path and decrypt it.

        The state data is stored as base64-encoded AES-GCM-256 encrypted data.
        Format: IV (12 bytes) + ciphertext + tag (16 bytes)

        Args:
            path: State path (e.g., "auth/users/U_abc123", "profiles/alice")
            key: Decryption key. Defaults to self.state_key if not provided.

        Returns:
            Decrypted plaintext string

        Raises:
            NotFoundError: If no state exists at this path
            ValueError: If decryption fails (invalid format)
        """
        message = state.get_state(self.client, self.space_id, path)

        encrypted_b64 = message.data
        if len(encrypted_b64) == 0:
            return ""

        # Base64 decode
        encrypted_bytes = base64.b64decode(encrypted_b64)

        # Decrypt using provided key or fall back to state key
        plaintext_bytes = decrypt_aes_gcm(encrypted_bytes, key if key is not None else self.state_key)

        # Convert to string
        return plaintext_bytes.decode("utf-8")

    def set_plaintext_state(self, path: str, data: str, prev_hash: str | None = None) -> MessageCreated:
        """
        Set plaintext state value at path.

        The data is stored as-is without encryption.

        Args:
            path: State path (e.g., "profiles/alice", "config/settings")
            data: Plaintext string data to store
            prev_hash: Previous message hash in state topic (optional, fetched if not provided)

        Returns:
            MessageCreated with message_hash and server_timestamp

        Note:
            If prev_hash is not provided, this will fetch the current chain head.
            This may cause conflicts if multiple clients are writing concurrently.
        """
        # Convert string to bytes and store directly
        data_bytes = data.encode("utf-8")
        return self._set_state(path, data_bytes, prev_hash)

    def set_encrypted_state(self, path: str, data: str, prev_hash: str | None = None, key: bytes | None = None) -> MessageCreated:
        """
        Set encrypted state value at path.

        The data is encrypted using AES-GCM-256 with the state key, then base64-encoded.
        Format: IV (12 bytes) + ciphertext + tag (16 bytes)

        Args:
            path: State path (e.g., "auth/users/U_abc123", "profiles/alice")
            data: Plaintext string data to encrypt and store
            prev_hash: Previous message hash in state topic (optional, fetched if not provided)
            key: Encryption key. Defaults to self.state_key if not provided.

        Returns:
            MessageCreated with message_hash and server_timestamp

        Note:
            If prev_hash is not provided, this will fetch the current chain head.
            This may cause conflicts if multiple clients are writing concurrently.
        """
        # Convert string to bytes
        plaintext_bytes = data.encode("utf-8")

        # Encrypt using provided key or fall back to state key
        encrypted_bytes = encrypt_aes_gcm(plaintext_bytes, key if key is not None else self.state_key)

        # Pass encrypted bytes directly; post_message will base64-encode them
        return self._set_state(path, encrypted_bytes, prev_hash)

    def _set_state(self, path: str, data: bytes, prev_hash: str | None = None) -> MessageCreated:
        """
        Set state value at path.

        State is stored as messages in the "state" topic with the path in the 'type' field.

        Args:
            path: State path (e.g., "profiles/alice")
            data: Encrypted state data
            prev_hash: Previous message hash in state topic (optional, fetched if not provided)

        Returns:
            MessageCreated with message_hash and server_timestamp

        Note:
            If prev_hash is not provided, this will fetch the current chain head.
            This may cause conflicts if multiple clients are writing concurrently.
        """
        # Fetch prev_hash if not provided — request reverse-chronological to get chain head
        if prev_hash is None:
            far_future = 9999999999999
            msgs = self.get_messages("state", from_timestamp=far_future, to_timestamp=0, limit=1)
            prev_hash = msgs[0].message_hash if msgs else None

        return state.set_state(
            client=self.client,
            space_id=self.space_id,
            path=path,
            data=data,
            prev_hash=prev_hash,
            sender_public_key_typed=self.member_id,
            sender_private_key=self.private_key,
        )

    def get_state_history(
        self,
        from_timestamp: int | None = None,
        to_timestamp: int | None = None,
        limit: int = 100,
    ) -> list[Message]:
        """
        Get all state change messages (event log).

        Args:
            from_timestamp: Optional start timestamp (milliseconds)
            to_timestamp: Optional end timestamp (milliseconds)
            limit: Maximum number of messages to return

        Returns:
            List of state change messages
        """
        return state.get_state_history(
            self.client,
            self.space_id,
            from_timestamp,
            to_timestamp,
            limit,
        )

    # ============================================================
    # Message Management
    # ============================================================

    def get_messages(
        self,
        topic_id: str,
        from_timestamp: int | None = None,
        to_timestamp: int | None = None,
        limit: int = 100,
        use_cache: bool = True,
        validate_chain: bool = True,
    ) -> list[Message]:
        """
        Get messages from a topic.

        When a local_store is configured and use_cache is True, this method:
        1. Checks if cached data might be stale (to_timestamp > latest cached)
        2. Fetches newer messages from server if needed
        3. Validates message hashes and chain integrity
        4. Fetches gap-filling messages if there's a gap between cached and new
        5. Merges server results with cached data
        6. Caches any new messages

        Args:
            topic_id: Topic identifier
            from_timestamp: Optional start timestamp (milliseconds)
            to_timestamp: Optional end timestamp (milliseconds)
            limit: Maximum number of messages to return
            use_cache: Whether to use local cache (default True)
            validate_chain: Whether to validate chain integrity (default True)

        Returns:
            List of messages

        Raises:
            ChainError: If chain validation fails
        """
        if not use_cache or self._local_store is None:
            server_messages = self._fetch_messages_from_server(
                topic_id, from_timestamp, to_timestamp, limit
            )
            if validate_chain and server_messages:
                self._validate_and_verify_messages(topic_id, server_messages)
            return server_messages

        # Get cached messages and latest cached timestamp
        cached = self._local_store.get_messages(
            self.space_id, topic_id, from_timestamp, to_timestamp, limit
        )
        latest_cached_ts = self._local_store.get_latest_timestamp(self.space_id, topic_id)

        # Determine if we need to fetch from server
        need_server_fetch = (
            to_timestamp is None
            or latest_cached_ts is None
            or to_timestamp > latest_cached_ts
        )

        if not need_server_fetch and cached:
            return cached

        # Fetch from server - either everything or just newer messages
        server_from = from_timestamp
        if latest_cached_ts is not None and cached:
            server_from = latest_cached_ts + 1

        server_messages = self._fetch_messages_from_server(
            topic_id, server_from, to_timestamp, limit
        )

        if not server_messages:
            return cached

        # Validate hashes of all new messages
        if validate_chain:
            for msg in server_messages:
                if not verify_message_hash(self.space_id, msg):
                    raise ChainError(
                        f"Message hash verification failed for {msg.message_hash}"
                    )

        # Check for gap between cached and new messages
        # The oldest new message's prev_hash should either:
        # 1. Be None (start of topic)
        # 2. Match the latest cached message's hash
        # 3. Otherwise, we have a gap that needs filling
        if validate_chain and cached:
            server_messages.sort(key=lambda m: m.server_timestamp)
            oldest_new = server_messages[0]
            latest_cached = max(cached, key=lambda m: m.server_timestamp)

            if oldest_new.prev_hash is not None and oldest_new.prev_hash != latest_cached.message_hash:
                # Gap detected - fetch missing messages
                gap_messages = self._fetch_gap_messages(
                    topic_id, latest_cached.message_hash, oldest_new.prev_hash
                )
                if gap_messages:
                    server_messages = gap_messages + server_messages

        # Validate chain integrity if we have both cached and new messages
        if validate_chain and cached and server_messages:
            latest_cached = max(cached, key=lambda m: m.server_timestamp)
            if not validate_message_chain_with_anchor(
                self.space_id, server_messages, latest_cached.message_hash
            ):
                # Check if chain starts from beginning (prev_hash is None)
                server_messages.sort(key=lambda m: m.server_timestamp)
                if server_messages[0].prev_hash is not None:
                    raise ChainError(
                        f"Chain validation failed: new messages don't link to cached chain"
                    )

        # Cache new messages (they've been validated)
        self._local_store.put_messages(self.space_id, server_messages)

        # Merge cached and server messages, deduplicate by hash
        seen_hashes = set()
        merged = []
        for msg in cached + server_messages:
            if msg.message_hash not in seen_hashes:
                seen_hashes.add(msg.message_hash)
                merged.append(msg)
        merged.sort(key=lambda m: m.server_timestamp)
        return merged[:limit]

    def _validate_and_verify_messages(
        self, topic_id: str, messages_list: list[Message]
    ) -> None:
        """Validate message hashes and chain for messages without cache."""
        for msg in messages_list:
            if not verify_message_hash(self.space_id, msg):
                raise ChainError(
                    f"Message hash verification failed for {msg.message_hash}"
                )

        # Validate chain links back to start or is internally consistent
        messages_list.sort(key=lambda m: m.server_timestamp)
        if messages_list:
            # First message should link to something we trust or be the start
            anchor = messages_list[0].prev_hash
            if not validate_message_chain_with_anchor(self.space_id, messages_list, anchor):
                raise ChainError("Chain validation failed: messages don't form valid chain")

    def _fetch_gap_messages(
        self,
        topic_id: str,
        cached_head_hash: str,
        target_prev_hash: str,
        max_iterations: int = 10,
    ) -> list[Message]:
        """
        Fetch messages to fill gap between cached head and new messages.

        Walks backwards from target_prev_hash until we reach cached_head_hash
        or the start of the topic.

        Args:
            topic_id: Topic identifier
            cached_head_hash: Hash of our latest cached message
            target_prev_hash: prev_hash of the oldest new message
            max_iterations: Maximum fetch iterations to prevent infinite loops

        Returns:
            List of gap-filling messages in chronological order
        """
        gap_messages = []
        current_hash = target_prev_hash

        for _ in range(max_iterations):
            if current_hash is None or current_hash == cached_head_hash:
                break

            # Fetch the message by hash
            try:
                msg = self._fetch_message_by_hash(topic_id, current_hash)
                if msg is None:
                    break
                gap_messages.insert(0, msg)  # Prepend to maintain order
                current_hash = msg.prev_hash
            except Exception:
                break

        return gap_messages

    def _fetch_message_by_hash(self, topic_id: str, message_hash: str) -> Message | None:
        """Fetch a single message by hash from server."""
        try:
            response = self.client.get(
                f"/spaces/{self.space_id}/topics/{topic_id}/messages/{message_hash}"
            )
            response.raise_for_status()
            data = response.json()
            return Message(**data)
        except httpx.HTTPStatusError:
            return None
        except Exception:
            return None

    def _fetch_messages_from_server(
        self,
        topic_id: str,
        from_timestamp: int | None = None,
        to_timestamp: int | None = None,
        limit: int = 100,
    ) -> list[Message]:
        """Fetch messages directly from server without caching."""
        try:
            params = {"limit": limit}
            if from_timestamp is not None:
                params["from"] = from_timestamp
            if to_timestamp is not None:
                params["to"] = to_timestamp

            response = self.client.get(f"/spaces/{self.space_id}/topics/{topic_id}/messages", params=params)
            response.raise_for_status()
            data = response.json()
            message_list = data.get("messages", [])
            return [Message(**msg) for msg in message_list]
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return []
            raise ValidationError(f"Failed to get messages: {e.response.text}") from e
        except Exception as e:
            raise ValidationError(f"Failed to get messages: {e}") from e

    def get_message(self, topic_id: str, message_hash: str, use_cache: bool = True) -> Message:
        """
        Get a specific message by hash.

        Args:
            topic_id: Topic identifier
            message_hash: Typed message identifier (44-char base64)
            use_cache: Whether to use local cache (default True)

        Returns:
            Message

        Raises:
            NotFoundError: If message not found
        """
        # Check local cache first
        if use_cache and self._local_store is not None:
            cached = self._local_store.get_message(self.space_id, topic_id, message_hash)
            if cached is not None:
                return cached

        # Fetch from server
        try:
            response = self.client.get(f"/spaces/{self.space_id}/topics/{topic_id}/messages/{message_hash}")
            response.raise_for_status()
            data = response.json()
            message = Message(**data)

            # Cache the message
            if use_cache and self._local_store is not None:
                self._local_store.put_message(self.space_id, message)

            return message
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise NotFoundError(f"Message not found: {message_hash}") from e
            raise ValidationError(f"Failed to get message: {e.response.text}") from e
        except Exception as e:
            raise ValidationError(f"Failed to get message: {e}") from e

    def post_message(
        self,
        topic_id: str,
        msg_type: str,
        data: bytes,
        prev_hash: str | None = None,
    ) -> MessageCreated:
        """
        Post a message to a topic.

        Args:
            topic_id: Topic identifier
            msg_type: Message type/category
            data: Encrypted message data
            prev_hash: Hash of previous message (optional, fetched if not provided)

        Returns:
            MessageCreated with message_hash and server_timestamp

        Note:
            If prev_hash is not provided, this will fetch the current chain head.
        """
        # Fetch prev_hash if not provided — request reverse-chronological to get chain head
        if prev_hash is None:
            far_future = 9999999999999
            msgs = self.get_messages(topic_id, from_timestamp=far_future, to_timestamp=0, limit=1)
            prev_hash = msgs[0].message_hash if msgs else None

        return messages.post_message(
            client=self.client,
            space_id=self.space_id,
            topic_id=topic_id,
            msg_type=msg_type,
            data=data,
            prev_hash=prev_hash,
            sender_public_key_typed=self.member_id,
            sender_private_key=self.private_key,
        )

    def derive_topic_key(self, topic_id: str) -> bytes:
        """
        Derive the encryption key for a topic.

        Args:
            topic_id: Topic identifier

        Returns:
            32-byte AES-256 topic key
        """
        return derive_key(self.message_key, f"topic key | {topic_id}")

    def post_encrypted_message(
        self,
        topic_id: str,
        msg_type: str,
        data: bytes,
        prev_hash: str | None = None,
    ) -> MessageCreated:
        """
        Encrypt and post a message to a topic.

        Encrypts the plaintext with the derived key for the given topic,
        then posts the ciphertext.

        Args:
            topic_id: Topic identifier
            msg_type: Message type/category
            data: Plaintext message data to encrypt
            prev_hash: Hash of previous message (optional, fetched if not provided)

        Returns:
            MessageCreated with message_hash and server_timestamp
        """
        topic_key = self.derive_topic_key(topic_id)
        encrypted = encrypt_aes_gcm(data, topic_key)
        return self.post_message(topic_id, msg_type, encrypted, prev_hash)

    def decrypt_message_data(self, msg: Message, topic_id: str) -> bytes:
        """
        Decrypt the data payload of an encrypted message.

        Derives the topic key and decrypts the message's base64-encoded data.

        Args:
            msg: Message with encrypted data payload
            topic_id: Topic identifier used to derive the decryption key

        Returns:
            Decrypted plaintext bytes
        """
        topic_key = self.derive_topic_key(topic_id)
        return messages.decrypt_message_data(msg, topic_key)

    # ============================================================
    # Blob Management
    # ============================================================

    def upload_plaintext_blob(self, data: bytes) -> BlobCreated:
        """
        Upload plaintext blob.

        The blob_id is computed from the content hash.

        Args:
            data: Plaintext blob data

        Returns:
            BlobCreated with blob_id and size
        """
        return blobs.upload_blob(self.client, self.space_id, data)

    def encrypt_and_upload_blob(self, data: bytes) -> EncryptedBlobCreated:
        """
        Encrypt and upload a blob.

        Generates a random AES-256 data encryption key (DEK), encrypts the data
        using AES-GCM-256, and uploads the encrypted blob.
        The blob_id is computed from the encrypted content hash.

        Args:
            data: Plaintext blob data to encrypt and upload

        Returns:
            EncryptedBlobCreated with blob_id, size, and the generated DEK
        """
        return blobs.encrypt_and_upload_blob(self.client, self.space_id, data)

    def download_plaintext_blob(self, blob_id: str) -> bytes:
        """
        Download plaintext blob.

        Args:
            blob_id: Typed blob identifier

        Returns:
            Plaintext blob data
        """
        return blobs.download_blob(self.client, self.space_id, blob_id)

    def download_and_decrypt_blob(self, blob_id: str, key: bytes) -> bytes:
        """
        Download and decrypt encrypted blob.

        The blob is decrypted using AES-GCM-256 with the provided DEK,
        which was returned by encrypt_and_upload_blob().

        Args:
            blob_id: Typed blob identifier
            key: 32-byte AES-256 data encryption key (DEK)

        Returns:
            Decrypted plaintext blob data

        Raises:
            cryptography.exceptions.InvalidTag: If decryption fails (wrong key or corrupted data)
        """
        encrypted_data = blobs.download_blob(self.client, self.space_id, blob_id)
        return decrypt_aes_gcm(encrypted_data, key)

    def delete_blob(self, blob_id: str) -> None:
        """
        Delete blob.

        Args:
            blob_id: Typed blob identifier
        """
        blobs.delete_blob(self.client, self.space_id, blob_id)

    # ============================================================
    # Key-Value Data Management
    # ============================================================

    def get_plaintext_data(self, path: str) -> bytes:
        """
        Get plaintext data value at path.

        Args:
            path: Data path (e.g., "profiles/alice", "settings/theme")

        Returns:
            Plaintext data bytes

        Raises:
            NotFoundError: If no data exists at this path
        """
        entry = kvdata.get_data(self.client, self.space_id, path)

        # Data is stored as base64-encoded
        return base64.b64decode(entry.data)

    def get_encrypted_data(self, path: str, key: bytes | None = None) -> bytes:
        """
        Get encrypted data value at path and decrypt it.

        The data is stored as base64-encoded AES-GCM-256 encrypted data.
        Format: IV (12 bytes) + ciphertext + tag (16 bytes)

        Args:
            path: Data path (e.g., "profiles/alice", "settings/theme")
            key: Decryption key. Defaults to self.data_key if not provided.

        Returns:
            Decrypted plaintext data bytes

        Raises:
            NotFoundError: If no data exists at this path
            cryptography.exceptions.InvalidTag: If decryption fails (wrong key or corrupted data)
        """
        entry = kvdata.get_data(self.client, self.space_id, path)

        # Base64 decode
        encrypted_bytes = base64.b64decode(entry.data)

        # Decrypt using provided key or fall back to data key
        return decrypt_aes_gcm(encrypted_bytes, key if key is not None else self.data_key)

    def set_plaintext_data(self, path: str, data: bytes) -> int:
        """
        Set plaintext data value at path.

        The data is base64-encoded but not encrypted.

        Args:
            path: Data path (e.g., "profiles/alice", "settings/theme")
            data: Plaintext data bytes to store

        Returns:
            Timestamp when the data was signed (milliseconds)
        """
        return self._set_data(path, data)

    def set_encrypted_data(self, path: str, data: bytes, key: bytes | None = None) -> int:
        """
        Set encrypted data value at path.

        The data is encrypted using AES-GCM-256 with the data key, then base64-encoded.
        Format: IV (12 bytes) + ciphertext + tag (16 bytes)

        Args:
            path: Data path (e.g., "profiles/alice", "settings/theme")
            data: Plaintext data bytes to encrypt and store
            key: Encryption key. Defaults to self.data_key if not provided.

        Returns:
            Timestamp when the data was signed (milliseconds)
        """
        # Encrypt using provided key or fall back to data key
        encrypted_bytes = encrypt_aes_gcm(data, key if key is not None else self.data_key)

        return self._set_data(path, encrypted_bytes)

    def get_encrypted_user_data(self, path: str) -> bytes:
        """
        Get user-private encrypted data at a path relative to this user's namespace.

        Reads from ``user/{member_id}/{path}`` and decrypts with self.user_data_key,
        which is confidential against other space members and the server.

        Args:
            path: Relative data path (e.g., "notes", "settings/theme")

        Returns:
            Decrypted plaintext data bytes

        Raises:
            ValueError: If user_symmetric_key was not provided to the Space constructor
            NotFoundError: If no data exists at this path
            cryptography.exceptions.InvalidTag: If decryption fails
        """
        if self.user_data_key is None:
            raise ValueError("user_symmetric_key is required for user-private encryption")
        return self.get_encrypted_data(f"user/{self.member_id}/{path}", key=self.user_data_key)

    def set_encrypted_user_data(self, path: str, data: bytes) -> int:
        """
        Store user-private encrypted data at a path relative to this user's namespace.

        Encrypts with self.user_data_key (confidential against other space members and
        the server) and stores at ``user/{member_id}/{path}``.

        Args:
            path: Relative data path (e.g., "notes", "settings/theme")
            data: Plaintext data bytes to encrypt and store

        Returns:
            Timestamp when the data was signed (milliseconds)

        Raises:
            ValueError: If user_symmetric_key was not provided to the Space constructor
        """
        if self.user_data_key is None:
            raise ValueError("user_symmetric_key is required for user-private encryption")
        return self.set_encrypted_data(f"user/{self.member_id}/{path}", data, key=self.user_data_key)

    def _set_data(self, path: str, data: bytes) -> int:
        """
        Set data value at path.

        Args:
            path: Data path
            data: Data bytes to store (will be base64-encoded)

        Returns:
            Timestamp when the data was signed (milliseconds)
        """
        return kvdata.set_data(
            client=self.client,
            space_id=self.space_id,
            path=path,
            data=data,
            signed_by=self.member_id,
            private_key=self.private_key,
        )

    # ============================================================
    # Authorization Utilities
    # ============================================================

    def create_role(self, role_name: str, description: str | None = None) -> MessageCreated:
        """
        Create a role in the space.

        Roles are stored at auth/roles/{role_name} and can have capabilities
        granted to them via grant_capability_to_role().

        Args:
            role_name: Name of the role to create
            description: Optional description of the role

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If role creation fails
        """
        role_data = {
            "role_id": role_name,
        }
        if description:
            role_data["description"] = description

        return self.set_plaintext_state(
            f"auth/roles/{role_name}",
            json.dumps(role_data),
        )

    def add_user(self, user_id: str, description: str | None = None) -> MessageCreated:
        """
        Add a user entry in the space.

        Users are stored at auth/users/{user_id} and can have capabilities
        granted to them via grant_capability_to_user().

        Args:
            user_id: Typed user identifier (U_...)
            description: Optional description of the user

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If user creation fails
        """
        user_data = {
            "user_id": user_id,
        }
        if description:
            user_data["description"] = description

        return self.set_plaintext_state(
            f"auth/users/{user_id}",
            json.dumps(user_data),
        )

    def create_tool(self, tool_id: str, description: str | None = None) -> MessageCreated:
        """
        Create a tool entry in the space.

        Tools are stored at auth/tools/{tool_id} and can have capabilities
        granted to them via grant_capability_to_tool().

        Args:
            tool_id: Typed tool identifier (T_...)
            description: Optional description of the tool

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If tool creation fails
        """
        tool_data = {
            "tool_id": tool_id,
        }
        if description:
            tool_data["description"] = description

        return self.set_plaintext_state(
            f"auth/tools/{tool_id}",
            json.dumps(tool_data),
        )

    def grant_capability_to_role(
        self,
        role_name: str,
        cap_id: str,
        capability: dict,
    ) -> MessageCreated:
        """
        Grant a capability to a role.

        Capabilities are stored at auth/roles/{role_name}/rights/{cap_id}.

        Args:
            role_name: Name of the role to grant the capability to
            cap_id: Capability ID
            capability: Capability dict with 'op' and 'path' keys

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If capability creation fails
        """
        return self.set_plaintext_state(
            f"auth/roles/{role_name}/rights/{cap_id}",
            json.dumps(capability),
        )

    def assign_role_to_user(self, user_id: str, role_name: str) -> MessageCreated:
        """
        Assign a role to a user.

        Role assignments are stored at auth/users/{user_id}/roles/{role_name}.

        Args:
            user_id: Typed user identifier (U_...)
            role_name: Name of the role to assign

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If role assignment fails
        """
        assignment_data = {
            "user_id": user_id,
            "role_id": role_name,
        }

        return self.set_plaintext_state(
            f"auth/users/{user_id}/roles/{role_name}",
            json.dumps(assignment_data),
        )

    def grant_capability_to_user(
        self,
        user_id: str,
        cap_id: str,
        capability: dict,
    ) -> MessageCreated:
        """
        Grant a capability to a user.

        Capabilities are stored at auth/users/{user_id}/rights/{cap_id}.

        Args:
            user_id: Typed user identifier (U_...)
            cap_id: Capability ID
            capability: Capability dict with 'op' and 'path' keys

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If capability creation fails
        """
        return self.set_plaintext_state(
            f"auth/users/{user_id}/rights/{cap_id}",
            json.dumps(capability),
        )

    def grant_capability_to_tool(
        self,
        tool_id: str,
        cap_id: str,
        capability: dict,
    ) -> MessageCreated:
        """
        Grant a capability to a tool.

        Capabilities are stored at auth/tools/{tool_id}/rights/{cap_id}.

        Args:
            tool_id: Typed tool identifier (T_...)
            cap_id: Capability ID
            capability: Capability dict with 'op' and 'path' keys

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If capability creation fails
        """
        return self.set_plaintext_state(
            f"auth/tools/{tool_id}/rights/{cap_id}",
            json.dumps(capability),
        )

    def create_invitation(self, description: str | None = None) -> Ed25519KeyPair:
        """
        Create an invitation tool that can add a new user to the space.

        Generates a new keypair, creates a tool entry for it, and grants
        the tool capabilities to create a user and assign them the "user" role.

        Args:
            description: Optional description of the invitation

        Returns:
            Ed25519KeyPair for the invitation tool. The recipient will use this
            keypair to authenticate and add themselves to the space.

        Raises:
            ValidationError: If tool or capability creation fails
        """
        keypair = generate_keypair()
        tool_id = keypair.to_tool_id()

        self.create_tool(tool_id, description=description)
        self.grant_capability_to_tool(
            tool_id,
            "can_create_user",
            {"op": "create", "path": "state/auth/users/{any}"},
        )
        self.grant_capability_to_tool(
            tool_id,
            "can_grant_user_role",
            {"op": "create", "path": "state/auth/users/{any}/roles/user"},
        )

        return keypair

    # ============================================================
    # OPAQUE Password-Based Key Recovery
    # ============================================================

    def opaque_register(
        self,
        username: str,
        password: str,
        user_id: str | None = None,
        private_key: bytes | None = None,
    ) -> str:
        """
        Register OPAQUE credentials for password-based login.

        After registration, the user can recover their keypair and symmetric_root
        by logging in with their username and password using opaque_login().

        This method requires authentication (auto-authenticates if enabled).

        Uses the opaque_snake library for the OPAQUE protocol.

        Args:
            username: OPAQUE username (must be unique within the space)
            password: Password for future logins
            user_id: Typed identifier string (USER or TOOL) for the public key.
                If None, uses self.member_id.
            private_key: 32-byte Ed25519 private key matching user_id.
                If None, uses self.private_key.

        Returns:
            The username that was registered

        Raises:
            OpaqueNotEnabledError: If OPAQUE is not enabled for this space
            OpaqueError: If registration fails
            ValidationError: If username already exists or user_id doesn't match private_key

        Example:
            # Register after being added to a space
            space = Space(space_id, member_id, private_key, symmetric_root, base_url)
            space.opaque_register("alice", "my-secure-password")

            # Register with a tool key
            space.opaque_register("tool-alice", "tool-password",
                                  user_id=tool_keypair.to_tool_id(),
                                  private_key=tool_keypair.private_key)

            # Later, recover credentials with password
            from reeeductio import opaque_login
            credentials = opaque_login(base_url, space_id, "alice", "my-secure-password")
        """
        # Import from our local opaque module which wraps opaque_snake
        import os
        from .opaque import opaque_register as _opaque_register

        # Use provided values or derive from self
        if user_id is None:
            user_id = self.member_id
        if private_key is None:
            private_key = self.private_key

        # Use the existing user_symmetric_key if present; otherwise generate a fresh
        # random key so that one is always stored in the credential blob and recovered
        # at the next opaque_login.
        user_symmetric_key = self.user_symmetric_key or os.urandom(32)

        return _opaque_register(
            client=self.client,
            space_id=self.space_id,
            username=username,
            password=password,
            user_id=user_id,
            private_key=private_key,
            symmetric_root=self.symmetric_root,
            user_symmetric_key=user_symmetric_key,
        )

    def enable_opaque(self) -> dict[str, bool]:
        """
        Enable OPAQUE for this space.

        Sets up the OPAQUE server configuration and creates the opaque-user role
        with the necessary permissions. This must be called by an admin before
        users can register OPAQUE credentials.

        This method:
        1. Creates OPAQUE server setup if it doesn't exist (stored in data)
        2. Creates opaque-user role if it doesn't exist (stored in state)
        3. Adds CREATE capability for opaque/users/{any} if missing

        Returns:
            Dict with keys indicating what was created:
            - server_setup_created: True if new server setup was uploaded
            - role_created: True if opaque-user role was created
            - capability_created: True if CREATE capability was added

        Raises:
            ValidationError: If operation fails (usually due to insufficient permissions)

        Example:
            # As space admin, enable OPAQUE
            space = Space(space_id, member_id, private_key, symmetric_root, base_url)
            result = space.enable_opaque()
            if result["server_setup_created"]:
                print("OPAQUE server setup created")
        """
        from .opaque import (
            OPAQUE_SERVER_SETUP_PATH,
            OPAQUE_USER_ROLE_ID,
            OPAQUE_USER_CAP_ID,
        )

        # Import OpaqueServer only after checking availability
        from opaque_snake import OpaqueServer

        result = {
            "server_setup_created": False,
            "role_created": False,
            "capability_created": False,
        }

        # Step 1: Check/create OPAQUE server setup (stored in data store)
        try:
            self.get_plaintext_data(OPAQUE_SERVER_SETUP_PATH)
            # Server setup exists
        except NotFoundError:
            # Create new server setup
            server = OpaqueServer()
            setup_bytes = server.export_setup()
            self.set_plaintext_data(OPAQUE_SERVER_SETUP_PATH, setup_bytes)
            result["server_setup_created"] = True

        # Step 2: Check/create opaque-user role (stored in state)
        try:
            self.get_plaintext_state(f"auth/roles/{OPAQUE_USER_ROLE_ID}")
            # Role exists
        except NotFoundError:
            self.create_role(
                OPAQUE_USER_ROLE_ID,
                description="Role for users who can register OPAQUE credentials",
            )
            result["role_created"] = True

        # Step 3: Check/create CREATE capability for opaque/users/{any}
        cap_path = f"auth/roles/{OPAQUE_USER_ROLE_ID}/rights/{OPAQUE_USER_CAP_ID}"
        try:
            self.get_plaintext_state(cap_path)
            # Capability exists
        except NotFoundError:
            self.grant_capability_to_role(
                OPAQUE_USER_ROLE_ID,
                OPAQUE_USER_CAP_ID,
                {"op": "create", "path": "data/opaque/users/{any}"},
            )
            result["capability_created"] = True

        return result


class AdminSpace(Space):
    """
    Client for interacting with the admin space to create new spaces.

    Extends Space with the ability to register new spaces in the admin space.
    The admin space is a special space that stores the registry of all spaces
    and their creators.

    Example:
        admin_space = AdminSpace(
            space_id=admin_space_id,
            member_id=user_keypair.to_user_id(),
            private_key=user_keypair.private_key,
            symmetric_root=admin_symmetric_root,
            base_url=base_url,
        )

        # Generate keypair for new space
        new_space_keypair = generate_keypair()

        # Register the space in the admin space
        admin_space.create_space(new_space_keypair)
    """

    def create_space(self, space_keypair: Ed25519KeyPair) -> str:
        """
        Create and register a new space in the admin space.

        This method:
        1. Derives the space_id from the space keypair's public key
        2. Creates a registration data structure with space_signature proving ownership
        3. Writes the registration to spaces/{space_id} in the admin space
        4. Indexes the space at users/{user_id}/spaces/{space_id}

        Args:
            space_keypair: Ed25519 keypair for the new space. The caller must
                          retain this keypair to access the space later.

        Returns:
            The space_id of the newly created space

        Raises:
            ValidationError: If space registration fails
        """
        from datetime import datetime, timezone

        from .crypto import encode_base64, sign_data

        # Derive space_id from the space keypair
        space_id = space_keypair.to_space_id()

        # Get the member_id of the caller (who is creating the space)
        created_by = self.member_id

        # Get current timestamp in milliseconds
        created_at = int(datetime.now(timezone.utc).timestamp() * 1000)

        # Create the canonical message to sign: {space_id}|{created_by}|{created_at}
        canonical_message = f"{space_id}|{created_by}|{created_at}"

        # Sign with the space's private key to prove ownership
        signature = sign_data(canonical_message.encode("utf-8"), space_keypair.private_key)
        space_signature = encode_base64(signature)

        # Create the registration data
        registration_data = {
            "space_id": space_id,
            "created_by": created_by,
            "created_at": created_at,
            "space_signature": space_signature,
        }

        # Write to spaces/{space_id} in the admin space
        self.set_plaintext_state(f"spaces/{space_id}", json.dumps(registration_data))

        # Index the space at users/{user_id}/spaces/{space_id}
        index_data = {"space_id": space_id}
        self.set_plaintext_state(f"users/{created_by}/spaces/{space_id}", json.dumps(index_data))

        return space_id


class AdminClient:
    """
    Admin client for authenticating to the admin space and getting its ID.

    This client provides a simple way to authenticate against the admin space
    without knowing its ID in advance. Once authenticated, use get_space_id()
    to obtain the admin space ID, then use a regular Space client to perform
    admin operations.

    Example:
        # Authenticate and get admin space ID
        admin = AdminClient(keypair, base_url)
        admin_space_id = admin.get_space_id()

        # Use regular Space client for admin operations
        space = Space(
            space_id=admin_space_id,
            member_id=keypair.to_user_id(),
            private_key=keypair.private_key,
            symmetric_root=admin_symmetric_root,
            base_url=base_url,
        )

        # Perform admin operations using standard state API
        space.set_plaintext_state(f"auth/users/{new_user_id}", user_data)

    Attributes:
        keypair: Ed25519 key pair for authentication and signing
        base_url: Base URL of the reeeductio server
    """

    def __init__(
        self,
        keypair: Ed25519KeyPair,
        base_url: str = "http://localhost:8000",
        auto_authenticate: bool = True,
    ):
        """
        Initialize AdminClient.

        Args:
            keypair: Ed25519 key pair for authentication and signing
            base_url: Base URL of the reeeductio server
            auto_authenticate: Whether to authenticate automatically on first request
        """
        self.keypair = keypair
        self.base_url = base_url
        self._auto_authenticate = auto_authenticate

        self._token: str | None = None
        self._token_expires_at: int | None = None
        self._client: httpx.Client | None = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close client."""
        self.close()

    def close(self):
        """Close the HTTP client."""
        if self._client:
            self._client.close()
            self._client = None

    @property
    def is_authenticated(self) -> bool:
        """Check if session has a valid token."""
        from datetime import datetime, timezone

        if not self._token:
            return False

        if self._token_expires_at:
            # Check if token is expired (with 60s buffer)
            now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
            return now_ms < (self._token_expires_at - 60_000)

        return True

    @property
    def token(self) -> str | None:
        """Get the current JWT token, if authenticated."""
        return self._token

    def authenticate(self) -> str:
        """
        Perform challenge-response authentication against the admin space.

        Returns:
            JWT bearer token

        Raises:
            AuthenticationError: If authentication fails
        """
        from .crypto import encode_base64, sign_data
        from .exceptions import AuthenticationError

        with httpx.Client(base_url=self.base_url) as client:
            # Step 1: Request challenge from admin endpoint
            try:
                response = client.post(
                    "/admin/auth/challenge",
                    json={"public_key": self.keypair.to_user_id()},
                )
                response.raise_for_status()
                challenge_data = response.json()
            except httpx.HTTPStatusError as e:
                raise AuthenticationError(f"Failed to get admin challenge: {e.response.text}") from e
            except Exception as e:
                raise AuthenticationError(f"Failed to get admin challenge: {e}") from e

            # Step 2: Sign the challenge string (UTF-8 encoded, not base64-decoded)
            challenge_bytes = challenge_data["challenge"].encode("utf-8")
            signature = sign_data(challenge_bytes, self.keypair.private_key)

            # Step 3: Verify signature and get token
            try:
                response = client.post(
                    "/admin/auth/verify",
                    json={
                        "public_key": self.keypair.to_user_id(),
                        "signature": encode_base64(signature),
                        "challenge": challenge_data["challenge"],
                    },
                )
                response.raise_for_status()
                token_data = response.json()
            except httpx.HTTPStatusError as e:
                raise AuthenticationError(f"Admin authentication failed: {e.response.text}") from e
            except Exception as e:
                raise AuthenticationError(f"Admin authentication failed: {e}") from e

            # Store token and expiration
            self._token = token_data["token"]
            self._token_expires_at = token_data["expires_at"]

            return self._token

    def _ensure_authenticated(self) -> str:
        """
        Ensure we have a valid token.

        Returns:
            Valid JWT bearer token

        Raises:
            AuthenticationError: If authentication fails
        """
        if self.is_authenticated and self._token is not None:
            return self._token

        return self.authenticate()

    @property
    def client(self) -> httpx.Client:
        """
        Get authenticated HTTP client.

        Returns:
            Authenticated httpx.Client

        Raises:
            AuthenticationError: If authentication fails
        """
        if self._auto_authenticate:
            token = self._ensure_authenticated()
        elif self._token:
            token = self._token
        else:
            raise ValueError("Not authenticated. Call authenticate() or set auto_authenticate=True")

        if not self._client:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers={"Authorization": f"Bearer {token}"},
            )
        else:
            self._client.headers["Authorization"] = f"Bearer {token}"

        return self._client

    def get_space_id(self) -> str:
        """
        Get the admin space ID.

        This allows you to use a regular Space client with the admin space ID
        to perform admin operations through the standard state and message endpoints.

        Returns:
            The admin space ID (44-char base64)

        Raises:
            AuthenticationError: If not authenticated or token is invalid
        """
        from .exceptions import AuthenticationError

        try:
            response = self.client.get("/admin/space")
            response.raise_for_status()
            return response.json()["space_id"]
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise AuthenticationError(f"Authentication required: {e.response.text}") from e
            raise AuthenticationError(f"Failed to get admin space ID: {e.response.text}") from e

    def delete_blob(self, blob_id: str) -> None:
        """
        Delete a blob directly from the server's blob storage.

        This is an admin operation that bypasses normal space-scoped blob deletion,
        allowing removal of orphaned or problematic blobs. Blobs are stored separately
        from space state and cannot be deleted through the regular state API.

        Args:
            blob_id: Typed blob identifier (44-char base64)

        Raises:
            NotFoundError: If blob not found
            AuthorizationError: If caller lacks admin permissions
        """
        from .exceptions import AuthorizationError, NotFoundError, ValidationError

        try:
            response = self.client.delete(f"/admin/blobs/{blob_id}")
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise NotFoundError(f"Blob not found: {blob_id}") from e
            elif e.response.status_code == 403:
                raise AuthorizationError(f"Permission denied: {e.response.text}") from e
            elif e.response.status_code == 401:
                raise AuthorizationError(f"Authentication required: {e.response.text}") from e
            raise ValidationError(f"Failed to delete blob: {e.response.text}") from e


class AsyncAdminClient:
    """
    Async admin client for authenticating to the admin space and getting its ID.

    This client provides an async way to authenticate against the admin space
    without knowing its ID in advance. Once authenticated, use get_space_id()
    to obtain the admin space ID, then use a regular AsyncSpace client to perform
    admin operations.

    Attributes:
        keypair: Ed25519 key pair for authentication and signing
        base_url: Base URL of the reeeductio server
    """

    def __init__(
        self,
        keypair: Ed25519KeyPair,
        base_url: str = "http://localhost:8000",
        auto_authenticate: bool = True,
    ):
        """
        Initialize AsyncAdminClient.

        Args:
            keypair: Ed25519 key pair for authentication and signing
            base_url: Base URL of the reeeductio server
            auto_authenticate: Whether to authenticate automatically on first request
        """
        self.keypair = keypair
        self.base_url = base_url
        self._auto_authenticate = auto_authenticate

        self._token: str | None = None
        self._token_expires_at: int | None = None
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - close client."""
        await self.close()

    async def close(self):
        """Close the async HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def is_authenticated(self) -> bool:
        """Check if session has a valid token."""
        from datetime import datetime, timezone

        if not self._token:
            return False

        if self._token_expires_at:
            now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
            return now_ms < (self._token_expires_at - 60_000)

        return True

    @property
    def token(self) -> str | None:
        """Get the current JWT token, if authenticated."""
        return self._token

    async def authenticate(self) -> str:
        """
        Perform challenge-response authentication against the admin space.

        Returns:
            JWT bearer token

        Raises:
            AuthenticationError: If authentication fails
        """
        from .crypto import encode_base64, sign_data
        from .exceptions import AuthenticationError

        async with httpx.AsyncClient(base_url=self.base_url) as client:
            # Step 1: Request challenge
            try:
                response = await client.post(
                    "/admin/auth/challenge",
                    json={"public_key": self.keypair.to_user_id()},
                )
                response.raise_for_status()
                challenge_data = response.json()
            except httpx.HTTPStatusError as e:
                raise AuthenticationError(f"Failed to get admin challenge: {e.response.text}") from e
            except Exception as e:
                raise AuthenticationError(f"Failed to get admin challenge: {e}") from e

            # Step 2: Sign the challenge string (UTF-8 encoded, not base64-decoded)
            challenge_bytes = challenge_data["challenge"].encode("utf-8")
            signature = sign_data(challenge_bytes, self.keypair.private_key)

            # Step 3: Verify signature and get token
            try:
                response = await client.post(
                    "/admin/auth/verify",
                    json={
                        "public_key": self.keypair.to_user_id(),
                        "signature": encode_base64(signature),
                        "challenge": challenge_data["challenge"],
                    },
                )
                response.raise_for_status()
                token_data = response.json()
            except httpx.HTTPStatusError as e:
                raise AuthenticationError(f"Admin authentication failed: {e.response.text}") from e
            except Exception as e:
                raise AuthenticationError(f"Admin authentication failed: {e}") from e

            self._token = token_data["token"]
            self._token_expires_at = token_data["expires_at"]

            return self._token

    async def _ensure_authenticated(self) -> str:
        """Ensure we have a valid token."""
        if self.is_authenticated and self._token is not None:
            return self._token

        return await self.authenticate()

    async def get_client(self) -> httpx.AsyncClient:
        """
        Get authenticated async HTTP client.

        Returns:
            Authenticated httpx.AsyncClient

        Raises:
            AuthenticationError: If authentication fails
        """
        if self._auto_authenticate:
            token = await self._ensure_authenticated()
        elif self._token:
            token = self._token
        else:
            raise ValueError("Not authenticated. Call authenticate() or set auto_authenticate=True")

        if not self._client:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={"Authorization": f"Bearer {token}"},
            )
        else:
            self._client.headers["Authorization"] = f"Bearer {token}"

        return self._client

    async def get_space_id(self) -> str:
        """
        Get the admin space ID.

        This allows you to use a regular AsyncSpace client with the admin space ID
        to perform admin operations through the standard state and message endpoints.

        Returns:
            The admin space ID (44-char base64)

        Raises:
            AuthenticationError: If not authenticated or token is invalid
        """
        from .exceptions import AuthenticationError

        client = await self.get_client()
        try:
            response = await client.get("/admin/space")
            response.raise_for_status()
            return response.json()["space_id"]
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise AuthenticationError(f"Authentication required: {e.response.text}") from e
            raise AuthenticationError(f"Failed to get admin space ID: {e.response.text}") from e

    async def delete_blob(self, blob_id: str) -> None:
        """
        Delete a blob directly from the server's blob storage.

        This is an admin operation that bypasses normal space-scoped blob deletion,
        allowing removal of orphaned or problematic blobs.

        Args:
            blob_id: Typed blob identifier (44-char base64)

        Raises:
            NotFoundError: If blob not found
            AuthorizationError: If caller lacks admin permissions
        """
        from .exceptions import AuthorizationError, NotFoundError, ValidationError

        client = await self.get_client()
        try:
            response = await client.delete(f"/admin/blobs/{blob_id}")
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise NotFoundError(f"Blob not found: {blob_id}") from e
            elif e.response.status_code == 403:
                raise AuthorizationError(f"Permission denied: {e.response.text}") from e
            elif e.response.status_code == 401:
                raise AuthorizationError(f"Authentication required: {e.response.text}") from e
            raise ValidationError(f"Failed to delete blob: {e.response.text}") from e


class AsyncSpace:
    """
    Async client for interacting with a reeeductio space.

    Provides WebSocket streaming and async HTTP operations.

    Attributes:
        space_id: Typed space identifier
        member_id: Typed member identifier (U_... for users, T_... for tools)
        private_key: Raw 32-byte Ed25519 private key
        symmetric_root: 256-bit root key for HKDF derivation
        user_symmetric_key: Optional 256-bit user-private key (not shared with space)
        message_key: Derived key for message encryption (32 bytes)
        state_key: Derived key for state encryption (32 bytes)
        data_key: Derived key for data encryption (32 bytes)
        user_message_key: User-private message key (None if no user_symmetric_key)
        user_data_key: User-private data key (None if no user_symmetric_key)
        base_url: Base URL of the reeeductio server
        auth: Async authentication session manager
    """

    def __init__(
        self,
        space_id: str,
        member_id: str,
        private_key: bytes,
        symmetric_root: bytes,
        base_url: str = "http://localhost:8000",
        auto_authenticate: bool = True,
        local_store: LocalMessageStore | None = None,
        user_symmetric_key: bytes | None = None,
    ):
        """
        Initialize AsyncSpace client.

        Args:
            space_id: Typed space identifier (44-char base64)
            member_id: Typed member identifier (U_... for users, T_... for tools)
            private_key: Raw 32-byte Ed25519 private key for authentication and signing
            symmetric_root: 256-bit (32-byte) root key for HKDF key derivation
            base_url: Base URL of the reeeductio server
            auto_authenticate: Whether to authenticate automatically on first request
            local_store: Optional local message store for caching. When provided,
                messages are cached locally and retrieved from cache when available.
            user_symmetric_key: Optional 256-bit (32-byte) user-private key for
                encrypting data that is confidential against other space members.
                When provided, used to derive user_message_key and user_data_key
                for user-private encryption.

        Raises:
            ValueError: If symmetric_root is not exactly 32 bytes
            ValueError: If user_symmetric_key is provided but not exactly 32 bytes
        """
        if len(symmetric_root) != 32:
            raise ValueError(f"symmetric_root must be exactly 32 bytes, got {len(symmetric_root)}")
        if user_symmetric_key is not None and len(user_symmetric_key) != 32:
            raise ValueError(f"user_symmetric_key must be exactly 32 bytes, got {len(user_symmetric_key)}")

        self.space_id = space_id
        self.member_id = member_id
        self.private_key = private_key
        self.symmetric_root = symmetric_root
        self.user_symmetric_key = user_symmetric_key
        self.base_url = base_url
        self._auto_authenticate = auto_authenticate
        self._local_store = local_store

        # Derive encryption keys from symmetric_root using HKDF
        self.message_key = derive_key(symmetric_root, f"message key | {space_id}")
        self.data_key = derive_key(symmetric_root, f"data key | {space_id}")
        self.state_key = derive_key(self.message_key, "topic key | state")

        # Derive user-private encryption keys if a user_symmetric_key was provided.
        # These are confidential against other space members (including admins) because
        # user_symmetric_key is not shared with the space.
        if user_symmetric_key is not None:
            self.user_message_key: bytes | None = derive_key(user_symmetric_key, f"user message key | {space_id}")
            self.user_data_key: bytes | None = derive_key(user_symmetric_key, f"user data key | {space_id}")
        else:
            self.user_message_key = None
            self.user_data_key = None

        # Create async authentication session
        self.auth = AsyncAuthSession(
            space_id=space_id,
            public_key_typed=member_id,
            private_key=private_key,
            base_url=base_url,
        )

        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - close client."""
        await self.close()

    async def close(self):
        """Close the async HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get_client(self) -> httpx.AsyncClient:
        """
        Get authenticated async HTTP client, ensuring valid authentication.

        Returns:
            Authenticated httpx.AsyncClient

        Raises:
            AuthenticationError: If authentication fails
        """
        if self._auto_authenticate:
            token = await self.auth.ensure_authenticated()
        elif self.auth.token:
            token = self.auth.token
        else:
            raise ValueError("Not authenticated. Call authenticate() or set auto_authenticate=True")

        if not self._client:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={"Authorization": f"Bearer {token}"},
            )
        else:
            self._client.headers["Authorization"] = f"Bearer {token}"

        return self._client

    async def authenticate(self) -> str:
        """
        Perform authentication.

        Returns:
            JWT bearer token
        """
        return await self.auth.authenticate()

    # ============================================================
    # WebSocket Streaming
    # ============================================================

    def _get_websocket_url(self) -> str:
        """Convert HTTP base URL to WebSocket URL."""
        ws_url = self.base_url.replace("http://", "ws://").replace("https://", "wss://")
        return f"{ws_url}/spaces/{self.space_id}/stream"

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[ClientConnection]:
        """
        Connect to the space's WebSocket stream.

        Yields a WebSocket connection that receives real-time messages.

        Usage:
            async with space.connect() as ws:
                async for message in ws:
                    data = json.loads(message)
                    print(data)

        Yields:
            WebSocket connection

        Raises:
            StreamError: If connection fails
            AuthenticationError: If authentication fails
        """
        token = await self.auth.ensure_authenticated()
        ws_url = f"{self._get_websocket_url()}?token={token}"

        try:
            async with websockets.connect(ws_url) as ws:
                yield ws
        except websockets.ConnectionClosedError as e:
            raise StreamError(f"WebSocket connection closed: {e}") from e
        except Exception as e:
            raise StreamError(f"WebSocket error: {e}") from e

    async def stream(self, include_pings: bool = False) -> AsyncIterator[dict[str, Any]]:
        """
        Stream messages from the space in real-time.

        This is a convenience method that connects to the WebSocket and
        yields parsed message dictionaries.

        Args:
            include_pings: If True, yield server ping messages. Default False.

        Yields:
            Message dictionaries with keys like:
            - message_hash: Typed message identifier
            - topic_id: Topic the message was posted to
            - type: Message type
            - data: Base64-encoded message data
            - sender: Typed user identifier
            - signature: Base64-encoded signature
            - server_timestamp: Server timestamp in milliseconds

        Raises:
            StreamError: If connection fails or is lost
            AuthenticationError: If authentication fails

        Example:
            async for msg in space.stream():
                print(f"New message in {msg['topic_id']}: {msg['message_hash']}")
        """
        async with self.connect() as ws:
            async for raw_message in ws:
                try:
                    data = json.loads(raw_message)

                    # Filter out ping messages unless requested
                    if data.get("type") == "ping" and not include_pings:
                        continue

                    yield data
                except json.JSONDecodeError:
                    # Handle non-JSON messages (like "pong")
                    continue

    async def stream_messages(self) -> AsyncIterator[Message]:
        """
        Stream messages from the space as Message objects.

        Like stream(), but returns parsed Message model instances.
        Only yields actual messages (not pings or other control messages).

        Yields:
            Message objects

        Raises:
            StreamError: If connection fails or is lost
            AuthenticationError: If authentication fails

        Example:
            async for msg in space.stream_messages():
                print(f"Message {msg.message_hash} from {msg.sender}")
        """
        async for data in self.stream(include_pings=False):
            # Only yield if it looks like a message (has message_hash)
            if "message_hash" in data:
                yield Message(**data)

    # ============================================================
    # Async Message Operations
    # ============================================================

    async def get_messages(
        self,
        topic_id: str,
        from_timestamp: int | None = None,
        to_timestamp: int | None = None,
        limit: int = 100,
        use_cache: bool = True,
        validate_chain: bool = True,
    ) -> list[Message]:
        """
        Get messages from a topic.

        When a local_store is configured and use_cache is True, this method:
        1. Checks if cached data might be stale (to_timestamp > latest cached)
        2. Fetches newer messages from server if needed
        3. Validates message hashes and chain integrity
        4. Fetches gap-filling messages if there's a gap between cached and new
        5. Merges server results with cached data
        6. Caches any new messages

        Args:
            topic_id: Topic identifier
            from_timestamp: Optional start timestamp (milliseconds)
            to_timestamp: Optional end timestamp (milliseconds)
            limit: Maximum number of messages to return
            use_cache: Whether to use local cache (default True)
            validate_chain: Whether to validate chain integrity (default True)

        Returns:
            List of messages

        Raises:
            ChainError: If chain validation fails
        """
        if not use_cache or self._local_store is None:
            server_messages = await self._fetch_messages_from_server(
                topic_id, from_timestamp, to_timestamp, limit
            )
            if validate_chain and server_messages:
                self._validate_and_verify_messages(topic_id, server_messages)
            return server_messages

        # Get cached messages and latest cached timestamp
        cached = self._local_store.get_messages(
            self.space_id, topic_id, from_timestamp, to_timestamp, limit
        )
        latest_cached_ts = self._local_store.get_latest_timestamp(self.space_id, topic_id)

        # Determine if we need to fetch from server
        need_server_fetch = (
            to_timestamp is None
            or latest_cached_ts is None
            or to_timestamp > latest_cached_ts
        )

        if not need_server_fetch and cached:
            return cached

        # Fetch from server - either everything or just newer messages
        server_from = from_timestamp
        if latest_cached_ts is not None and cached:
            server_from = latest_cached_ts + 1

        server_messages = await self._fetch_messages_from_server(
            topic_id, server_from, to_timestamp, limit
        )

        if not server_messages:
            return cached

        # Validate hashes of all new messages
        if validate_chain:
            for msg in server_messages:
                if not verify_message_hash(self.space_id, msg):
                    raise ChainError(
                        f"Message hash verification failed for {msg.message_hash}"
                    )

        # Check for gap between cached and new messages
        if validate_chain and cached:
            server_messages.sort(key=lambda m: m.server_timestamp)
            oldest_new = server_messages[0]
            latest_cached = max(cached, key=lambda m: m.server_timestamp)

            if oldest_new.prev_hash is not None and oldest_new.prev_hash != latest_cached.message_hash:
                # Gap detected - fetch missing messages
                gap_messages = await self._fetch_gap_messages(
                    topic_id, latest_cached.message_hash, oldest_new.prev_hash
                )
                if gap_messages:
                    server_messages = gap_messages + server_messages

        # Validate chain integrity if we have both cached and new messages
        if validate_chain and cached and server_messages:
            latest_cached = max(cached, key=lambda m: m.server_timestamp)
            if not validate_message_chain_with_anchor(
                self.space_id, server_messages, latest_cached.message_hash
            ):
                server_messages.sort(key=lambda m: m.server_timestamp)
                if server_messages[0].prev_hash is not None:
                    raise ChainError(
                        f"Chain validation failed: new messages don't link to cached chain"
                    )

        # Cache new messages (they've been validated)
        self._local_store.put_messages(self.space_id, server_messages)

        # Merge cached and server messages, deduplicate by hash
        seen_hashes = set()
        merged = []
        for msg in cached + server_messages:
            if msg.message_hash not in seen_hashes:
                seen_hashes.add(msg.message_hash)
                merged.append(msg)
        merged.sort(key=lambda m: m.server_timestamp)
        return merged[:limit]

    def _validate_and_verify_messages(
        self, topic_id: str, messages_list: list[Message]
    ) -> None:
        """Validate message hashes and chain for messages without cache."""
        for msg in messages_list:
            if not verify_message_hash(self.space_id, msg):
                raise ChainError(
                    f"Message hash verification failed for {msg.message_hash}"
                )

        messages_list.sort(key=lambda m: m.server_timestamp)
        if messages_list:
            anchor = messages_list[0].prev_hash
            if not validate_message_chain_with_anchor(self.space_id, messages_list, anchor):
                raise ChainError("Chain validation failed: messages don't form valid chain")

    async def _fetch_gap_messages(
        self,
        topic_id: str,
        cached_head_hash: str,
        target_prev_hash: str,
        max_iterations: int = 10,
    ) -> list[Message]:
        """
        Fetch messages to fill gap between cached head and new messages.

        Walks backwards from target_prev_hash until we reach cached_head_hash
        or the start of the topic.
        """
        gap_messages = []
        current_hash = target_prev_hash

        for _ in range(max_iterations):
            if current_hash is None or current_hash == cached_head_hash:
                break

            try:
                msg = await self._fetch_message_by_hash(topic_id, current_hash)
                if msg is None:
                    break
                gap_messages.insert(0, msg)
                current_hash = msg.prev_hash
            except Exception:
                break

        return gap_messages

    async def _fetch_message_by_hash(self, topic_id: str, message_hash: str) -> Message | None:
        """Fetch a single message by hash from server."""
        try:
            client = await self.get_client()
            response = await client.get(
                f"/spaces/{self.space_id}/topics/{topic_id}/messages/{message_hash}"
            )
            response.raise_for_status()
            data = response.json()
            return Message(**data)
        except httpx.HTTPStatusError:
            return None
        except Exception:
            return None

    async def _fetch_messages_from_server(
        self,
        topic_id: str,
        from_timestamp: int | None = None,
        to_timestamp: int | None = None,
        limit: int = 100,
    ) -> list[Message]:
        """Fetch messages directly from server without caching."""
        client = await self.get_client()
        return await messages.get_messages_async(
            client=client,
            space_id=self.space_id,
            topic_id=topic_id,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
            limit=limit,
        )

    async def post_message(
        self,
        topic_id: str,
        msg_type: str,
        data: bytes,
        prev_hash: str | None = None,
    ) -> MessageCreated:
        """
        Post a message to a topic.

        Args:
            topic_id: Topic identifier
            msg_type: Message type/category
            data: Message data (will be base64-encoded)
            prev_hash: Hash of previous message (optional, fetched if not provided)

        Returns:
            MessageCreated with message_hash and server_timestamp
        """
        if prev_hash is None:
            far_future = 9999999999999
            msgs = await self.get_messages(topic_id, from_timestamp=far_future, to_timestamp=0, limit=1)
            prev_hash = msgs[0].message_hash if msgs else None

        client = await self.get_client()
        return await messages.post_message_async(
            client=client,
            space_id=self.space_id,
            topic_id=topic_id,
            msg_type=msg_type,
            data=data,
            prev_hash=prev_hash,
            sender_public_key_typed=self.member_id,
            sender_private_key=self.private_key,
        )

    def derive_topic_key(self, topic_id: str) -> bytes:
        """
        Derive the encryption key for a topic.

        Args:
            topic_id: Topic identifier

        Returns:
            32-byte AES-256 topic key
        """
        return derive_key(self.message_key, f"topic key | {topic_id}")

    async def post_encrypted_message(
        self,
        topic_id: str,
        msg_type: str,
        data: bytes,
        prev_hash: str | None = None,
    ) -> MessageCreated:
        """
        Encrypt and post a message to a topic.

        Encrypts the plaintext with the derived key for the given topic,
        then posts the ciphertext.

        Args:
            topic_id: Topic identifier
            msg_type: Message type/category
            data: Plaintext message data to encrypt
            prev_hash: Hash of previous message (optional, fetched if not provided)

        Returns:
            MessageCreated with message_hash and server_timestamp
        """
        topic_key = self.derive_topic_key(topic_id)
        encrypted = encrypt_aes_gcm(data, topic_key)
        return await self.post_message(topic_id, msg_type, encrypted, prev_hash)

    def decrypt_message_data(self, msg: Message, topic_id: str) -> bytes:
        """
        Decrypt the data payload of an encrypted message.

        Derives the topic key and decrypts the message's base64-encoded data.

        Args:
            msg: Message with encrypted data payload
            topic_id: Topic identifier used to derive the decryption key

        Returns:
            Decrypted plaintext bytes
        """
        topic_key = self.derive_topic_key(topic_id)
        return messages.decrypt_message_data(msg, topic_key)

    # ============================================================
    # Async State Operations
    # ============================================================

    async def get_plaintext_state(self, path: str) -> str:
        """
        Get current state value at path.

        Args:
            path: State path

        Returns:
            Plaintext state data
        """
        client = await self.get_client()
        message = await state.get_state_async(client, self.space_id, path)
        return base64.b64decode(message.data).decode("utf-8")

    async def get_encrypted_state(self, path: str, key: bytes | None = None) -> str:
        """
        Get encrypted state value at path and decrypt it.

        Args:
            path: State path
            key: Decryption key. Defaults to self.state_key if not provided.

        Returns:
            Decrypted plaintext string
        """
        client = await self.get_client()
        message = await state.get_state_async(client, self.space_id, path)

        encrypted_b64 = message.data
        if len(encrypted_b64) == 0:
            return ""

        encrypted_bytes = base64.b64decode(encrypted_b64)
        plaintext_bytes = decrypt_aes_gcm(encrypted_bytes, key if key is not None else self.state_key)
        return plaintext_bytes.decode("utf-8")

    async def set_plaintext_state(self, path: str, data: str, prev_hash: str | None = None) -> MessageCreated:
        """
        Set plaintext state value at path.

        Args:
            path: State path
            data: Plaintext string data to store
            prev_hash: Previous message hash (optional, fetched if not provided)

        Returns:
            MessageCreated with message_hash and server_timestamp
        """
        data_bytes = data.encode("utf-8")
        return await self._set_state(path, data_bytes, prev_hash)

    async def set_encrypted_state(self, path: str, data: str, prev_hash: str | None = None, key: bytes | None = None) -> MessageCreated:
        """
        Set encrypted state value at path.

        Args:
            path: State path
            data: Plaintext string data to encrypt and store
            prev_hash: Previous message hash (optional, fetched if not provided)
            key: Encryption key. Defaults to self.state_key if not provided.

        Returns:
            MessageCreated with message_hash and server_timestamp
        """
        plaintext_bytes = data.encode("utf-8")
        encrypted_bytes = encrypt_aes_gcm(plaintext_bytes, key if key is not None else self.state_key)
        return await self._set_state(path, encrypted_bytes, prev_hash)

    async def _set_state(self, path: str, data: bytes, prev_hash: str | None = None) -> MessageCreated:
        """Internal: set state value at path."""
        if prev_hash is None:
            far_future = 9999999999999
            msgs = await self.get_messages("state", from_timestamp=far_future, to_timestamp=0, limit=1)
            prev_hash = msgs[0].message_hash if msgs else None

        client = await self.get_client()
        return await state.set_state_async(
            client=client,
            space_id=self.space_id,
            path=path,
            data=data,
            prev_hash=prev_hash,
            sender_public_key_typed=self.member_id,
            sender_private_key=self.private_key,
        )

    async def get_state_history(
        self,
        from_timestamp: int | None = None,
        to_timestamp: int | None = None,
        limit: int = 100,
    ) -> list[Message]:
        """
        Get all state change messages (event log).

        Args:
            from_timestamp: Optional start timestamp (milliseconds)
            to_timestamp: Optional end timestamp (milliseconds)
            limit: Maximum number of messages to return

        Returns:
            List of state change messages
        """
        client = await self.get_client()
        return await state.get_state_history_async(
            client, self.space_id, from_timestamp, to_timestamp, limit
        )

    # ============================================================
    # Async Blob Operations
    # ============================================================

    async def upload_plaintext_blob(self, data: bytes) -> BlobCreated:
        """Upload plaintext blob."""
        client = await self.get_client()
        return await blobs.upload_blob_async(client, self.space_id, data)

    async def encrypt_and_upload_blob(self, data: bytes) -> EncryptedBlobCreated:
        """
        Encrypt and upload a blob.

        Generates a random AES-256 data encryption key (DEK), encrypts the data
        using AES-GCM-256, and uploads the encrypted blob.

        Returns:
            EncryptedBlobCreated with blob_id, size, and the generated DEK
        """
        client = await self.get_client()
        return await blobs.encrypt_and_upload_blob_async(client, self.space_id, data)

    async def download_plaintext_blob(self, blob_id: str) -> bytes:
        """Download plaintext blob."""
        client = await self.get_client()
        return await blobs.download_blob_async(client, self.space_id, blob_id)

    async def download_and_decrypt_blob(self, blob_id: str, key: bytes) -> bytes:
        """
        Download and decrypt encrypted blob.

        Args:
            blob_id: Typed blob identifier
            key: 32-byte AES-256 data encryption key (DEK) returned by encrypt_and_upload_blob()

        Returns:
            Decrypted plaintext blob data
        """
        client = await self.get_client()
        encrypted_data = await blobs.download_blob_async(client, self.space_id, blob_id)
        return decrypt_aes_gcm(encrypted_data, key)

    async def delete_blob(self, blob_id: str) -> None:
        """Delete blob."""
        client = await self.get_client()
        await blobs.delete_blob_async(client, self.space_id, blob_id)

    # ============================================================
    # Async Key-Value Data Operations
    # ============================================================

    async def get_plaintext_data(self, path: str) -> bytes:
        """Get plaintext data value at path."""
        client = await self.get_client()
        entry = await kvdata.get_data_async(client, self.space_id, path)
        return base64.b64decode(entry.data)

    async def get_encrypted_data(self, path: str, key: bytes | None = None) -> bytes:
        """
        Get encrypted data value at path and decrypt it.

        Args:
            path: Data path
            key: Decryption key. Defaults to self.data_key if not provided.
        """
        client = await self.get_client()
        entry = await kvdata.get_data_async(client, self.space_id, path)
        encrypted_bytes = base64.b64decode(entry.data)
        return decrypt_aes_gcm(encrypted_bytes, key if key is not None else self.data_key)

    async def set_plaintext_data(self, path: str, data: bytes) -> int:
        """Set plaintext data value at path."""
        return await self._set_data(path, data)

    async def set_encrypted_data(self, path: str, data: bytes, key: bytes | None = None) -> int:
        """
        Set encrypted data value at path.

        Args:
            path: Data path
            data: Plaintext data bytes to encrypt and store
            key: Encryption key. Defaults to self.data_key if not provided.
        """
        encrypted_bytes = encrypt_aes_gcm(data, key if key is not None else self.data_key)
        return await self._set_data(path, encrypted_bytes)

    async def get_encrypted_user_data(self, path: str) -> bytes:
        """
        Get user-private encrypted data at a path relative to this user's namespace.

        Reads from ``user/{member_id}/{path}`` and decrypts with self.user_data_key,
        which is confidential against other space members and the server.

        Args:
            path: Relative data path (e.g., "notes", "settings/theme")

        Returns:
            Decrypted plaintext data bytes

        Raises:
            ValueError: If user_symmetric_key was not provided to the Space constructor
            NotFoundError: If no data exists at this path
            cryptography.exceptions.InvalidTag: If decryption fails
        """
        if self.user_data_key is None:
            raise ValueError("user_symmetric_key is required for user-private encryption")
        return await self.get_encrypted_data(f"user/{self.member_id}/{path}", key=self.user_data_key)

    async def set_encrypted_user_data(self, path: str, data: bytes) -> int:
        """
        Store user-private encrypted data at a path relative to this user's namespace.

        Encrypts with self.user_data_key (confidential against other space members and
        the server) and stores at ``user/{member_id}/{path}``.

        Args:
            path: Relative data path (e.g., "notes", "settings/theme")
            data: Plaintext data bytes to encrypt and store

        Returns:
            Timestamp when the data was signed (milliseconds)

        Raises:
            ValueError: If user_symmetric_key was not provided to the Space constructor
        """
        if self.user_data_key is None:
            raise ValueError("user_symmetric_key is required for user-private encryption")
        return await self.set_encrypted_data(f"user/{self.member_id}/{path}", data, key=self.user_data_key)

    async def _set_data(self, path: str, data: bytes) -> int:
        """Internal: set data value at path."""
        client = await self.get_client()
        return await kvdata.set_data_async(
            client=client,
            space_id=self.space_id,
            path=path,
            data=data,
            signed_by=self.member_id,
            private_key=self.private_key,
        )

    # ============================================================
    # Authorization Utilities
    # ============================================================

    async def create_role(self, role_name: str, description: str | None = None) -> MessageCreated:
        """
        Create a role in the space.

        Roles are stored at auth/roles/{role_name} and can have capabilities
        granted to them via grant_capability_to_role().

        Args:
            role_name: Name of the role to create
            description: Optional description of the role

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If role creation fails
        """
        role_data = {
            "role_id": role_name,
        }
        if description:
            role_data["description"] = description

        return await self.set_plaintext_state(
            f"auth/roles/{role_name}",
            json.dumps(role_data),
        )

    async def add_user(self, user_id: str, description: str | None = None) -> MessageCreated:
        """
        Add a user entry in the space.

        Users are stored at auth/users/{user_id} and can have capabilities
        granted to them via grant_capability_to_user().

        Args:
            user_id: Typed user identifier (U_...)
            description: Optional description of the user

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If user creation fails
        """
        user_data = {
            "user_id": user_id,
        }
        if description:
            user_data["description"] = description

        return await self.set_plaintext_state(
            f"auth/users/{user_id}",
            json.dumps(user_data),
        )

    async def create_tool(self, tool_id: str, description: str | None = None) -> MessageCreated:
        """
        Create a tool entry in the space.

        Tools are stored at auth/tools/{tool_id} and can have capabilities
        granted to them via grant_capability_to_tool().

        Args:
            tool_id: Typed tool identifier (T_...)
            description: Optional description of the tool

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If tool creation fails
        """
        tool_data = {
            "tool_id": tool_id,
        }
        if description:
            tool_data["description"] = description

        return await self.set_plaintext_state(
            f"auth/tools/{tool_id}",
            json.dumps(tool_data),
        )

    async def grant_capability_to_role(
        self,
        role_name: str,
        cap_id: str,
        capability: dict,
    ) -> MessageCreated:
        """
        Grant a capability to a role.

        Capabilities are stored at auth/roles/{role_name}/rights/{cap_id}.

        Args:
            role_name: Name of the role to grant the capability to
            cap_id: Capability ID
            capability: Capability dict with 'op' and 'path' keys

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If capability creation fails
        """
        return await self.set_plaintext_state(
            f"auth/roles/{role_name}/rights/{cap_id}",
            json.dumps(capability),
        )

    async def assign_role_to_user(self, user_id: str, role_name: str) -> MessageCreated:
        """
        Assign a role to a user.

        Role assignments are stored at auth/users/{user_id}/roles/{role_name}.

        Args:
            user_id: Typed user identifier (U_...)
            role_name: Name of the role to assign

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If role assignment fails
        """
        assignment_data = {
            "user_id": user_id,
            "role_id": role_name,
        }

        return await self.set_plaintext_state(
            f"auth/users/{user_id}/roles/{role_name}",
            json.dumps(assignment_data),
        )

    async def grant_capability_to_user(
        self,
        user_id: str,
        cap_id: str,
        capability: dict,
    ) -> MessageCreated:
        """
        Grant a capability to a user.

        Capabilities are stored at auth/users/{user_id}/rights/{cap_id}.

        Args:
            user_id: Typed user identifier (U_...)
            cap_id: Capability ID
            capability: Capability dict with 'op' and 'path' keys

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If capability creation fails
        """
        return await self.set_plaintext_state(
            f"auth/users/{user_id}/rights/{cap_id}",
            json.dumps(capability),
        )

    async def grant_capability_to_tool(
        self,
        tool_id: str,
        cap_id: str,
        capability: dict,
    ) -> MessageCreated:
        """
        Grant a capability to a tool.

        Capabilities are stored at auth/tools/{tool_id}/rights/{cap_id}.

        Args:
            tool_id: Typed tool identifier (T_...)
            cap_id: Capability ID
            capability: Capability dict with 'op' and 'path' keys

        Returns:
            MessageCreated with message_hash and server_timestamp

        Raises:
            ValidationError: If capability creation fails
        """
        return await self.set_plaintext_state(
            f"auth/tools/{tool_id}/rights/{cap_id}",
            json.dumps(capability),
        )

    async def create_invitation(self, description: str | None = None) -> Ed25519KeyPair:
        """
        Create an invitation tool that can add a new user to the space.

        Generates a new keypair, creates a tool entry for it, and grants
        the tool capabilities to create a user and assign them the "user" role.

        Args:
            description: Optional description of the invitation

        Returns:
            Ed25519KeyPair for the invitation tool. The recipient will use this
            keypair to authenticate and add themselves to the space.

        Raises:
            ValidationError: If tool or capability creation fails
        """
        keypair = generate_keypair()
        tool_id = keypair.to_tool_id()

        await self.create_tool(tool_id, description=description)
        await self.grant_capability_to_tool(
            tool_id,
            "can_create_user",
            {"op": "create", "path": "state/auth/users/{any}"},
        )
        await self.grant_capability_to_tool(
            tool_id,
            "can_grant_user_role",
            {"op": "create", "path": "state/auth/users/{any}/roles/user"},
        )

        return keypair

    # ============================================================
    # OPAQUE Password-Based Key Recovery
    # ============================================================

    async def opaque_register(
        self,
        username: str,
        password: str,
        user_id: str | None = None,
        private_key: bytes | None = None,
    ) -> str:
        """
        Register OPAQUE credentials for password-based login.

        After registration, the user can recover their keypair and symmetric_root
        by logging in with their username and password using opaque_login_async().

        This method requires authentication (auto-authenticates if enabled).

        Uses the opaque_snake library for the OPAQUE protocol.

        Args:
            username: OPAQUE username (must be unique within the space)
            password: Password for future logins
            user_id: Typed identifier string (USER or TOOL) for the public key.
                If None, uses self.member_id.
            private_key: 32-byte Ed25519 private key matching user_id.
                If None, uses self.private_key.

        Returns:
            The username that was registered

        Raises:
            OpaqueNotEnabledError: If OPAQUE is not enabled for this space
            OpaqueError: If registration fails
            ValidationError: If username already exists or user_id doesn't match private_key

        Example:
            async with AsyncSpace(space_id, member_id, private_key, symmetric_root, base_url) as space:
                await space.opaque_register("alice", "my-secure-password")

                # Register with a tool key
                await space.opaque_register("tool-alice", "tool-password",
                                            user_id=tool_keypair.to_tool_id(),
                                            private_key=tool_keypair.private_key)

            # Later, recover credentials with password
            from reeeductio import opaque_login_async
            credentials = await opaque_login_async(base_url, space_id, "alice", "my-secure-password")
        """
        from .opaque import opaque_register_async as _opaque_register_async

        # Use provided values or derive from self
        if user_id is None:
            user_id = self.member_id
        if private_key is None:
            private_key = self.private_key

        client = await self.get_client()
        return await _opaque_register_async(
            client=client,
            space_id=self.space_id,
            username=username,
            password=password,
            user_id=user_id,
            private_key=private_key,
            symmetric_root=self.symmetric_root,
        )

    async def enable_opaque(self) -> dict[str, bool]:
        """
        Enable OPAQUE for this space.

        Sets up the OPAQUE server configuration and creates the opaque-user role
        with the necessary permissions. This must be called by an admin before
        users can register OPAQUE credentials.

        This method:
        1. Creates OPAQUE server setup if it doesn't exist (stored in data)
        2. Creates opaque-user role if it doesn't exist (stored in state)
        3. Adds CREATE capability for opaque/users/{any} if missing

        Returns:
            Dict with keys indicating what was created:
            - server_setup_created: True if new server setup was uploaded
            - role_created: True if opaque-user role was created
            - capability_created: True if CREATE capability was added

        Raises:
            ValidationError: If operation fails (usually due to insufficient permissions)

        Example:
            async with AsyncSpace(space_id, member_id, private_key, symmetric_root, base_url) as space:
                result = await space.enable_opaque()
                if result["server_setup_created"]:
                    print("OPAQUE server setup created")
        """
        from .opaque import (
            OPAQUE_SERVER_SETUP_PATH,
            OPAQUE_USER_ROLE_ID,
            OPAQUE_USER_CAP_ID,
        )

        # Import OpaqueServer only after checking availability
        from opaque_snake import OpaqueServer

        result = {
            "server_setup_created": False,
            "role_created": False,
            "capability_created": False,
        }

        # Step 1: Check/create OPAQUE server setup (stored in data store)
        try:
            await self.get_plaintext_data(OPAQUE_SERVER_SETUP_PATH)
            # Server setup exists
        except NotFoundError:
            # Create new server setup
            server = OpaqueServer()
            setup_bytes = server.export_setup()
            await self.set_plaintext_data(OPAQUE_SERVER_SETUP_PATH, setup_bytes)
            result["server_setup_created"] = True

        # Step 2: Check/create opaque-user role (stored in state)
        try:
            await self.get_plaintext_state(f"auth/roles/{OPAQUE_USER_ROLE_ID}")
            # Role exists
        except NotFoundError:
            await self.create_role(
                OPAQUE_USER_ROLE_ID,
                description="Role for users who can register OPAQUE credentials",
            )
            result["role_created"] = True

        # Step 3: Check/create CREATE capability for opaque/users/{any}
        cap_path = f"auth/roles/{OPAQUE_USER_ROLE_ID}/rights/{OPAQUE_USER_CAP_ID}"
        try:
            await self.get_plaintext_state(cap_path)
            # Capability exists
        except NotFoundError:
            await self.grant_capability_to_role(
                OPAQUE_USER_ROLE_ID,
                OPAQUE_USER_CAP_ID,
                {"op": "create", "path": "data/opaque/users/{any}"},
            )
            result["capability_created"] = True

        return result


class AsyncAdminSpace(AsyncSpace):
    """
    Async client for interacting with the admin space to create new spaces.

    Extends AsyncSpace with the ability to register new spaces in the admin space.
    The admin space is a special space that stores the registry of all spaces
    and their creators.

    Example:
        async with AsyncAdminSpace(
            space_id=admin_space_id,
            member_id=user_keypair.to_user_id(),
            private_key=user_keypair.private_key,
            symmetric_root=admin_symmetric_root,
            base_url=base_url,
        ) as admin_space:
            # Generate keypair for new space
            new_space_keypair = generate_keypair()

            # Register the space in the admin space
            space_id = await admin_space.create_space(new_space_keypair)
    """

    async def create_space(self, space_keypair: Ed25519KeyPair) -> str:
        """
        Create and register a new space in the admin space.

        This method:
        1. Derives the space_id from the space keypair's public key
        2. Creates a registration data structure with space_signature proving ownership
        3. Writes the registration to spaces/{space_id} in the admin space
        4. Indexes the space at users/{user_id}/spaces/{space_id}

        Args:
            space_keypair: Ed25519 keypair for the new space. The caller must
                          retain this keypair to access the space later.

        Returns:
            The space_id of the newly created space

        Raises:
            ValidationError: If space registration fails
        """
        from datetime import datetime, timezone

        from .crypto import encode_base64, sign_data

        # Derive space_id from the space keypair
        space_id = space_keypair.to_space_id()

        # Get the member_id of the caller (who is creating the space)
        created_by = self.member_id

        # Get current timestamp in milliseconds
        created_at = int(datetime.now(timezone.utc).timestamp() * 1000)

        # Create the canonical message to sign: {space_id}|{created_by}|{created_at}
        canonical_message = f"{space_id}|{created_by}|{created_at}"

        # Sign with the space's private key to prove ownership
        signature = sign_data(canonical_message.encode("utf-8"), space_keypair.private_key)
        space_signature = encode_base64(signature)

        # Create the registration data
        registration_data = {
            "space_id": space_id,
            "created_by": created_by,
            "created_at": created_at,
            "space_signature": space_signature,
        }

        # Write to spaces/{space_id} in the admin space
        await self.set_plaintext_state(f"spaces/{space_id}", json.dumps(registration_data))

        # Index the space at users/{user_id}/spaces/{space_id}
        index_data = {"space_id": space_id}
        await self.set_plaintext_state(f"users/{created_by}/spaces/{space_id}", json.dumps(index_data))

        return space_id
