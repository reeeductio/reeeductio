"""
Channel - Core business logic for a single channel

This class encapsulates all channel operations including state management,
message handling, and WebSocket connections. It's designed to be:
- Framework-agnostic (works with FastAPI, Durable Objects, etc.)
- Self-contained (manages its own storage)
- Thread-safe for multi-worker deployments
"""

import asyncio
import time
from pathlib import Path
from typing import Optional, List, Dict, Any, Set
from fastapi import WebSocket
import json

from sqlite_state_store import SqliteStateStore
from sqlite_message_store import SqliteMessageStore
from crypto import CryptoUtils
from blob_store import BlobStore
from authorization import AuthorizationEngine
from identifiers import extract_public_key
import secrets
import jwt


class Channel:
    """
    Represents a single channel with its state, messages, and connections.

    Each channel instance manages:
    - State storage (members, capabilities, metadata)
    - Message storage (per-topic message chains)
    - Active WebSocket connections
    - Authorization logic

    Can be used in:
    - FastAPI with per-channel instances
    - Durable Objects (TypeScript port)
    - Other frameworks
    """

    def __init__(
        self,
        channel_id: str,
        storage_dir: Optional[str] = None,
        state_store: Optional[SqliteStateStore] = None,
        message_store: Optional[SqliteMessageStore] = None,
        blob_store: Optional[BlobStore] = None,
        jwt_secret: Optional[str] = None,
        jwt_algorithm: str = "HS256",
        jwt_expiry_hours: int = 24
    ):
        """
        Initialize a Channel instance.

        Args:
            channel_id: Unique channel identifier
            storage_dir: Directory for this channel's databases (if not providing stores)
            state_store: Optional pre-configured state store
            message_store: Optional pre-configured message store
            blob_store: Optional blob store (shared across channels for deduplication)
            jwt_secret: JWT signing secret (shared across all channels for consistency)
            jwt_algorithm: JWT signing algorithm
            jwt_expiry_hours: JWT token expiry in hours
        """
        self.channel_id = channel_id
        self.blob_store = blob_store

        # JWT configuration
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.jwt_expiry_hours = jwt_expiry_hours

        # Initialize or use provided stores
        if state_store and message_store:
            self.state_store = state_store
            self.message_store = message_store
        else:
            # Create per-channel databases
            if storage_dir is None:
                storage_dir = f"channels/ch_{channel_id}"

            storage_path = Path(storage_dir)
            storage_path.mkdir(parents=True, exist_ok=True)

            self.state_store = SqliteStateStore(str(storage_path / "state.db"))
            self.message_store = SqliteMessageStore(str(storage_path / "messages.db"))

        # Initialize crypto and authorization
        self.crypto = CryptoUtils()
        self.authz = AuthorizationEngine(self.state_store, self.crypto)

        # WebSocket connections for this channel
        self.websockets: Set[WebSocket] = set()

        # In-memory challenge storage (for authentication)
        # In production, store in Redis with TTL
        self.challenges: Dict[str, Dict[str, Any]] = {}

    # ========================================================================
    # Authentication Operations
    # ========================================================================

    def create_challenge(self, public_key: str, expiry_seconds: int = 300) -> Dict[str, Any]:
        """
        Create an authentication challenge for a user.

        Args:
            public_key: User's public key identifier
            expiry_seconds: Challenge validity in seconds

        Returns:
            Dictionary with challenge and expires_at
        """
        challenge_bytes = secrets.token_bytes(32)
        challenge = self.crypto.base64_encode(challenge_bytes)
        expires_at = int(time.time() * 1000) + (expiry_seconds * 1000)

        challenge_key = public_key
        self.challenges[challenge_key] = {
            "challenge": challenge,
            "expires_at": expires_at
        }

        return {
            "challenge": challenge,
            "expires_at": expires_at
        }

    def verify_challenge(
        self,
        public_key: str,
        challenge: str,
        signature: str
    ) -> bool:
        """
        Verify a signed challenge for authentication.

        Args:
            public_key: User's public key identifier
            challenge: The challenge string to verify
            signature: Base64-encoded signature of the challenge

        Returns:
            True if verification succeeds

        Raises:
            ValueError: If challenge not found, expired, or signature invalid
        """
        challenge_key = public_key

        # Check if challenge exists
        if challenge_key not in self.challenges:
            raise ValueError("Challenge not found")

        stored = self.challenges[challenge_key]

        # Check if expired
        if stored["expires_at"] < int(time.time() * 1000):
            del self.challenges[challenge_key]
            raise ValueError("Challenge expired")

        # Check if challenge matches
        if stored["challenge"] != challenge:
            raise ValueError("Challenge mismatch")

        # Extract public key bytes and verify signature
        try:
            user_pubkey_bytes = extract_public_key(public_key)
        except Exception as e:
            raise ValueError(f"Invalid user identifier: {e}")

        message = challenge.encode('utf-8')
        signature_bytes = self.crypto.base64_decode(signature)

        if not self.crypto.verify_signature(message, signature_bytes, user_pubkey_bytes):
            raise ValueError("Invalid signature")

        # Check if user is a member of this channel
        if not self.is_member(public_key):
            raise ValueError("Not a member of this channel")

        # Clean up challenge
        del self.challenges[challenge_key]

        return True

    def create_jwt(self, public_key: str) -> dict:
        """
        Create a JWT token for an authenticated user.

        Args:
            public_key: User's public key identifier

        Returns:
            Dictionary with token and expires_at (in milliseconds)

        Raises:
            ValueError: If JWT secret is not configured
        """
        if not self.jwt_secret:
            raise ValueError("JWT secret not configured")

        now_seconds = int(time.time())
        expiry_seconds = now_seconds + (self.jwt_expiry_hours * 3600)

        payload = {
            "channel_id": self.channel_id,
            "public_key": public_key,
            "iat": now_seconds,
            "exp": expiry_seconds
        }

        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        return {
            "token": token,
            "expires_at": expiry_seconds * 1000  # Return milliseconds
        }

    def verify_jwt(self, token: str) -> dict:
        """
        Verify and decode a JWT token.

        Args:
            token: JWT token string

        Returns:
            Decoded payload dictionary

        Raises:
            ValueError: If token is invalid, expired, or for wrong channel
        """
        if not self.jwt_secret:
            raise ValueError("JWT secret not configured")

        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])

            # Verify token is for this channel
            if payload.get("channel_id") != self.channel_id:
                raise ValueError("Token channel mismatch")

            return payload

        except jwt.ExpiredSignatureError:
            raise ValueError("Token expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")

    def refresh_jwt(self, token: str) -> dict:
        """
        Refresh a JWT token (verify old token and issue new one).

        Args:
            token: Current JWT token string

        Returns:
            Dictionary with new token and expires_at (in milliseconds)

        Raises:
            ValueError: If token is invalid, expired, or for wrong channel
        """
        # Verify the current token
        payload = self.verify_jwt(token)

        # Issue a new token with the same public_key
        return self.create_jwt(payload["public_key"])

    def authenticate_request(self, token: str) -> dict:
        """
        Authenticate a request using JWT token (convenience method for endpoints).

        This is a simple wrapper around verify_jwt with the same behavior.
        Endpoints can use this to authenticate and get user info.

        Args:
            token: JWT token string

        Returns:
            Dictionary with channel_id and public_key

        Raises:
            ValueError: If token is invalid, expired, or for wrong channel
        """
        return self.verify_jwt(token)

    # ========================================================================
    # State Operations
    # ========================================================================

    def get_state(self, path: str, token: str) -> Dict[str, Any]:
        """
        Get state value by path with authentication and authorization.

        Args:
            path: State path to retrieve
            token: JWT authentication token

        Returns:
            State data dictionary

        Raises:
            ValueError: If auth fails, permission denied, or state not found
        """
        # Authenticate
        user = self.authenticate_request(token)

        # Check read permission
        if not self.check_permission(user["public_key"], "read", path):
            raise ValueError("No read permission")

        # Get state
        state = self.state_store.get_state(self.channel_id, path)
        if state is None:
            raise ValueError("State not found")

        return state

    def set_state(
        self,
        path: str,
        data: str,
        token: str,
        signature: Optional[str] = None,
        signed_by: Optional[str] = None
    ) -> int:
        """
        Set state value with authentication and authorization.

        Args:
            path: State path to set
            data: Base64-encoded state data
            token: JWT authentication token
            signature: Optional signature for capability grants
            signed_by: Optional signer ID for capability grants

        Returns:
            Timestamp when state was updated (milliseconds)

        Raises:
            ValueError: If auth fails, permission denied, or validation fails
        """
        # Authenticate
        user = self.authenticate_request(token)

        # Check if state already exists
        existing = self.state_store.get_state(self.channel_id, path)
        operation = "write" if existing else "create"

        # Check permission
        if not self.check_permission(user["public_key"], operation, path):
            raise ValueError(f"No {operation} permission for path: {path}")

        # For capability paths, validate signature
        if self.is_capability_path(path):
            if not signature or not signed_by:
                raise ValueError("Signature required for capability grants")

            # Decode and validate capability
            import base64
            import json
            try:
                decoded = base64.b64decode(data)
                capability_dict = json.loads(decoded)
            except Exception as e:
                raise ValueError(f"Capability grants must be base64-encoded JSON objects: {e}")

            # Verify the capability grant
            if not self.verify_capability_grant(path, capability_dict, signed_by, signature):
                raise ValueError("Invalid capability grant or privilege escalation")

        # Store state
        now = int(time.time() * 1000)
        self.state_store.set_state(
            self.channel_id,
            path,
            data,
            user["public_key"],
            now
        )

        return now

    def delete_state(self, path: str, token: str) -> None:
        """
        Delete state value with authentication and authorization.

        Args:
            path: State path to delete
            token: JWT authentication token

        Raises:
            ValueError: If auth fails, permission denied, or state not found
        """
        # Authenticate
        user = self.authenticate_request(token)

        # Check write permission for deletion
        if not self.check_permission(user["public_key"], "write", path):
            raise ValueError("No delete permission")

        # Delete state
        if not self.state_store.delete_state(self.channel_id, path):
            raise ValueError("State not found")

    def list_state(self, prefix: str) -> List[Dict[str, Any]]:
        """List state entries matching prefix"""
        return self.state_store.list_state(self.channel_id, prefix)

    # ========================================================================
    # Message Operations
    # ========================================================================

    async def post_message(
        self,
        topic_id: str,
        message_hash: str,
        prev_hash: Optional[str],
        encrypted_payload: str,
        signature: str,
        token: str
    ) -> int:
        """
        Post a message to a topic with authentication and validation.

        Stores the message and broadcasts it to all connected WebSocket clients.

        Args:
            topic_id: Topic identifier
            message_hash: SHA256 hash of the message
            prev_hash: Hash of previous message in chain (None for first)
            encrypted_payload: Base64-encoded encrypted message content
            signature: Base64-encoded Ed25519 signature
            token: JWT authentication token

        Returns:
            server_timestamp: Timestamp when message was stored (milliseconds)

        Raises:
            ValueError: If auth fails, permission denied, or validation fails
        """
        # Authenticate
        user = self.authenticate_request(token)
        sender = user["public_key"]

        # Check create permission
        if not self.check_permission(sender, "create", f"topics/{topic_id}/messages/"):
            raise ValueError("No post permission")

        # Validate message hash
        expected_hash = self.compute_message_hash(topic_id, prev_hash, encrypted_payload, sender)
        if expected_hash != message_hash:
            raise ValueError("Message hash mismatch")

        # Verify signature
        signature_bytes = self.crypto.base64_decode(signature)
        sender_bytes = extract_public_key(sender)
        if not self.verify_message_signature(message_hash, signature_bytes, sender_bytes):
            raise ValueError("Invalid message signature")

        # Get current chain head
        current_head = self.message_store.get_chain_head(self.channel_id, topic_id)

        # Validate prev_hash
        if current_head is None:
            if prev_hash is not None:
                raise ValueError("First message must have prev_hash=null")
        else:
            if prev_hash != current_head["message_hash"]:
                raise ValueError(f"Chain conflict: expected prev_hash={current_head['message_hash']}")

        # Store message
        server_timestamp = int(time.time() * 1000)
        self.message_store.add_message(
            channel_id=self.channel_id,
            topic_id=topic_id,
            message_hash=message_hash,
            prev_hash=prev_hash,
            encrypted_payload=encrypted_payload,
            sender=sender,
            signature=signature,
            server_timestamp=server_timestamp
        )

        # Broadcast to WebSocket subscribers
        message_dict = {
            "message_hash": message_hash,
            "topic_id": topic_id,
            "prev_hash": prev_hash,
            "encrypted_payload": encrypted_payload,
            "sender": sender,
            "signature": signature,
            "server_timestamp": server_timestamp
        }
        await self.broadcast_message(message_dict)

        return server_timestamp

    def get_messages(
        self,
        topic_id: str,
        token: str,
        from_ts: Optional[int] = None,
        to_ts: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query messages with authentication and permission check.

        Args:
            topic_id: Topic identifier
            token: JWT authentication token
            from_ts: Optional start timestamp (inclusive)
            to_ts: Optional end timestamp (inclusive)
            limit: Maximum number of messages to return

        Returns:
            List of message dictionaries

        Raises:
            ValueError: If auth fails or permission denied
        """
        # Authenticate
        user = self.authenticate_request(token)

        # Check read permission
        if not self.check_permission(user["public_key"], "read", f"topics/{topic_id}/messages/"):
            raise ValueError("No read permission for topic")

        # Get messages
        return self.message_store.get_messages(
            self.channel_id,
            topic_id,
            from_ts,
            to_ts,
            limit
        )

    def get_message_by_hash(self, message_hash: str, token: str) -> Dict[str, Any]:
        """
        Get a specific message by hash with authentication and permission check.

        Args:
            message_hash: Message hash
            token: JWT authentication token

        Returns:
            Message dictionary

        Raises:
            ValueError: If auth fails, permission denied, or message not found
        """
        # Authenticate
        user = self.authenticate_request(token)

        # Get message
        message = self.message_store.get_message_by_hash(self.channel_id, message_hash)
        if not message:
            raise ValueError("Message not found")

        # Check read permission for the message's topic
        if not self.check_permission(user["public_key"], "read", f"topics/{message['topic_id']}/messages/"):
            raise ValueError("No read permission")

        return message

    # ========================================================================
    # Authorization
    # ========================================================================

    def check_permission(
        self,
        user_id: str,
        operation: str,
        path: str
    ) -> bool:
        """Check if user has permission for operation on path"""
        return self.authz.check_permission(
            self.channel_id,
            user_id,
            operation,
            path
        )

    def verify_capability_grant(
        self,
        path: str,
        capability_dict: dict,
        signed_by: str,
        signature: str
    ) -> bool:
        """Verify a capability grant is valid"""
        return self.authz.verify_capability_grant(
            self.channel_id,
            path,
            capability_dict,
            signed_by,
            signature
        )

    def is_capability_path(self, path: str) -> bool:
        """Check if path is a capability path"""
        return self.authz.is_capability_path(path)

    def is_member(self, user_id: str) -> bool:
        """Check if user is a member of this channel"""
        member = self.state_store.get_state(self.channel_id, f"members/{user_id}")
        return member is not None or user_id == self.channel_id

    def is_channel_admin(self, user_id: str) -> bool:
        """
        Check if user is a channel admin (currently just the channel owner).

        Args:
            user_id: The user's public key

        Returns:
            True if user is the channel owner (channel_id matches user_id)
        """
        return user_id == self.channel_id

    # ========================================================================
    # Blob Management
    # ========================================================================

    def authorize_blob_upload(self, user_id: str, token: str) -> bool:
        """
        Authorize a blob upload.

        Any authenticated member of the channel can upload blobs.

        Args:
            user_id: The user's public key
            token: JWT token to verify

        Returns:
            True if authorized

        Raises:
            ValueError: If authorization fails
        """
        # Verify token
        self.verify_jwt(token)

        # Check if user is a member
        if not self.is_member(user_id):
            raise ValueError("Not a member of this channel")

        return True

    def authorize_blob_download(self, user_id: str, token: str, blob_metadata) -> bool:
        """
        Authorize a blob download.

        Users can download blobs only if their channel has a reference to the blob.

        Args:
            user_id: The user's public key
            token: JWT token to verify
            blob_metadata: BlobMetadata object with references list

        Returns:
            True if authorized

        Raises:
            ValueError: If authorization fails
        """
        # Verify token
        self.verify_jwt(token)

        # Check if user is a member
        if not self.is_member(user_id):
            raise ValueError("Not a member of this channel")

        # Check if this channel has a reference to the blob
        if not blob_metadata.has_reference(self.channel_id):
            raise ValueError("Blob belongs to a different channel")

        return True

    def authorize_blob_delete(self, user_id: str, token: str, blob_metadata) -> bool:
        """
        Authorize a blob deletion (reference removal).

        Only the uploader or channel admin can delete their channel's reference to a blob.

        Args:
            user_id: The user's public key
            token: JWT token to verify
            blob_metadata: BlobMetadata object with references list

        Returns:
            True if authorized

        Raises:
            ValueError: If authorization fails
        """
        # Verify token
        self.verify_jwt(token)

        # Check if user is a member
        if not self.is_member(user_id):
            raise ValueError("Not a member of this channel")

        # Check if this channel has a reference to the blob
        if not blob_metadata.has_reference(self.channel_id):
            raise ValueError("Blob belongs to a different channel")

        # Get the specific reference for this channel and user
        reference = blob_metadata.get_reference(self.channel_id, user_id)

        # Check if user is uploader or admin
        is_uploader = (reference is not None)
        is_admin = self.is_channel_admin(user_id)

        if not (is_uploader or is_admin):
            raise ValueError("Only the uploader or channel admin can delete this blob")

        return True

    def upload_blob(self, user_id: str, token: str, blob_id: str, blob_data: bytes) -> dict:
        """
        Upload a blob to the channel with authorization and validation.

        Args:
            user_id: The user's public key
            token: JWT token to verify
            blob_id: Content-addressed identifier for the blob
            blob_data: Raw binary blob data

        Returns:
            Dictionary with blob_id and size

        Raises:
            ValueError: If authorization fails, blob_id mismatch, or blob_store not configured
            FileExistsError: If blob reference already exists
        """
        if not self.blob_store:
            raise ValueError("Blob store not configured for this channel")

        # Authorize upload
        self.authorize_blob_upload(user_id, token)

        # Verify blob_id matches content hash
        expected_blob_id = CryptoUtils.compute_blob_id(blob_data)
        if blob_id != expected_blob_id:
            raise ValueError(f"blob_id mismatch: provided {blob_id}, expected {expected_blob_id}")

        # Store blob with ownership metadata
        self.blob_store.add_blob(blob_id, blob_data, self.channel_id, user_id)

        return {
            "blob_id": blob_id,
            "size": len(blob_data)
        }

    def download_blob(self, user_id: str, token: str, blob_id: str) -> Optional[bytes]:
        """
        Download a blob from the channel with authorization.

        Args:
            user_id: The user's public key
            token: JWT token to verify
            blob_id: Content-addressed identifier for the blob

        Returns:
            Blob data if found and authorized, None if not found

        Raises:
            ValueError: If authorization fails or blob_store not configured
        """
        if not self.blob_store:
            raise ValueError("Blob store not configured for this channel")

        # Get blob metadata for authorization
        metadata = self.blob_store.get_blob_metadata(blob_id)
        if not metadata:
            return None

        # Authorize download
        self.authorize_blob_download(user_id, token, metadata)

        # Retrieve blob data
        return self.blob_store.get_blob(blob_id)

    def get_blob_download_url(self, user_id: str, token: str, blob_id: str) -> Optional[str]:
        """
        Get a pre-signed download URL for a blob (if supported by blob store).

        Args:
            user_id: The user's public key
            token: JWT token to verify
            blob_id: Content-addressed identifier for the blob

        Returns:
            Pre-signed URL if available, None otherwise

        Raises:
            ValueError: If authorization fails or blob_store not configured
        """
        if not self.blob_store:
            raise ValueError("Blob store not configured for this channel")

        # Get blob metadata for authorization
        metadata = self.blob_store.get_blob_metadata(blob_id)
        if not metadata:
            return None

        # Authorize download
        self.authorize_blob_download(user_id, token, metadata)

        # Get pre-signed URL if supported
        return self.blob_store.get_download_url(blob_id)

    def delete_blob(self, user_id: str, token: str, blob_id: str) -> bool:
        """
        Delete a blob reference from the channel with authorization.

        Removes the channel's reference to the blob. If no references remain,
        the blob content is also deleted.

        Args:
            user_id: The user's public key
            token: JWT token to verify
            blob_id: Content-addressed identifier for the blob

        Returns:
            True if blob content was deleted (no references remain), False otherwise

        Raises:
            ValueError: If authorization fails or blob_store not configured
        """
        if not self.blob_store:
            raise ValueError("Blob store not configured for this channel")

        # Get blob metadata for authorization
        metadata = self.blob_store.get_blob_metadata(blob_id)
        if not metadata:
            raise ValueError("Blob not found")

        # Authorize deletion
        self.authorize_blob_delete(user_id, token, metadata)

        # Remove the reference (will delete blob content if no references remain)
        return self.blob_store.remove_blob_reference(blob_id, self.channel_id, user_id)

    # ========================================================================
    # WebSocket Management
    # ========================================================================

    async def handle_websocket(self, websocket: WebSocket) -> None:
        """
        Handle a WebSocket connection for this channel.

        Manages the full lifecycle: accept, keep-alive, ping/pong, and cleanup.

        Args:
            websocket: The WebSocket connection to handle
        """
        # Accept and register the connection
        await websocket.accept()
        self.websockets.add(websocket)

        try:
            # Keep connection alive and handle incoming messages
            while True:
                # Wait for any client messages (ping/pong, etc.)
                # In this implementation, we primarily send messages to clients
                # but we need to keep the connection open
                try:
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                    # Handle ping/pong or other control messages if needed
                    if data == "ping":
                        await websocket.send_text("pong")
                except asyncio.TimeoutError:
                    # Send periodic ping to keep connection alive
                    try:
                        await websocket.send_text(json.dumps({"type": "ping"}))
                    except Exception:
                        break
                except Exception:  # Includes WebSocketDisconnect
                    break

        except Exception:
            # Log error if needed
            pass
        finally:
            # Clean up connection
            self.websockets.discard(websocket)

    def disconnect_websocket(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection from this channel"""
        self.websockets.discard(websocket)

    async def broadcast_message(self, message: dict) -> None:
        """Broadcast a message to all connected WebSocket clients"""
        if not self.websockets:
            return

        message_json = json.dumps(message)
        dead_connections = set()

        for websocket in self.websockets:
            try:
                await websocket.send_text(message_json)
            except Exception:
                dead_connections.add(websocket)

        # Clean up dead connections
        for websocket in dead_connections:
            self.disconnect_websocket(websocket)

    def get_connection_count(self) -> int:
        """Get number of active WebSocket connections"""
        return len(self.websockets)

    # ========================================================================
    # Validation & Crypto Utilities
    # ========================================================================

    def compute_message_hash(
        self,
        topic_id: str,
        prev_hash: Optional[str],
        encrypted_payload: str,
        sender: str
    ) -> str:
        """Compute the hash for a message"""
        return self.crypto.compute_message_hash(
            self.channel_id,
            topic_id,
            prev_hash,
            encrypted_payload,
            sender
        )

    def verify_message_signature(
        self,
        message_hash: str,
        signature_bytes: bytes,
        sender_pubkey_bytes: bytes
    ) -> bool:
        """Verify a message signature"""
        return self.crypto.verify_message_signature(
            message_hash,
            signature_bytes,
            sender_pubkey_bytes
        )

    def verify_signature(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes
    ) -> bool:
        """Verify a generic signature"""
        return self.crypto.verify_signature(message, signature, public_key)

    # ========================================================================
    # Maintenance & Stats
    # ========================================================================

    def get_stats(self) -> dict:
        """Get channel statistics"""
        # Count messages across all topics (this is expensive, consider caching)
        # For now, return basic info
        return {
            "channel_id": self.channel_id,
            "websocket_connections": self.get_connection_count(),
            # Could add: message count, member count, storage size, etc.
        }

    def close(self) -> None:
        """
        Close the channel and cleanup resources.
        Useful for testing or graceful shutdown.
        """
        # Close all WebSocket connections
        for websocket in list(self.websockets):
            try:
                asyncio.create_task(websocket.close())
            except Exception:
                pass
        self.websockets.clear()

        # SQLite connections will be closed by garbage collection
        # If we need explicit cleanup, we could add close() methods to stores
