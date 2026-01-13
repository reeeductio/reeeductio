"""
Space - Core business logic for a single space

This class encapsulates all space operations including state management,
message handling, and WebSocket connections. It's designed to be:
- Framework-agnostic (works with FastAPI, Durable Objects, etc.)
- Self-contained (manages its own storage)
- Thread-safe for multi-worker deployments
"""

import asyncio
import time
from typing import Optional, List, Dict, Any, Set
from fastapi import WebSocket
import json

from data_store import DataStore
from message_store import MessageStore
from event_sourced_state_store import EventSourcedStateStore
from crypto import CryptoUtils
from blob_store import BlobStore
from authorization import AuthorizationEngine
from identifiers import extract_public_key
from path_validation import validate_user_path, PathValidationError
from exceptions import ChainConflictError
import secrets
import jwt


class Space:
    """
    Represents a single space with its state, messages, and connections.

    Each space instance manages:
    - State storage (members, capabilities, metadata)
    - Message storage (per-topic message chains)
    - Active WebSocket connections
    - Authorization logic

    Can be used in:
    - FastAPI with per-space instances
    - Durable Objects (TypeScript port)
    - Other frameworks
    """

    #region init
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
        Initialize a Space instance.

        Args:
            space_id: Unique space identifier
            state_store: State store instance for this space
            message_store: Message store instance for this space
            blob_store: Optional blob store (shared across spaces for deduplication)
            jwt_secret: JWT signing secret (shared across all spaces for consistency)
            jwt_algorithm: JWT signing algorithm
            jwt_expiry_hours: JWT token expiry in hours
        """
        self.space_id = space_id
        self.message_store = message_store
        self.data_store = data_store
        self.blob_store = blob_store
        self.state_store = EventSourcedStateStore(message_store)

        # JWT configuration
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.jwt_expiry_hours = jwt_expiry_hours

        # Initialize crypto and authorization
        self.crypto = CryptoUtils()
        self.authz = AuthorizationEngine(
            self.state_store,
            self.crypto,
            blob_store=self.blob_store,
            data_store=self.data_store
        )

        # WebSocket connections for this space
        self.websockets: Set[WebSocket] = set()

        # In-memory challenge storage (for authentication)
        # In production, store in Redis with TTL
        self.challenges: Dict[str, Dict[str, Any]] = {}

    #region Authentication
    # ========================================================================
    # Authentication Operations
    # ========================================================================

    def create_challenge(self, member_id: str, expiry_seconds: int = 300) -> Dict[str, Any]:
        """
        Create an authentication challenge for a user or tool.

        Args:
            member_id: User or tool public key identifier (U_* or T_*)
            expiry_seconds: Challenge validity in seconds

        Returns:
            Dictionary with challenge and expires_at
        """
        challenge_bytes = secrets.token_bytes(32)
        challenge = self.crypto.base64_encode(challenge_bytes)
        expires_at = int(time.time() * 1000) + (expiry_seconds * 1000)

        challenge_key = member_id
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
        member_id: str,
        challenge: str,
        signature: str
    ) -> bool:
        """
        Verify a signed challenge for authentication.

        Works for both users (U_*) and tools (T_*). Tools can authenticate
        to make API requests, but their permissions are still limited by
        their capabilities (no ambient authority).

        Args:
            member_id: User or tool public key identifier (U_* or T_*)
            challenge: The challenge string to verify
            signature: Base64-encoded signature of the challenge

        Returns:
            True if verification succeeds

        Raises:
            ValueError: If challenge not found, expired, or signature invalid
        """
        challenge_key = member_id

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
            user_pubkey_bytes = extract_public_key(member_id)
        except Exception as e:
            raise ValueError(f"Invalid user identifier: {e}")

        message = challenge.encode('utf-8')
        signature_bytes = self.crypto.base64_decode(signature)

        if not self.crypto.verify_signature(message, signature_bytes, user_pubkey_bytes):
            raise ValueError("Invalid signature")

        # Check if user is a member of this space
        if not self.is_member(member_id):
            raise ValueError("Not a member of this space")

        # Clean up challenge
        del self.challenges[challenge_key]

        return True

    def create_jwt(self, member_id: str) -> dict:
        """
        Create a JWT token for an authenticated user or tool.

        Tools can authenticate to make API requests (e.g., uploading photos),
        but their permissions are still limited by their capabilities.

        Args:
            member_id: User or tool public key identifier (U_* or T_*)

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
            "space_id": self.space_id,
            "id": member_id,
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
            ValueError: If token is invalid, expired, or for wrong space
        """
        if not self.jwt_secret:
            raise ValueError("JWT secret not configured")

        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])

            # Verify token is for this space
            if payload.get("space_id") != self.space_id:
                raise ValueError("Token space mismatch")

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
            ValueError: If token is invalid, expired, or for wrong space
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
            Dictionary with space_id and public_key

        Raises:
            ValueError: If token is invalid, expired, or for wrong space
        """
        return self.verify_jwt(token)

    #region State
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
            PathValidationError: If path contains invalid characters or wildcards
        """
        # Validate path
        try:
            validate_user_path(path)
        except PathValidationError as e:
            raise ValueError(f"Invalid path: {e}")

        # Authenticate the member of the space
        # (member might be a user or a tool)
        member = self.authenticate_request(token)

        # Check read permission
        if not self.check_permission(member["id"], "read", path):
            raise ValueError("No read permission")

        # Get state - In the event-sourced state model,
        # the current state for `path` is the most recent
        # message in topic "state" with type `path`
        state = self.message_store.get_most_recent_message(
            space_id=self.space_id,
            topic_id="state",
            type=path
        )
        if state is None:
            raise ValueError("State not found")

        return state

    def _check_state_operation(
        self,
        path: str,
        data: str,
        signed_by: str
    ) -> None:
        """
        Validate state-specific constraints before allowing a state message to be posted.

        This includes chain-of-trust verification, capability grant validation,
        role grant validation, and tool creation verification.

        Args:
            path: State path being modified
            data: Base64-encoded state data
            signed_by: Typed identifier of the signer (user or tool)

        Raises:
            ValueError: If validation fails
        """
        print("Checking state operation")

        # Validate path
        try:
            validate_user_path(path)
        except PathValidationError as e:
            raise ValueError(f"Invalid path: {e}")

        # CRITICAL SECURITY: Verify chain of trust for the signer
        # This prevents database tampering attacks where an adversary inserts
        # a new public key directly into the database
        # Exception: When creating new users/tools, we verify the chain in the
        # specific validation methods below, not here (chicken-and-egg problem)
        is_member_creation = (
            (path.startswith("auth/users/") and path.count('/') == 2) or
            (path.startswith("auth/tools/") and path.count('/') == 2)
        )
        if not is_member_creation:
            # For all other writes, signer must have valid chain of trust
            if not self.authz.verify_chain_of_trust(self.space_id, signed_by):
                raise ValueError(f"Signer {signed_by} has invalid chain of trust")

        # For capability paths, validate capability structure
        if self.is_capability_path(path):
            print("State operation is capability path")
            # Decode and validate capability
            import base64
            import json
            try:
                decoded = base64.b64decode(data)
                capability_dict = json.loads(decoded)
            except Exception as e:
                raise ValueError(f"Capability grants must be base64-encoded JSON objects: {e}")

            # Verify the capability grant (privilege escalation check for users)
            print("Verifying capability grant")
            if not self.verify_capability_grant(path, capability_dict, signed_by):
                print("Capability grant verification failed")
                raise ValueError("Invalid capability grant or privilege escalation")
        else:
            print("State operation is not capability grant")

        # For role grant paths, validate role grant structure
        if self.authz.is_role_grant_path(path):
            # Decode and validate role grant
            import base64
            import json
            try:
                decoded = base64.b64decode(data)
                role_grant_dict = json.loads(decoded)
            except Exception as e:
                raise ValueError(f"Role grants must be base64-encoded JSON objects: {e}")

            # Path-content consistency validation
            parts = path.strip('/').split('/')
            if len(parts) >= 5:
                path_user_id = parts[2]
                path_role_id = parts[4]

                if role_grant_dict.get("user_id") != path_user_id:
                    raise ValueError(f"Role grant user_id mismatch: path has '{path_user_id}' but data has '{role_grant_dict.get('user_id')}'")

                if role_grant_dict.get("role_id") != path_role_id:
                    raise ValueError(f"Role grant role_id mismatch: path has '{path_role_id}' but data has '{role_grant_dict.get('role_id')}'")

            # Verify the role grant (subset checking)
            if not self.authz.verify_role_grant(self.space_id, path, role_grant_dict, signed_by):
                raise ValueError("Invalid role grant or privilege escalation")
        else:
            print("State operation is not role grant")

        # For user/tool creation, verify the creator has valid chain of trust
        # The new user/tool won't have a chain yet (we're creating it), but the
        # creator must have a valid chain
        if is_member_creation:
            # Verify the creator (signed_by) has valid chain of trust
            if not self.authz.verify_chain_of_trust(self.space_id, signed_by):
                raise ValueError(f"Creator {signed_by} has invalid chain of trust - cannot create new members")

        # Initialize tool usage tracking if creating a use-limited tool
        # This should happen before the message is posted
        if path.startswith("auth/tools/") and path.count('/') == 2:
            import base64
            import json
            try:
                tool_def = json.loads(base64.b64decode(data))
                if tool_def.get('use_limit') is not None:
                    tool_id = path.split('/')[-1]
                    self.message_store.initialize_tool_usage(self.space_id, tool_id)
            except Exception:
                pass  # Invalid JSON, will be caught elsewhere

    async def set_state(
        self,
        path: str,
        prev_hash: Optional[str],
        data: str,
        message_hash: str,
        signature: str,
        token: str
    ) -> int:
        """
        Set state value by posting a message to the "state" topic.

        State is stored as messages with the state path in the "type" field.
        This creates an immutable audit log of all state changes.

        Args:
            path: State path to set (becomes the message "type")
            prev_hash: Hash of previous message in state topic chain (None for first)
            data: Base64-encoded state data
            message_hash: SHA256 hash of the message (client-computed)
            signature: Ed25519 signature over message_hash by sender
            token: JWT authentication token

        Returns:
            server_timestamp: Timestamp when state message was stored (milliseconds)

        Raises:
            ValueError: If auth fails, permission denied, validation fails, or chain conflict
            PathValidationError: If path contains invalid characters or wildcards
        """
        # Simply delegate everything to post_message() with path as the message type
        # The "state" topic handler in post_message will call _check_state_operation
        # to do state-specific validation (capabilities, roles, chain of trust, etc.)
        return await self.post_message(
            topic_id="state",
            message_hash=message_hash,
            msg_type=path,  # State path IS the message type!
            prev_hash=prev_hash,
            data=data,
            signature=signature,
            token=token
        )

    def list_state(self, prefix: str) -> List[Dict[str, Any]]:
        """List state entries matching prefix"""
        return self.state_store.list_state(self.space_id, prefix)


    #region Messages
    # ========================================================================
    # Message Operations
    # ========================================================================

    async def post_message(
        self,
        topic_id: str,
        message_hash: str,
        msg_type: str,
        prev_hash: Optional[str],
        data: str,
        signature: str,
        token: str
    ) -> int:
        """
        Post a message to a topic with authentication and validation.

        Stores the message and broadcasts it to all connected WebSocket clients.

        Args:
            topic_id: Topic identifier
            message_hash: SHA256 hash of the message
            msg_type: Message type (e.g., "chat.text", "chat.image")
            prev_hash: Hash of previous message in chain (None for first)
            data: Base64-encoded encrypted message content
            signature: Base64-encoded Ed25519 signature
            token: JWT authentication token

        Returns:
            server_timestamp: Timestamp when message was stored (milliseconds)

        Raises:
            ValueError: If auth fails, permission denied, or validation fails
        """
        # Authenticate
        user = self.authenticate_request(token)
        sender = user["id"]

        # Check tool use limit BEFORE processing (returns True if usage should be tracked)
        should_track_usage = self._check_tool_limit(sender)

        # Check create permission
        # state topic is special - Doesn't require topic permission to send
        if topic_id != "state" and not self.check_permission(sender, "create", f"topics/{topic_id}/messages/"):
            raise ValueError("No post permission")

        # Validate message hash
        expected_hash = self.compute_message_hash(topic_id, prev_hash, data, sender)
        if expected_hash != message_hash:
            raise ValueError("Message hash mismatch")

        # Verify signature
        signature_bytes = self.crypto.base64_decode(signature)
        sender_bytes = extract_public_key(sender)
        if not self.verify_message_signature(message_hash, signature_bytes, sender_bytes):
            raise ValueError("Invalid message signature")

        # For state-events topic, also check state-specific authorization
        if topic_id == "state":
            path = msg_type  # Path is stored in the type field for state events

            # Validate path first - before authentication or authorization
            # This prevents wildcard injection attacks
            try:
                validate_user_path(path)
            except PathValidationError as e:
                raise ValueError(f"Invalid path: {e}")

            # Perform state-specific validation (chain of trust, capabilities, roles, tool creation)
            self._check_state_operation(path, data, sender)

            # Determine operation type based on data and existing state
            if data:
                # Set/create operation - check if state exists
                existing = self.state_store.get_state(self.space_id, path)
                operation = "modify" if existing else "create"
            else:
                # Delete operation (empty data)
                operation = "delete"

            # Check permission for this specific state path
            # Use unified namespace: prefix with "state/"
            if not self.check_permission(sender, operation, f"state/{path}"):
                raise ValueError(f"No {operation} permission for state path: {path}")
            
            # Invalidate the cache for this path
            # NOTE: This is safer than attempting to update the cache in place, and avoids potential
            #       race conditions if we have multiple calls to this method running concurrently.
            #       The state store will safely re-load its cache from the database the next time
            #       this path entry is read.  The database is the source of ground truth, because
            #       it uses transactions to prevent race conditions.
            self.state_store.invalidate_cache(path)

        # Store message with atomic chain validation
        server_timestamp = int(time.time() * 1000)
        try:
            self.message_store.add_message(
                space_id=self.space_id,
                topic_id=topic_id,
                message_hash=message_hash,
                msg_type=msg_type,
                prev_hash=prev_hash,
                data=data,
                sender=sender,
                signature=signature,
                server_timestamp=server_timestamp
            )
        except ChainConflictError as e:
            # Chain conflict - client needs to get new head and retry
            raise ValueError(f"Chain conflict: {e}. Please get current chain head and retry.")

        # Increment tool usage after successful write (only if tool has use_limit)
        if should_track_usage:
            self._increment_tool_usage(sender)

        # Broadcast to WebSocket subscribers
        message_dict = {
            "message_hash": message_hash,
            "topic_id": topic_id,
            "type": msg_type,
            "prev_hash": prev_hash,
            "data": data,
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
        if not self.check_permission(user["id"], "read", f"topics/{topic_id}/messages/"):
            raise ValueError("No read permission for topic")

        # Get messages
        return self.message_store.get_messages(
            self.space_id,
            topic_id,
            from_ts,
            to_ts,
            limit
        )

    def get_message_by_hash(self, topic_id: str, message_hash: str, token: str) -> Dict[str, Any]:
        """
        Get a specific message by hash with authentication and permission check.

        Args:
            topic_id: Topic identifier
            message_hash: Message hash
            token: JWT authentication token

        Returns:
            Message dictionary

        Raises:
            ValueError: If auth fails, permission denied, or message not found
        """
        # Authenticate
        user = self.authenticate_request(token)

        # Check read permission for the topic (before DB query for better security)
        if not self.check_permission(user["id"], "read", f"topics/{topic_id}/messages/"):
            raise ValueError("No read permission")

        # Get message
        message = self.message_store.get_message_by_hash(self.space_id, topic_id, message_hash)
        if not message:
            raise ValueError("Message not found")

        return message

    #region KV Data
    # ========================================================================
    # KV Data Operations
    # ========================================================================
        
    def get_data(self, path: str, token: str) -> Dict[str, Any]:
        """
        Get state value by path with authentication and authorization.

        Args:
            path: State path to retrieve
            token: JWT authentication token

        Returns:
            KV data dictionary

        Raises:
            ValueError: If auth fails, permission denied, or state not found
            PathValidationError: If path contains invalid characters or wildcards
        """

        # Authenticate
        member = self.authenticate_request(token)

        # Check read permission for the data path (before DB query for better security)
        if not self.check_permission(member["id"], "read", f"data/{path}"):
            raise ValueError("No read permission")

        # Fetch the data
        data = self.data_store.get_data(self.space_id, path)
        if not data:
            raise ValueError("Data not found")
        # Return result
        return data
    
    def set_data(
            self,
            path: str,
            data: str,
            signature: str,
            signed_by: str,
            signed_at: int,
            token: str
    ):
        """
        Set data value by path with authentication and authorization.

        Args:
            path: Data store path (KV key) to write
            data: KV value to store (base64)
            signature: Sender's signature
            signed_by: ID of sender
            signed_at: Signature timestamp
            token: JWT authentication token

        Returns:
            Server timestamp

        Raises:
            ValueError: If auth fails or permission denied
            PathValidationError: If path contains invalid characters or wildcards
        """
        # Authenticate
        member = self.authenticate_request(token)
        if signed_by != member["id"]:
            raise ValueError("Signer does not match")

        # Get current timestamp (before db operations)
        server_timestamp = int(time.time() * 1000)

        # Determine operation type based on data and existing contents
        if data:
            # Set/create operation - check if data exists
            existing = self.data_store.get_data(self.space_id, path)
            operation = "modify" if existing else "create"
        else:
            # Delete operation (empty data)
            operation = "delete"

        # Check permission for this specific data path
        if not self.check_permission(member["id"], operation, path):
            raise ValueError(f"No {operation} permission for state path: {path}")
        
        # Save the data in the store
        self.data_store.set_data(self.space_id, path, data, signature, signed_by, signed_at)

        return server_timestamp
    
    def delete_data(
        self,
        path: str,
        token: str
    ):
        """
        Delete data value by path with authentication and authorization.

        Args:
            path: Data store path (KV key) to write
            token: JWT authentication token

        Raises:
            ValueError: If auth fails or permission denied
            PathValidationError: If path contains invalid characters or wildcards
        """
        # Authenticate
        member = self.authenticate_request(token)

        # Check permission for this specific data path
        if not self.check_permission(member["id"], "delete", path):
            raise ValueError(f"No delete permission for state path: {path}")
        
        # Remove the data from the store
        self.data_store.delete_data(self.space_id, path)

    #region Authorization
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
            self.space_id,
            user_id,
            operation,
            path
        )

    def verify_capability_grant(
        self,
        path: str,
        capability_dict: dict,
        signed_by: str
    ) -> bool:
        """Verify a capability grant is valid"""
        return self.authz.verify_capability_grant(
            self.space_id,
            path,
            capability_dict,
            signed_by
        )

    def is_capability_path(self, path: str) -> bool:
        """Check if path is a capability path"""
        return self.authz.is_capability_path(path)

    def is_member(self, member_id: str) -> bool:
        """
        Check if user or tool is a member of this space.

        Args:
            user_id: User ID (U_*) or Tool ID (T_*)

        Returns:
            True if identifier is the space owner, a member, or a registered tool
        """
        # Space creator is always a member
        member_public_key = extract_public_key(member_id)
        space_public_key = extract_public_key(self.space_id)
        if member_public_key == space_public_key:
            return True

        # Check if it's a tool
        if member_id.startswith('T'):
            tool = self.state_store.get_state(self.space_id, f"auth/tools/{member_id}")
            return tool is not None

        # Check if it's a regular user
        user = self.state_store.get_state(self.space_id, f"auth/users/{member_id}")
        return user is not None

    def is_space_admin(self, user_id: str) -> bool:
        """
        Check if user is a space admin (currently just the space owner).

        Args:
            user_id: The user's public key

        Returns:
            True if user is the space owner (space_id matches user_id)
        """
        return user_id == self.space_id

    def _check_tool_limit(self, member_id: str) -> bool:
        """
        Check if tool has exceeded use limit.

        This is called BEFORE a write operation for tools only.
        Regular users are not subject to use limits.

        Args:
            member_id: User or tool identifier

        Returns:
            True if the tool has a use_limit (and usage should be tracked), False otherwise

        Raises:
            ValueError: If tool has exceeded use limit or tool not found
        """
        # Only check limits for tools (T_*)
        if not member_id.startswith('T'):
            return False
        
        tool_id = member_id

        # Get tool definition from state
        tool_data = self.state_store.get_state(self.space_id, f"auth/tools/{tool_id}")
        if not tool_data:
            raise ValueError(f"Tool {tool_id} not found in space")

        # Check if tool has use_limit
        import base64
        import json
        try:
            tool_def = json.loads(base64.b64decode(tool_data['data']))
        except Exception as e:
            raise ValueError(f"Invalid tool definition for {tool_id}: {e}")

        use_limit = tool_def.get('use_limit')
        if use_limit is None:
            # No limit set - unlimited uses allowed, don't track
            return False

        # Get current usage
        usage = self.message_store.get_tool_usage(self.space_id, tool_id)
        current_count = usage['use_count'] if usage else 0

        # Check limit
        if current_count >= use_limit:
            raise ValueError(f"Tool {tool_id} has exceeded use limit ({use_limit})")

        # Tool has a limit and hasn't exceeded it - track this use
        return True

    def _increment_tool_usage(self, user_public_key: str) -> None:
        """
        Increment tool usage counter after a successful write operation.

        This is called AFTER a write operation succeeds for tools only.
        Regular users do not have usage tracked.

        Args:
            user_public_key: User or tool public key
        """
        # Only track usage for tools (T_*)
        if not user_public_key.startswith('T'):
            return

        now = int(time.time() * 1000)
        self.message_store.increment_tool_usage(self.space_id, user_public_key, now)

    #region Blobs
    # ========================================================================
    # Blob Management
    # ========================================================================

    def authorize_blob_upload(self, user_id: str, token: str) -> bool:
        """
        Authorize a blob upload.

        Any authenticated member of the space can upload blobs.

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
            raise ValueError("Not a member of this space")

        return True

    def authorize_blob_download(self, user_id: str, token: str, blob_metadata) -> bool:
        """
        Authorize a blob download.

        Users can download blobs only if their space has a reference to the blob.

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
            raise ValueError("Not a member of this space")

        # Check if this space has a reference to the blob
        if not blob_metadata.has_reference(self.space_id):
            raise ValueError("Blob belongs to a different space")

        return True

    def authorize_blob_delete(self, user_id: str, token: str, blob_metadata) -> bool:
        """
        Authorize a blob deletion (reference removal).

        Only the uploader or space admin can delete their space's reference to a blob.

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
            raise ValueError("Not a member of this space")

        # Check if this space has a reference to the blob
        if not blob_metadata.has_reference(self.space_id):
            raise ValueError("Blob belongs to a different space")

        # Get the specific reference for this space and user
        reference = blob_metadata.get_reference(self.space_id, user_id)

        # Check if user is uploader or admin
        is_uploader = (reference is not None)
        is_admin = self.is_space_admin(user_id)

        if not (is_uploader or is_admin):
            raise ValueError("Only the uploader or space admin can delete this blob")

        return True

    def upload_blob(self, user_id: str, token: str, blob_id: str, blob_data: bytes) -> dict:
        """
        Upload a blob to the space with authorization and validation.

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
            raise ValueError("Blob store not configured for this space")

        # Check tool use limit BEFORE processing (returns True if usage should be tracked)
        should_track_usage = self._check_tool_limit(user_id)

        # Authorize upload
        self.authorize_blob_upload(user_id, token)

        # Verify blob_id matches content hash
        expected_blob_id = CryptoUtils.compute_blob_id(blob_data)
        if blob_id != expected_blob_id:
            raise ValueError(f"blob_id mismatch: provided {blob_id}, expected {expected_blob_id}")

        # Store blob with ownership metadata
        self.blob_store.add_blob(blob_id, blob_data, self.space_id, user_id)

        # Increment tool usage after successful write (only if tool has use_limit)
        if should_track_usage:
            self._increment_tool_usage(user_id)

        return {
            "blob_id": blob_id,
            "size": len(blob_data)
        }

    def download_blob(self, user_id: str, token: str, blob_id: str) -> Optional[bytes]:
        """
        Download a blob from the space with authorization.

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
            raise ValueError("Blob store not configured for this space")

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
            raise ValueError("Blob store not configured for this space")

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
        Delete a blob reference from the space with authorization.

        Removes the space's reference to the blob. If no references remain,
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
            raise ValueError("Blob store not configured for this space")

        # Get blob metadata for authorization
        metadata = self.blob_store.get_blob_metadata(blob_id)
        if not metadata:
            raise ValueError("Blob not found")

        # Authorize deletion
        self.authorize_blob_delete(user_id, token, metadata)

        # Remove the reference (will delete blob content if no references remain)
        return self.blob_store.remove_blob_reference(blob_id, self.space_id, user_id)

    #region WebSockets
    # ========================================================================
    # WebSocket Management
    # ========================================================================

    async def handle_websocket(self, websocket: WebSocket) -> None:
        """
        Handle a WebSocket connection for this space.

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
        """Remove a WebSocket connection from this space"""
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

    #region Utilities
    # ========================================================================
    # Validation & Crypto Utilities
    # ========================================================================

    def compute_message_hash(
        self,
        topic_id: str,
        prev_hash: Optional[str],
        data: str,
        sender: str
    ) -> str:
        """Compute the hash for a message"""
        return self.crypto.compute_message_hash(
            self.space_id,
            topic_id,
            prev_hash,
            data,
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

    #region Stats
    # ========================================================================
    # Maintenance & Stats
    # ========================================================================

    def get_stats(self) -> dict:
        """Get space statistics"""
        # Count messages across all topics (this is expensive, consider caching)
        # For now, return basic info
        return {
            "space_id": self.space_id,
            "websocket_connections": self.get_connection_count(),
            # Could add: message count, member count, storage size, etc.
        }

    def close(self) -> None:
        """
        Close the space and cleanup resources.
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
