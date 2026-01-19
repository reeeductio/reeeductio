"""
Space Manager - Manages Space instances with optional Redis pub/sub

Provides simple space management with optional Redis integration
for cross-instance WebSocket broadcasting.

Supports a special admin space that uses AdminSpace class for
additional validation rules (space registration, created_by enforcement).
"""

import threading
from pathlib import Path
from typing import Dict, Optional, Callable
from space import Space
from admin_space import AdminSpace
from data_store import DataStore
from message_store import MessageStore
from sqlite_data_store import SqliteDataStore
from sqlite_message_store import SqliteMessageStore
from blob_store import BlobStore
from lru_cache import LRUCache
from logging_config import get_logger

logger = get_logger(__name__)


class SpaceManager:
    """
    Manages Space instances with LRU caching.

    With consistent hashing in nginx, each space's requests go to the same
    instance, so WebSocket connections are naturally colocated. This manager
    provides simple caching to avoid recreating Space instances.

    Optional: Can integrate Redis pub/sub for cross-instance messaging if needed.
    """

    def __init__(
        self,
        base_storage_dir: str = "spaces",
        max_cached_spaces: int = 1000,
        redis_client=None,  # Optional: redis.Redis() instance
        data_store_factory: Optional[Callable[[], DataStore]] = None,
        message_store_factory: Optional[Callable[[], MessageStore]] = None,
        blob_store: Optional[BlobStore] = None,
        jwt_secret: Optional[str] = None,
        jwt_algorithm: str = "HS256",
        jwt_expiry_hours: int = 24,
        admin_space_id: Optional[str] = None
    ):
        """
        Initialize the space manager.

        Args:
            base_storage_dir: Base directory for space storage (used with SQLite)
            max_cached_spaces: Maximum number of spaces to keep in memory
            redis_client: Optional Redis client for pub/sub (set to None if using consistent hashing)
            data_store_factory: Optional factory function () -> DataStore (for global stores like Firestore)
            message_store_factory: Optional factory function () -> MessageStore (for global stores like Firestore)
            blob_store: Optional blob storage backend (shared across all spaces)
            jwt_secret: JWT signing secret (shared across all spaces)
            jwt_algorithm: JWT signing algorithm
            jwt_expiry_hours: JWT token expiry in hours
            admin_space_id: Optional admin space ID (uses AdminSpace class for this space)
        """
        self.base_storage_dir = base_storage_dir
        self.max_cached_spaces = max_cached_spaces
        self.redis_client = redis_client
        self.data_store_factory = data_store_factory
        self.message_store_factory = message_store_factory
        self.blob_store = blob_store
        self.admin_space_id = admin_space_id

        # JWT configuration (shared across all spaces)
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.jwt_expiry_hours = jwt_expiry_hours

        # LRU cache: space_id -> Space instance
        self._spaces = LRUCache(max_size=max_cached_spaces)

        # Lock for thread-safe access
        self._lock = threading.Lock()

        # Redis pub/sub (optional, for cross-instance WebSocket broadcasting)
        if redis_client:
            self._setup_redis_pubsub()

    def get_space(self, space_id: str) -> Space:
        """
        Get or create a Space instance.

        Returns AdminSpace for the admin space ID, regular Space for others.

        Args:
            space_id: Space identifier

        Returns:
            Space instance for the given ID (AdminSpace if admin_space_id matches)
        """
        with self._lock:
            # Check if space exists in cache
            cached_space = self._spaces.get(space_id)
            if cached_space is not None:
                logger.debug(f"Space cache hit: {space_id}")
                return cached_space

            is_admin_space = (self.admin_space_id and space_id == self.admin_space_id)
            space_type = "admin" if is_admin_space else "regular"
            logger.info(f"Creating new {space_type} space instance: {space_id}")

            # Create stores for this space
            if self.data_store_factory and self.message_store_factory:
                # Use provided factories (e.g., Firestore - shared global stores)
                data_store = self.data_store_factory()
                message_store = self.message_store_factory()
            else:
                # Default: per-space SQLite databases
                storage_dir = f"{self.base_storage_dir}/ch_{space_id}"
                storage_path = Path(storage_dir)
                storage_path.mkdir(parents=True, exist_ok=True)

                data_store = SqliteDataStore(str(storage_path / "state.db"))
                message_store = SqliteMessageStore(str(storage_path / "messages.db"))

            # Create space instance - use AdminSpace for admin space
            if is_admin_space:
                space = AdminSpace(
                    space_id=space_id,
                    data_store=data_store,
                    message_store=message_store,
                    blob_store=self.blob_store,
                    jwt_secret=self.jwt_secret,
                    jwt_algorithm=self.jwt_algorithm,
                    jwt_expiry_hours=self.jwt_expiry_hours
                )
            else:
                space = Space(
                    space_id=space_id,
                    data_store=data_store,
                    message_store=message_store,
                    blob_store=self.blob_store,
                    jwt_secret=self.jwt_secret,
                    jwt_algorithm=self.jwt_algorithm,
                    jwt_expiry_hours=self.jwt_expiry_hours
                )

            # Add to cache (LRU will handle eviction automatically)
            self._spaces.set(space_id, space)

            return space

    def evict_space(self, space_id: str) -> bool:
        """
        Remove a space from cache.

        Args:
            space_id: Space identifier

        Returns:
            True if space was evicted, False if not in cache
        """
        with self._lock:
            space = self._spaces.pop(space_id, None)
            if space is not None:
                space.close()
                return True
            return False

    def get_stats(self) -> dict:
        """Get manager statistics"""
        with self._lock:
            return {
                "cached_spaces": len(self._spaces),
                "max_cached_spaces": self.max_cached_spaces,
                "base_storage_dir": self.base_storage_dir,
                "redis_enabled": self.redis_client is not None
            }

    # ========================================================================
    # Optional: Redis Pub/Sub for Cross-Instance Broadcasting
    # ========================================================================

    def _setup_redis_pubsub(self):
        """
        Setup Redis pub/sub listener (only needed if NOT using consistent hashing).

        This allows WebSocket connections on different instances to receive messages.
        """
        # Implementation would run in background thread, listening to Redis spaces
        # and calling space.broadcast_message() for local WebSocket connections
        pass

    async def publish_message(self, space_id: str, message: dict):
        """
        Publish a message to Redis (optional, for cross-instance broadcasting).

        Args:
            space_id: Space identifier
            message: Message to broadcast
        """
        if self.redis_client:
            import json
            # Publish to Redis space
            self.redis_client.publish(
                f"space:{space_id}",
                json.dumps(message)
            )
        else:
            # No Redis - use local broadcast (works with consistent hashing)
            space = self.get_space(space_id)
            await space.broadcast_message(message)

    def shutdown(self):
        """Close all spaces and clear cache"""
        with self._lock:
            # Close all spaces before clearing
            for space in self._spaces.values():
                space.close()
            self._spaces.clear()
