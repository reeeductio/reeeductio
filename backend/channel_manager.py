"""
Channel Manager - Manages Channel instances with optional Redis pub/sub

Provides simple channel management with optional Redis integration
for cross-instance WebSocket broadcasting.
"""

import threading
from pathlib import Path
from typing import Dict, Optional, Callable
from channel import Channel
from state_store import StateStore
from message_store import MessageStore
from sqlite_state_store import SqliteStateStore
from sqlite_message_store import SqliteMessageStore
from blob_store import BlobStore
from lru_cache import LRUCache
from logging_config import get_logger

logger = get_logger(__name__)


class ChannelManager:
    """
    Manages Channel instances with LRU caching.

    With consistent hashing in nginx, each channel's requests go to the same
    instance, so WebSocket connections are naturally colocated. This manager
    provides simple caching to avoid recreating Channel instances.

    Optional: Can integrate Redis pub/sub for cross-instance messaging if needed.
    """

    def __init__(
        self,
        base_storage_dir: str = "channels",
        max_cached_channels: int = 1000,
        redis_client=None,  # Optional: redis.Redis() instance
        state_store_factory: Optional[Callable[[], StateStore]] = None,
        message_store_factory: Optional[Callable[[], MessageStore]] = None,
        blob_store: Optional[BlobStore] = None,
        jwt_secret: Optional[str] = None,
        jwt_algorithm: str = "HS256",
        jwt_expiry_hours: int = 24
    ):
        """
        Initialize the channel manager.

        Args:
            base_storage_dir: Base directory for channel storage (used with SQLite)
            max_cached_channels: Maximum number of channels to keep in memory
            redis_client: Optional Redis client for pub/sub (set to None if using consistent hashing)
            state_store_factory: Optional factory function () -> StateStore (for global stores like Firestore)
            message_store_factory: Optional factory function () -> MessageStore (for global stores like Firestore)
            blob_store: Optional blob storage backend (shared across all channels)
            jwt_secret: JWT signing secret (shared across all channels)
            jwt_algorithm: JWT signing algorithm
            jwt_expiry_hours: JWT token expiry in hours
        """
        self.base_storage_dir = base_storage_dir
        self.max_cached_channels = max_cached_channels
        self.redis_client = redis_client
        self.state_store_factory = state_store_factory
        self.message_store_factory = message_store_factory
        self.blob_store = blob_store

        # JWT configuration (shared across all channels)
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.jwt_expiry_hours = jwt_expiry_hours

        # LRU cache: channel_id -> Channel instance
        self._channels = LRUCache(max_size=max_cached_channels)

        # Lock for thread-safe access
        self._lock = threading.Lock()

        # Redis pub/sub (optional, for cross-instance WebSocket broadcasting)
        if redis_client:
            self._setup_redis_pubsub()

    def get_channel(self, channel_id: str) -> Channel:
        """
        Get or create a Channel instance.

        Args:
            channel_id: Channel identifier

        Returns:
            Channel instance for the given ID
        """
        with self._lock:
            # Check if channel exists in cache
            cached_channel = self._channels.get(channel_id)
            if cached_channel is not None:
                logger.debug(f"Channel cache hit: {channel_id}")
                return cached_channel

            logger.info(f"Creating new channel instance: {channel_id}")
            # Create stores for this channel
            if self.state_store_factory and self.message_store_factory:
                # Use provided factories (e.g., Firestore - shared global stores)
                state_store = self.state_store_factory()
                message_store = self.message_store_factory()
            else:
                # Default: per-channel SQLite databases
                storage_dir = f"{self.base_storage_dir}/ch_{channel_id}"
                storage_path = Path(storage_dir)
                storage_path.mkdir(parents=True, exist_ok=True)

                state_store = SqliteStateStore(str(storage_path / "state.db"))
                message_store = SqliteMessageStore(str(storage_path / "messages.db"))

            # Create channel instance
            channel = Channel(
                channel_id=channel_id,
                state_store=state_store,
                message_store=message_store,
                blob_store=self.blob_store,
                jwt_secret=self.jwt_secret,
                jwt_algorithm=self.jwt_algorithm,
                jwt_expiry_hours=self.jwt_expiry_hours
            )

            # Add to cache (LRU will handle eviction automatically)
            self._channels.set(channel_id, channel)

            return channel

    def evict_channel(self, channel_id: str) -> bool:
        """
        Remove a channel from cache.

        Args:
            channel_id: Channel identifier

        Returns:
            True if channel was evicted, False if not in cache
        """
        with self._lock:
            channel = self._channels.pop(channel_id, None)
            if channel is not None:
                channel.close()
                return True
            return False

    def get_stats(self) -> dict:
        """Get manager statistics"""
        with self._lock:
            return {
                "cached_channels": len(self._channels),
                "max_cached_channels": self.max_cached_channels,
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
        # Implementation would run in background thread, listening to Redis channels
        # and calling channel.broadcast_message() for local WebSocket connections
        pass

    async def publish_message(self, channel_id: str, message: dict):
        """
        Publish a message to Redis (optional, for cross-instance broadcasting).

        Args:
            channel_id: Channel identifier
            message: Message to broadcast
        """
        if self.redis_client:
            import json
            # Publish to Redis channel
            self.redis_client.publish(
                f"channel:{channel_id}",
                json.dumps(message)
            )
        else:
            # No Redis - use local broadcast (works with consistent hashing)
            channel = self.get_channel(channel_id)
            await channel.broadcast_message(message)

    def shutdown(self):
        """Close all channels and clear cache"""
        with self._lock:
            # Close all channels before clearing
            for channel in self._channels.values():
                channel.close()
            self._channels.clear()
