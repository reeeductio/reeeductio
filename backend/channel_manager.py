"""
Channel Manager - Manages Channel instances with optional Redis pub/sub

Provides simple channel management with optional Redis integration
for cross-instance WebSocket broadcasting.
"""

import threading
from typing import Dict, Optional
from collections import OrderedDict
from channel import Channel
from blob_store import BlobStore


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
        blob_store: Optional[BlobStore] = None,
        jwt_secret: Optional[str] = None,
        jwt_algorithm: str = "HS256",
        jwt_expiry_hours: int = 24
    ):
        """
        Initialize the channel manager.

        Args:
            base_storage_dir: Base directory for channel storage
            max_cached_channels: Maximum number of channels to keep in memory
            redis_client: Optional Redis client for pub/sub (set to None if using consistent hashing)
            blob_store: Optional blob storage backend (shared across all channels)
            jwt_secret: JWT signing secret (shared across all channels)
            jwt_algorithm: JWT signing algorithm
            jwt_expiry_hours: JWT token expiry in hours
        """
        self.base_storage_dir = base_storage_dir
        self.max_cached_channels = max_cached_channels
        self.redis_client = redis_client
        self.blob_store = blob_store

        # JWT configuration (shared across all channels)
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.jwt_expiry_hours = jwt_expiry_hours

        # LRU cache: channel_id -> Channel instance
        self._channels: OrderedDict[str, Channel] = OrderedDict()

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
            if channel_id in self._channels:
                # Move to end (mark as recently used)
                self._channels.move_to_end(channel_id)
                return self._channels[channel_id]

            # Create new channel instance
            storage_dir = f"{self.base_storage_dir}/ch_{channel_id}"
            channel = Channel(
                channel_id=channel_id,
                storage_dir=storage_dir,
                blob_store=self.blob_store,
                jwt_secret=self.jwt_secret,
                jwt_algorithm=self.jwt_algorithm,
                jwt_expiry_hours=self.jwt_expiry_hours
            )

            # Add to cache
            self._channels[channel_id] = channel

            # Evict oldest channel if cache is full
            if len(self._channels) > self.max_cached_channels:
                # Remove least recently used (first item)
                oldest_id, oldest_channel = self._channels.popitem(last=False)
                oldest_channel.close()

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
            if channel_id in self._channels:
                channel = self._channels.pop(channel_id)
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
            for channel in self._channels.values():
                channel.close()
            self._channels.clear()
