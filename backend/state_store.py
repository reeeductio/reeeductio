"""
State storage abstraction layer for E2EE messaging system

Provides a base StateStore interface for concrete implementations for
storing space state.  Currently the only implementation is event-sourced
state (EventSourcedStateStore).
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Union
from lru_cache import LRUCache


class StateStore(ABC):
    """Abstract base class for state storage backends"""

    def __init__(self):
        """
        Initialize the state store.

        Subclasses should call super().__init__() and optionally initialize
        the cache for local storage backends.
        """
        # Optional cache for local storage backends (SQLite, LMDB)
        # Remote storage backends (DynamoDB, etc.) should leave this as None
        # to avoid cache coherency issues across multiple application instances
        self._cache: Optional[LRUCache] = None

    @abstractmethod
    def get_state(
        self,
        space_id: str,
        path: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get state value by path

        Args:
            space_id: Space identifier
            path: State path (e.g., "profiles/alice")

        Returns:
            Dictionary containing:
                - message_hash: Hash of the current state message for the requested path
                - topic_id: Topic identifier
                - type: Message type (== state path)
                - prev_hash: Hash of previous message in chain
                - data: Message data (base64 encoded)
                - sender: Public key of sender
                - signature: Cryptographic signature
                - server_timestamp: Unix timestamp from server
            None if state doesn't exist
        """
        pass


    @abstractmethod
    def list_state(
        self,
        space_id: str,
        prefix: str
    ) -> List[Dict[str, Any]]:
        """
        List all state entries matching a prefix (must be ordered by path)

        Args:
            space_id: Space identifier
            prefix: Path prefix to match (e.g., "users/")

        Returns:
            List of dictionaries, each containing:
                - message_hash: Hash of the current state message for the given path
                - topic_id: Topic identifier
                - type: Message type (== state path)
                - prev_hash: Hash of previous message in chain
                - data: Message data (base64 encoded)
                - sender: Public key of sender
                - signature: Cryptographic signature
                - server_timestamp: Unix timestamp from server
            Results are ordered by path lexicographically
        """
        pass

 
    def invalidate_cache(
            self,
            path: str
    ):
        """
        Clear any cached value for the given path

        Args:
            path: State path (e.g., "profiles/alice")
        """
        if self._cache is not None:
            self._cache.delete(path)
