"""
Key-value storage abstraction layer for E2EE messaging system

Provides a base DataStore interface and concrete implementations for
storing legacy space data in different backends (SQLite, LMDB, DynamoDB, etc.)

Note: This is the legacy data storage system. New state storage should use
the event-sourced StateStore which stores state as messages in the message chain.
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Union
from lru_cache import LRUCache


class DataStore(ABC):
    """Abstract base class for legacy data storage backends"""

    def __init__(self):
        """
        Initialize the data store.

        Subclasses should call super().__init__() and optionally initialize
        the cache for local storage backends.
        """
        # Optional cache for local storage backends (SQLite, LMDB)
        # Remote storage backends (DynamoDB, etc.) should leave this as None
        # to avoid cache coherency issues across multiple application instances
        self._cache: Optional[LRUCache] = None

    @abstractmethod
    def get_data(
        self,
        space_id: str,
        path: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get data value by path

        Args:
            space_id: Space identifier
            path: Data path (e.g., "/members/alice")

        Returns:
            Dictionary containing:
                - path: The data path
                - data: The data value (base64-encoded string)
                - signature: Ed25519 signature over (path + data + signed_at)
                - signed_by: Public key of who signed this entry
                - signed_at: Unix timestamp in milliseconds when entry was signed
            None if entry doesn't exist
        """
        pass

    @abstractmethod
    def set_data(
        self,
        space_id: str,
        path: str,
        data: str,
        signature: str,
        signed_by: str,
        signed_at: int
    ) -> None:
        """
        Set data value (create or update)

        Args:
            space_id: Space identifier
            path: Data path
            data: Data value (base64-encoded string)
            signature: Ed25519 signature over (path + data + signed_at)
            signed_by: Public key of who signed this entry
            signed_at: Unix timestamp in milliseconds when entry was signed
        """
        pass

    @abstractmethod
    def delete_data(self, space_id: str, path: str) -> bool:
        """
        Delete data value

        Args:
            space_id: Space identifier
            path: Data path

        Returns:
            True if data was deleted, False if it didn't exist
        """
        pass

    @abstractmethod
    def list_data(
        self,
        space_id: str,
        prefix: str
    ) -> List[Dict[str, Any]]:
        """
        List all data entries matching a prefix (must be ordered by path)

        Args:
            space_id: Space identifier
            prefix: Path prefix to match (e.g., "/members/")

        Returns:
            List of dictionaries, each containing:
                - path: Full data path
                - data: The data value (base64-encoded string)
                - signature: Ed25519 signature over (path + data + signed_at)
                - signed_by: Public key of who signed this entry
                - signed_at: Unix timestamp in milliseconds when entry was signed
            Results are ordered by path lexicographically
        """
        pass
