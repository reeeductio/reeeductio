"""
State storage abstraction layer for E2EE messaging system

Provides a base DataStore interface and concrete implementations for
storing space state in different backends (SQLite, LMDB, DynamoDB, etc.)
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Union
from lru_cache import LRUCache


class DataStore(ABC):
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
            path: State path (e.g., "/state/members/alice")

        Returns:
            Dictionary containing:
                - path: The state path
                - data: The state data (base64-encoded string)
                - signature: Ed25519 signature over (path + data + signed_at)
                - signed_by: Public key of who signed this state entry
                - signed_at: Unix timestamp in milliseconds when entry was signed
            None if state doesn't exist
        """
        pass

    @abstractmethod
    def set_state(
        self,
        space_id: str,
        path: str,
        data: str,
        signature: str,
        signed_by: str,
        signed_at: int
    ) -> None:
        """
        Set state value (create or update)

        Args:
            space_id: Space identifier
            path: State path
            data: State data (base64-encoded string)
            signature: Ed25519 signature over (path + data + signed_at)
            signed_by: Public key of who signed this state entry
            signed_at: Unix timestamp in milliseconds when entry was signed
        """
        pass

    @abstractmethod
    def delete_state(self, space_id: str, path: str) -> bool:
        """
        Delete state value

        Args:
            space_id: Space identifier
            path: State path

        Returns:
            True if state was deleted, False if it didn't exist
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
            prefix: Path prefix to match (e.g., "/state/members/")

        Returns:
            List of dictionaries, each containing:
                - path: Full state path
                - data: The state data (base64-encoded string)
                - signature: Ed25519 signature over (path + data + signed_at)
                - signed_by: Public key of who signed this state entry
                - signed_at: Unix timestamp in milliseconds when entry was signed
            Results are ordered by path lexicographically
        """
        pass

    @abstractmethod
    def initialize_tool_usage(self, space_id: str, tool_id: str) -> None:
        """
        Initialize tool usage tracking for a use-limited tool.

        This should be called when a tool with use_limit is created.
        Creates a row with use_count=0 so that increment_tool_usage can always UPDATE.

        Args:
            space_id: Space identifier
            tool_id: Tool identifier (T_*)
        """
        pass

    @abstractmethod
    def increment_tool_usage(self, space_id: str, tool_id: str, timestamp: int) -> int:
        """
        Increment tool use count and return new count.

        This is operational metadata (NOT part of space state).
        Used to track and enforce use_limit for tools.

        NOTE: Assumes initialize_tool_usage has been called for this tool.
        Will only UPDATE (never INSERT).

        Args:
            space_id: Space identifier
            tool_id: Tool identifier (T_*)
            timestamp: Current timestamp in milliseconds

        Returns:
            New use count after increment
        """
        pass

    @abstractmethod
    def get_tool_usage(self, space_id: str, tool_id: str) -> Optional[Dict[str, Any]]:
        """
        Get tool usage statistics.

        This is operational metadata (NOT part of space state).

        Args:
            space_id: Space identifier
            tool_id: Tool identifier (T_*)

        Returns:
            Dictionary with use_count and last_used_at, or None if tool has not been used
        """
        pass
