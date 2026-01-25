"""
Message storage abstraction layer for E2EE messaging system

Provides a base MessageStore interface and concrete implementations for
storing messages in different backends (SQLite, PostgreSQL, etc.)
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from lru_cache import LRUCache


class MessageStore(ABC):
    """Abstract base class for message storage backends"""

    def __init__(self):
        """
        Initialize the message store.

        Subclasses should call super().__init__() and optionally initialize
        the cache for local storage backends.
        """
        # Optional cache for local storage backends (SQLite)
        # Remote storage backends (PostgreSQL, MySQL) should leave this as None
        # to avoid cache coherency issues across multiple application instances
        self._cache: Optional[LRUCache] = None

    @abstractmethod
    def add_message(
        self,
        space_id: str,
        topic_id: str,
        message_hash: str,
        msg_type: str,
        prev_hash: Optional[str],
        data: str,
        sender: str,
        signature: str,
        server_timestamp: int
    ) -> None:
        """
        Add a new message to a topic

        Args:
            space_id: Space identifier
            topic_id: Topic identifier within the space
            message_hash: Content-addressed hash of the message
            msg_type: Message type (e.g., "chat.text") or state path (e.g., "/auth/users/U_alice/rights/cap_123")
            prev_hash: Hash of the previous message in the chain (None for first message)
            data: Message data (encrypted for chat, base64 state data for state events)
            sender: Public key of the sender
            signature: Cryptographic signature of the message
            server_timestamp: Unix timestamp when server received the message
        """
        pass

    @abstractmethod
    def get_messages(
        self,
        space_id: str,
        topic_id: str,
        from_ts: Optional[int] = None,
        to_ts: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query messages with time-based filtering.

        Ordering:
        - If from_ts and to_ts are both provided and from_ts > to_ts, return results
          in reverse-chronological order (newest first).
        - Otherwise return results in chronological order (oldest first).

        Args:
            space_id: Space identifier
            topic_id: Topic identifier within the space
            from_ts: Optional start timestamp (inclusive)
            to_ts: Optional end timestamp (inclusive)
            limit: Maximum number of messages to return

        Returns:
            List of message dictionaries in the requested order, each containing:
                - message_hash: Content-addressed hash of the message
                - topic_id: Topic identifier
                - type: Message type or state path
                - prev_hash: Hash of previous message in chain
                - data: Message data (encrypted for chat, base64 for state)
                - sender: Public key of sender
                - signature: Cryptographic signature
                - server_timestamp: Unix timestamp from server
        """
        pass

    @abstractmethod
    def get_message_by_hash(
        self,
        space_id: str,
        topic_id: str,
        message_hash: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get a specific message by its hash

        Args:
            space_id: Space identifier
            topic_id: Topic identifier within the space
            message_hash: Content-addressed hash of the message

        Returns:
            Dictionary containing:
                - message_hash: Content-addressed hash of the message
                - topic_id: Topic identifier
                - type: Message type or state path
                - prev_hash: Hash of previous message in chain
                - data: Message data (encrypted for chat, base64 for state)
                - sender: Public key of sender
                - signature: Cryptographic signature
                - server_timestamp: Unix timestamp from server
            None if message doesn't exist
        """
        pass

    @abstractmethod
    def get_chain_head(
        self,
        space_id: str,
        topic_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get the most recent message in a topic (chain head)

        Args:
            space_id: Space identifier
            topic_id: Topic identifier within the space

        Returns:
            Dictionary containing:
                - message_hash: Hash of the most recent message
            None if topic has no messages
        """
        pass

    @abstractmethod
    def get_most_recent_message(
        self,
        space_id: str,
        topic_id: str,
        type: str
    ) -> Optional[Dict[str,Any]]:
        """
        Get the most recent message of a given type

        Args:
            space_id: Space identifier
            topic_id: Topic identifier within the space
            type: Message type within the topic

        Returns:
            Dictionary containing:
                - message_hash: Hash of the most recent message
                - topic_id: Topic identifier
                - type: Message type or state path
                - prev_hash: Hash of previous message in chain
                - data: Message data (encrypted for chat, base64 for state)
                - sender: Public key of sender
                - signature: Cryptographic signature
                - server_timestamp: Unix timestamp from server
            None if topic has no messages
        """

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
