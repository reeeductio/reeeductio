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
        channel_id: str,
        topic_id: str,
        message_hash: str,
        prev_hash: Optional[str],
        encrypted_payload: str,
        sender: str,
        signature: str,
        server_timestamp: int
    ) -> None:
        """
        Add a new message to a topic

        Args:
            channel_id: Channel identifier
            topic_id: Topic identifier within the channel
            message_hash: Content-addressed hash of the message
            prev_hash: Hash of the previous message in the chain (None for first message)
            encrypted_payload: Encrypted message content
            sender: Public key of the sender
            signature: Cryptographic signature of the message
            server_timestamp: Unix timestamp when server received the message
        """
        pass

    @abstractmethod
    def get_messages(
        self,
        channel_id: str,
        topic_id: str,
        from_ts: Optional[int] = None,
        to_ts: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query messages with time-based filtering

        Args:
            channel_id: Channel identifier
            topic_id: Topic identifier within the channel
            from_ts: Optional start timestamp (inclusive)
            to_ts: Optional end timestamp (inclusive)
            limit: Maximum number of messages to return

        Returns:
            List of message dictionaries in chronological order, each containing:
                - message_hash: Content-addressed hash of the message
                - topic_id: Topic identifier
                - prev_hash: Hash of previous message in chain
                - encrypted_payload: Encrypted message content
                - sender: Public key of sender
                - signature: Cryptographic signature
                - server_timestamp: Unix timestamp from server
        """
        pass

    @abstractmethod
    def get_message_by_hash(
        self,
        channel_id: str,
        topic_id: str,
        message_hash: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get a specific message by its hash

        Args:
            channel_id: Channel identifier
            topic_id: Topic identifier within the channel
            message_hash: Content-addressed hash of the message

        Returns:
            Dictionary containing:
                - message_hash: Content-addressed hash of the message
                - topic_id: Topic identifier
                - prev_hash: Hash of previous message in chain
                - encrypted_payload: Encrypted message content
                - sender: Public key of sender
                - signature: Cryptographic signature
                - server_timestamp: Unix timestamp from server
            None if message doesn't exist
        """
        pass

    @abstractmethod
    def get_chain_head(
        self,
        channel_id: str,
        topic_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get the most recent message in a topic (chain head)

        Args:
            channel_id: Channel identifier
            topic_id: Topic identifier within the channel

        Returns:
            Dictionary containing:
                - message_hash: Hash of the most recent message
            None if topic has no messages
        """
        pass
