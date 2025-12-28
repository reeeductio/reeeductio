"""
State storage abstraction layer for E2EE messaging system

Provides a base StateManager interface and concrete implementations for
storing channel state in different backends (SQLite, LMDB, DynamoDB, etc.)
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Union


class StateManager(ABC):
    """Abstract base class for state storage backends"""

    @abstractmethod
    def get_state(
        self,
        channel_id: str,
        path: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get state value by path

        Args:
            channel_id: Channel identifier
            path: State path (e.g., "/state/members/alice")

        Returns:
            Dictionary containing:
                - data: The state data (dict if plaintext, str if encrypted)
                - encrypted: Boolean indicating if data is encrypted
                - updated_by: Public key of who last updated this state
                - updated_at: Unix timestamp of last update
            None if state doesn't exist
        """
        pass

    @abstractmethod
    def set_state(
        self,
        channel_id: str,
        path: str,
        data: Union[Dict, str],
        encrypted: bool,
        updated_by: str,
        updated_at: int
    ) -> None:
        """
        Set state value (create or update)

        Args:
            channel_id: Channel identifier
            path: State path
            data: State data (dict for plaintext, str for encrypted)
            encrypted: Whether the data is encrypted
            updated_by: Public key of who is updating this state
            updated_at: Unix timestamp of update
        """
        pass

    @abstractmethod
    def delete_state(self, channel_id: str, path: str) -> bool:
        """
        Delete state value

        Args:
            channel_id: Channel identifier
            path: State path

        Returns:
            True if state was deleted, False if it didn't exist
        """
        pass

    @abstractmethod
    def list_state(
        self,
        channel_id: str,
        prefix: str
    ) -> List[Dict[str, Any]]:
        """
        List all state entries matching a prefix (must be ordered by path)

        Args:
            channel_id: Channel identifier
            prefix: Path prefix to match (e.g., "/state/members/")

        Returns:
            List of dictionaries, each containing:
                - path: Full state path
                - data: The state data (dict if plaintext, str if encrypted)
                - encrypted: Boolean indicating if data is encrypted
                - updated_by: Public key of who last updated this state
                - updated_at: Unix timestamp of last update
            Results are ordered by path lexicographically
        """
        pass
