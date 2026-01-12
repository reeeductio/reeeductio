from state_store import StateStore
from message_store import MessageStore
from lru_cache import LRUCache

from typing import Any, Dict, List, Optional

class EventSourcedStateStore(StateStore):

    def __init__(self,
                 message_store: MessageStore
    ):
        self.message_store = message_store
        self._cache = LRUCache()

    def get_state(
        self,
        space_id: str,
        path: str
    ) -> Optional[Dict[str, Any]]:
        
        # First check the cache
        if self._cache != None:
            cached_msg = self._cache.get(path)
            if cached_msg != None:
                return cached_msg
        
        # Fetch the result from the message store
        msg = self.message_store.get_most_recent_message(
            space_id=space_id,
            topic_id="state",
            type=path
        )

        # Update the cache
        if msg != None and self._cache != None:
            self._cache.set(path, msg)

        return msg

    def list_state(
        self,
        space_id: str,
        prefix: str
    ) -> List[Dict[str, Any]]:
        """
        List all state entries matching a prefix

        Retrieves all messages from the state topic, filters by prefix,
        and returns only the most recent message for each unique path.
        """
        # FIXME: Add a MessageStore.get_messages_with_prefix() function to make this more efficient

        # Get all messages from the state topic
        # We use a large limit to get all messages - this could be optimized
        # with pagination if state topics become very large
        all_messages = self.message_store.get_messages(
            space_id=space_id,
            topic_id="state",
            limit=10000  # Large enough for most use cases
        )

        # Filter messages that match the prefix and group by path (type)
        # Keep only the most recent message for each path
        path_to_latest: Dict[str, Dict[str, Any]] = {}

        for msg in all_messages:
            path = msg["type"]

            # Check if path matches prefix
            if not path.startswith(prefix):
                continue

            # Keep only the most recent message for this path
            if path not in path_to_latest:
                path_to_latest[path] = msg
            else:
                # Compare timestamps to keep the most recent
                if msg["server_timestamp"] > path_to_latest[path]["server_timestamp"]:
                    path_to_latest[path] = msg

        # Sort by path lexicographically and return as list
        result = [path_to_latest[path] for path in sorted(path_to_latest.keys())]

        return result
