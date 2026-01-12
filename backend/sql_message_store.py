"""
SQL-based implementation of MessageStore

Provides a common base class for SQL database implementations (SQLite, PostgreSQL, MySQL)
with database-agnostic SQL queries. Concrete classes only need to implement connection
management and placeholder formatting.
"""

from abc import abstractmethod
from typing import Optional, List, Dict, Any, ContextManager
from contextlib import contextmanager
from message_store import MessageStore
from exceptions import ChainConflictError


class SqlMessageStore(MessageStore):
    """
    Abstract SQL-based message store

    Implements all SQL logic using standard SQL syntax. Subclasses only need to:
    1. Implement __init__() with database-specific connection setup
    2. Implement get_connection() for database-specific connections
    3. Implement _get_placeholder() to return the appropriate parameter placeholder
    4. Optionally override _init_db() for database-specific schema tweaks
    """

    @abstractmethod
    def get_connection(self) -> ContextManager[Any]:
        """
        Context manager for database connections

        Must yield a connection object that:
        - Supports cursor() method
        - Supports commit() and rollback()
        - Has a row_factory that returns dict-like rows

        Implementations should use @contextmanager decorator.
        """
        pass

    @abstractmethod
    def _get_placeholder(self, position: int = 0) -> str:
        """
        Get the parameter placeholder for this database

        Args:
            position: Parameter position (0-indexed), used for PostgreSQL $1, $2, etc.

        Returns:
            - SQLite: "?"
            - PostgreSQL: "$1", "$2", etc.
            - MySQL: "%s"
        """
        pass

    def __init__(self):
        """Initialize the SQL message store"""
        super().__init__()

    def _init_db(self):
        """Initialize database schema"""
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Messages table - blockchain-style message chains
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    space_id TEXT NOT NULL,
                    topic_id TEXT NOT NULL,
                    message_hash TEXT NOT NULL PRIMARY KEY,
                    type TEXT NOT NULL,
                    prev_hash TEXT,
                    data TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    server_timestamp INTEGER NOT NULL
                )
            """)

            # Create indexes for message queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_topic
                ON messages(space_id, topic_id, server_timestamp)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_timestamp
                ON messages(space_id, topic_id, server_timestamp DESC)
            """)

            # Index for filtering by type (useful for state events)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_type
                ON messages(space_id, topic_id, type)
            """)

            # Tool usage table - operational metadata for use-limited tools
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tool_usage (
                    space_id TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    use_count INTEGER NOT NULL DEFAULT 0,
                    last_used_at INTEGER,
                    PRIMARY KEY (space_id, tool_id)
                )
            """)

            # Create index for faster tool usage queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_tool_usage_space
                ON tool_usage(space_id)
            """)

            conn.commit()

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
        Add a new message to a topic with atomic chain validation.

        This implements compare-and-swap (CAS) on the chain head to prevent
        race conditions. The transaction ensures atomicity between checking
        the current head and inserting the new message.

        Raises:
            ChainConflictError: If prev_hash doesn't match current chain head
        """
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Get current chain head (within transaction for atomicity)
            cursor.execute(f"""
                SELECT message_hash
                FROM messages
                WHERE space_id = {ph(0)} AND topic_id = {ph(1)}
                ORDER BY server_timestamp DESC
                LIMIT 1
            """, (space_id, topic_id))

            row = cursor.fetchone()
            current_head = row["message_hash"] if row else None

            # Validate chain continuity (CAS condition)
            if current_head != prev_hash:
                # Format error message with truncated hashes
                if current_head is None:
                    expected = "None (first message)"
                else:
                    expected = current_head[:16] + "..."
                if prev_hash is None:
                    got = "None"
                else:
                    got = prev_hash[:16] + "..."

                raise ChainConflictError(
                    f"Chain conflict in topic '{topic_id}': "
                    f"expected prev_hash={expected}, got {got}. "
                    f"Another message was added concurrently."
                )

            # Build query with appropriate placeholders
            placeholders = ", ".join([ph(i) for i in range(9)])

            # Insert message (chain validated - we own the new head)
            cursor.execute(f"""
                INSERT INTO messages
                (space_id, topic_id, message_hash, type, prev_hash,
                 data, sender, signature, server_timestamp)
                VALUES ({placeholders})
            """, (
                space_id, topic_id, message_hash, msg_type, prev_hash,
                data, sender, signature, server_timestamp
            ))

            # Transaction commits on context exit

        # Invalidate cache if present
        if self._cache is not None:
            # Invalidate chain head for this topic
            chain_head_key = f"chain_head:{space_id}:{topic_id}"
            self._cache.pop(chain_head_key, None)

    def get_messages(
        self,
        space_id: str,
        topic_id: str,
        from_ts: Optional[int] = None,
        to_ts: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query messages with time-based filtering"""
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT message_hash, topic_id, type, prev_hash,
                       data, sender, signature, server_timestamp
                FROM messages
                WHERE space_id = {0} AND topic_id = {1}
            """
            params: List[Any] = [space_id, topic_id]
            param_idx = 2

            if from_ts is not None:
                query += f" AND server_timestamp >= {{{param_idx}}}"
                params.append(from_ts)
                param_idx += 1

            if to_ts is not None:
                query += f" AND server_timestamp <= {{{param_idx}}}"
                params.append(to_ts)
                param_idx += 1

            query += f" ORDER BY server_timestamp DESC LIMIT {{{param_idx}}}"
            params.append(limit)

            # Format query with placeholders
            query = query.format(*[ph(i) for i in range(len(params))])

            cursor.execute(query, params)

            messages = []
            for row in cursor.fetchall():
                messages.append({
                    "message_hash": row["message_hash"],
                    "topic_id": row["topic_id"],
                    "type": row["type"],
                    "prev_hash": row["prev_hash"],
                    "data": row["data"],
                    "sender": row["sender"],
                    "signature": row["signature"],
                    "server_timestamp": row["server_timestamp"]
                })

            # Reverse to get chronological order
            messages.reverse()
            return messages

    def get_message_by_hash(
        self,
        space_id: str,
        topic_id: str,
        message_hash: str
    ) -> Optional[Dict[str, Any]]:
        """Get a specific message by its hash"""
        # Check cache if present
        if self._cache is not None:
            cache_key = f"message:{space_id}:{topic_id}:{message_hash}"
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT message_hash, topic_id, type, prev_hash,
                       data, sender, signature, server_timestamp
                FROM messages
                WHERE space_id = {ph(0)} AND topic_id = {ph(1)} AND message_hash = {ph(2)}
            """, (space_id, topic_id, message_hash))

            row = cursor.fetchone()
            if not row:
                return None

            result = {
                "message_hash": row["message_hash"],
                "topic_id": row["topic_id"],
                "type": row["type"],
                "prev_hash": row["prev_hash"],
                "data": row["data"],
                "sender": row["sender"],
                "signature": row["signature"],
                "server_timestamp": row["server_timestamp"]
            }

            # Store in cache if present
            if self._cache is not None:
                cache_key = f"message:{space_id}:{topic_id}:{message_hash}"
                self._cache.set(cache_key, result)

            return result

    def get_chain_head(
        self,
        space_id: str,
        topic_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get the most recent message in a topic (chain head)"""
        # Check cache if present
        if self._cache is not None:
            cache_key = f"chain_head:{space_id}:{topic_id}"
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT message_hash
                FROM messages
                WHERE space_id = {ph(0)} AND topic_id = {ph(1)}
                ORDER BY server_timestamp DESC
                LIMIT 1
            """, (space_id, topic_id))

            row = cursor.fetchone()
            if not row:
                return None

            result = {
                "message_hash": row["message_hash"]
            }

            # Store in cache if present
            if self._cache is not None:
                cache_key = f"chain_head:{space_id}:{topic_id}"
                self._cache.set(cache_key, result)

            return result

    def get_most_recent_message(
        self,
        space_id: str,
        topic_id: str,
        type: str
    ) -> Optional[Dict[str, Any]]:
        """Get the most recent message of a given type"""
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT message_hash, topic_id, type, prev_hash,
                       data, sender, signature, server_timestamp
                FROM messages
                WHERE space_id = {ph(0)} AND topic_id = {ph(1)} AND type = {ph(2)}
                ORDER BY server_timestamp DESC
                LIMIT 1
            """, (space_id, topic_id, type))

            row = cursor.fetchone()
            if not row:
                return None

            return {
                "message_hash": row["message_hash"],
                "topic_id": row["topic_id"],
                "type": row["type"],
                "prev_hash": row["prev_hash"],
                "data": row["data"],
                "sender": row["sender"],
                "signature": row["signature"],
                "server_timestamp": row["server_timestamp"]
            }

    def initialize_tool_usage(self, space_id: str, tool_id: str) -> None:
        """
        Initialize tool usage tracking for a use-limited tool.
        Creates a row with use_count=0.
        """
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()
            placeholders = ", ".join([ph(i) for i in range(3)])
            cursor.execute(f"""
                INSERT INTO tool_usage
                (space_id, tool_id, use_count)
                VALUES ({placeholders})
            """, (space_id, tool_id, 0))

    def increment_tool_usage(self, space_id: str, tool_id: str, timestamp: int) -> int:
        """
        Increment tool use count and return new count.

        This is operational metadata (NOT part of space state).
        Used to track and enforce use_limit for tools.

        NOTE: Assumes initialize_tool_usage has been called for this tool.

        Args:
            space_id: Space identifier
            tool_id: Tool identifier (T_*)
            timestamp: Current timestamp in milliseconds

        Returns:
            New use count after increment
        """
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Update existing row (should always exist for use-limited tools)
            # Note: Parameters must be in order they appear in SQL, not by ph() number
            cursor.execute(f"""
                UPDATE tool_usage
                SET use_count = use_count + 1, last_used_at = {ph(0)}
                WHERE space_id = {ph(1)} AND tool_id = {ph(2)}
            """, (timestamp, space_id, tool_id))

            if cursor.rowcount == 0:
                raise ValueError(f"Tool {tool_id} not initialized for space {space_id}")

            # Get updated count
            cursor.execute(f"""
                SELECT use_count
                FROM tool_usage
                WHERE space_id = {ph(0)} AND tool_id = {ph(1)}
            """, (space_id, tool_id))

            row = cursor.fetchone()
            return row["use_count"]

    def get_tool_usage(self, space_id: str, tool_id: str) -> Optional[Dict[str, Any]]:
        """
        Get tool usage statistics.

        This is operational metadata (NOT part of space state).

        Args:
            space_id: Space identifier
            tool_id: Tool identifier (T_*)

        Returns:
            Dictionary with use_count and last_used_at, or None if not found
        """
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT use_count, last_used_at
                FROM tool_usage
                WHERE space_id = {ph(0)} AND tool_id = {ph(1)}
            """, (space_id, tool_id))

            row = cursor.fetchone()
            if not row:
                return None

            return {
                "use_count": row["use_count"],
                "last_used_at": row["last_used_at"]
            }
