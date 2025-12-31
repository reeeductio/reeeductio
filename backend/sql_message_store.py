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
                    channel_id TEXT NOT NULL,
                    topic_id TEXT NOT NULL,
                    message_hash TEXT NOT NULL PRIMARY KEY,
                    prev_hash TEXT,
                    encrypted_payload TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    server_timestamp INTEGER NOT NULL
                )
            """)

            # Create indexes for message queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_topic
                ON messages(channel_id, topic_id, server_timestamp)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_timestamp
                ON messages(channel_id, topic_id, server_timestamp DESC)
            """)

            conn.commit()

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
        """Add a new message to a topic"""
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Build query with appropriate placeholders
            placeholders = ", ".join([ph(i) for i in range(8)])

            cursor.execute(f"""
                INSERT INTO messages
                (channel_id, topic_id, message_hash, prev_hash,
                 encrypted_payload, sender, signature, server_timestamp)
                VALUES ({placeholders})
            """, (
                channel_id, topic_id, message_hash, prev_hash,
                encrypted_payload, sender, signature, server_timestamp
            ))

        # Invalidate cache if present
        if self._cache is not None:
            # Invalidate chain head for this topic
            chain_head_key = f"chain_head:{channel_id}:{topic_id}"
            self._cache.pop(chain_head_key, None)

    def get_messages(
        self,
        channel_id: str,
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
                SELECT message_hash, topic_id, prev_hash,
                       encrypted_payload, sender, signature, server_timestamp
                FROM messages
                WHERE channel_id = {0} AND topic_id = {1}
            """
            params: List[Any] = [channel_id, topic_id]
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
                    "prev_hash": row["prev_hash"],
                    "encrypted_payload": row["encrypted_payload"],
                    "sender": row["sender"],
                    "signature": row["signature"],
                    "server_timestamp": row["server_timestamp"]
                })

            # Reverse to get chronological order
            messages.reverse()
            return messages

    def get_message_by_hash(
        self,
        channel_id: str,
        topic_id: str,
        message_hash: str
    ) -> Optional[Dict[str, Any]]:
        """Get a specific message by its hash"""
        # Check cache if present
        if self._cache is not None:
            cache_key = f"message:{channel_id}:{topic_id}:{message_hash}"
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT message_hash, topic_id, prev_hash,
                       encrypted_payload, sender, signature, server_timestamp
                FROM messages
                WHERE channel_id = {ph(0)} AND topic_id = {ph(1)} AND message_hash = {ph(2)}
            """, (channel_id, topic_id, message_hash))

            row = cursor.fetchone()
            if not row:
                return None

            result = {
                "message_hash": row["message_hash"],
                "topic_id": row["topic_id"],
                "prev_hash": row["prev_hash"],
                "encrypted_payload": row["encrypted_payload"],
                "sender": row["sender"],
                "signature": row["signature"],
                "server_timestamp": row["server_timestamp"]
            }

            # Store in cache if present
            if self._cache is not None:
                cache_key = f"message:{channel_id}:{topic_id}:{message_hash}"
                self._cache.set(cache_key, result)

            return result

    def get_chain_head(
        self,
        channel_id: str,
        topic_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get the most recent message in a topic (chain head)"""
        # Check cache if present
        if self._cache is not None:
            cache_key = f"chain_head:{channel_id}:{topic_id}"
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT message_hash
                FROM messages
                WHERE channel_id = {ph(0)} AND topic_id = {ph(1)}
                ORDER BY server_timestamp DESC
                LIMIT 1
            """, (channel_id, topic_id))

            row = cursor.fetchone()
            if not row:
                return None

            result = {
                "message_hash": row["message_hash"]
            }

            # Store in cache if present
            if self._cache is not None:
                cache_key = f"chain_head:{channel_id}:{topic_id}"
                self._cache.set(cache_key, result)

            return result
