"""
Local SQLite message store for client-side caching.

Provides offline access and reduces network requests by caching
messages fetched from the server.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .models import Message


class LocalMessageStore:
    """
    Local SQLite cache for messages.

    This is a read-through cache for messages fetched from the server.
    It does not perform chain validation (the server is authoritative).

    Usage:
        store = LocalMessageStore("~/.reeeductio/cache.db")

        # Store messages fetched from server
        store.put_message(space_id, message)

        # Retrieve cached messages
        messages = store.get_messages(space_id, topic_id, limit=100)

        # Check if a message exists locally
        msg = store.get_message(space_id, topic_id, message_hash)
    """

    def __init__(self, db_path: str | Path):
        """
        Initialize local message store.

        Args:
            db_path: Path to SQLite database file. Parent directories
                     will be created if they don't exist.
        """
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    message_hash TEXT PRIMARY KEY,
                    space_id TEXT NOT NULL,
                    topic_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    prev_hash TEXT,
                    data TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    server_timestamp INTEGER NOT NULL
                )
            """)

            # Index for querying by topic and timestamp
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_topic_time
                ON messages(space_id, topic_id, server_timestamp)
            """)

            # Index for querying by type (useful for state lookups)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_type
                ON messages(space_id, topic_id, type)
            """)

    def put_message(self, space_id: str, message: Message) -> None:
        """
        Store a message in the local cache.

        Args:
            space_id: Space the message belongs to
            message: Message to store
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO messages
                (message_hash, space_id, topic_id, type, prev_hash,
                 data, sender, signature, server_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message.message_hash,
                    space_id,
                    message.topic_id,
                    message.type,
                    message.prev_hash,
                    message.data,
                    message.sender,
                    message.signature,
                    message.server_timestamp,
                ),
            )

    def put_messages(self, space_id: str, messages: list[Message]) -> None:
        """
        Store multiple messages in the local cache.

        Args:
            space_id: Space the messages belong to
            messages: Messages to store
        """
        if not messages:
            return

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(
                """
                INSERT OR REPLACE INTO messages
                (message_hash, space_id, topic_id, type, prev_hash,
                 data, sender, signature, server_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        msg.message_hash,
                        space_id,
                        msg.topic_id,
                        msg.type,
                        msg.prev_hash,
                        msg.data,
                        msg.sender,
                        msg.signature,
                        msg.server_timestamp,
                    )
                    for msg in messages
                ],
            )

    def get_message(
        self, space_id: str, topic_id: str, message_hash: str
    ) -> Message | None:
        """
        Get a specific message by hash.

        Args:
            space_id: Space identifier
            topic_id: Topic identifier
            message_hash: Message hash to look up

        Returns:
            Message if found, None otherwise
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT message_hash, topic_id, type, prev_hash,
                       data, sender, signature, server_timestamp
                FROM messages
                WHERE space_id = ? AND topic_id = ? AND message_hash = ?
                """,
                (space_id, topic_id, message_hash),
            )
            row = cursor.fetchone()
            if not row:
                return None

            return Message(
                message_hash=row["message_hash"],
                topic_id=row["topic_id"],
                type=row["type"],
                prev_hash=row["prev_hash"],
                data=row["data"],
                sender=row["sender"],
                signature=row["signature"],
                server_timestamp=row["server_timestamp"],
            )

    def get_messages(
        self,
        space_id: str,
        topic_id: str,
        from_timestamp: int | None = None,
        to_timestamp: int | None = None,
        limit: int = 100,
    ) -> list[Message]:
        """
        Get messages from a topic with optional time filtering.

        Args:
            space_id: Space identifier
            topic_id: Topic identifier
            from_timestamp: Optional start timestamp (inclusive, milliseconds)
            to_timestamp: Optional end timestamp (inclusive, milliseconds)
            limit: Maximum number of messages to return

        Returns:
            List of messages, ordered by timestamp.
            If from_timestamp > to_timestamp, returns in descending order.
        """
        # Determine sort order based on timestamp range
        reverse_order = (
            from_timestamp is not None
            and to_timestamp is not None
            and from_timestamp > to_timestamp
        )
        range_start = to_timestamp if reverse_order else from_timestamp
        range_end = from_timestamp if reverse_order else to_timestamp

        with self._connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT message_hash, topic_id, type, prev_hash,
                       data, sender, signature, server_timestamp
                FROM messages
                WHERE space_id = ? AND topic_id = ?
            """
            params: list = [space_id, topic_id]

            if range_start is not None:
                query += " AND server_timestamp >= ?"
                params.append(range_start)

            if range_end is not None:
                query += " AND server_timestamp <= ?"
                params.append(range_end)

            order = "DESC" if reverse_order else "ASC"
            query += f" ORDER BY server_timestamp {order} LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)

            return [
                Message(
                    message_hash=row["message_hash"],
                    topic_id=row["topic_id"],
                    type=row["type"],
                    prev_hash=row["prev_hash"],
                    data=row["data"],
                    sender=row["sender"],
                    signature=row["signature"],
                    server_timestamp=row["server_timestamp"],
                )
                for row in cursor.fetchall()
            ]

    def get_latest_message(
        self, space_id: str, topic_id: str, msg_type: str | None = None
    ) -> Message | None:
        """
        Get the most recent message in a topic.

        Args:
            space_id: Space identifier
            topic_id: Topic identifier
            msg_type: Optional message type filter

        Returns:
            Most recent message, or None if topic is empty
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            if msg_type is not None:
                cursor.execute(
                    """
                    SELECT message_hash, topic_id, type, prev_hash,
                           data, sender, signature, server_timestamp
                    FROM messages
                    WHERE space_id = ? AND topic_id = ? AND type = ?
                    ORDER BY server_timestamp DESC
                    LIMIT 1
                    """,
                    (space_id, topic_id, msg_type),
                )
            else:
                cursor.execute(
                    """
                    SELECT message_hash, topic_id, type, prev_hash,
                           data, sender, signature, server_timestamp
                    FROM messages
                    WHERE space_id = ? AND topic_id = ?
                    ORDER BY server_timestamp DESC
                    LIMIT 1
                    """,
                    (space_id, topic_id),
                )

            row = cursor.fetchone()
            if not row:
                return None

            return Message(
                message_hash=row["message_hash"],
                topic_id=row["topic_id"],
                type=row["type"],
                prev_hash=row["prev_hash"],
                data=row["data"],
                sender=row["sender"],
                signature=row["signature"],
                server_timestamp=row["server_timestamp"],
            )

    def get_latest_timestamp(self, space_id: str, topic_id: str) -> int | None:
        """
        Get the timestamp of the most recent cached message.

        Useful for fetching only newer messages from the server.

        Args:
            space_id: Space identifier
            topic_id: Topic identifier

        Returns:
            Timestamp in milliseconds, or None if no messages cached
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT MAX(server_timestamp) as max_ts
                FROM messages
                WHERE space_id = ? AND topic_id = ?
                """,
                (space_id, topic_id),
            )
            row = cursor.fetchone()
            return row["max_ts"] if row and row["max_ts"] is not None else None

    def delete_messages(
        self,
        space_id: str,
        topic_id: str | None = None,
        before_timestamp: int | None = None,
    ) -> int:
        """
        Delete cached messages.

        Args:
            space_id: Space identifier
            topic_id: Optional topic filter (delete all topics if None)
            before_timestamp: Optional timestamp filter (delete older messages)

        Returns:
            Number of messages deleted
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            query = "DELETE FROM messages WHERE space_id = ?"
            params: list = [space_id]

            if topic_id is not None:
                query += " AND topic_id = ?"
                params.append(topic_id)

            if before_timestamp is not None:
                query += " AND server_timestamp < ?"
                params.append(before_timestamp)

            cursor.execute(query, params)
            return cursor.rowcount

    def clear(self) -> None:
        """Delete all cached messages."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM messages")

    def count_messages(self, space_id: str | None = None) -> int:
        """
        Count cached messages.

        Args:
            space_id: Optional space filter

        Returns:
            Number of messages in cache
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            if space_id is not None:
                cursor.execute(
                    "SELECT COUNT(*) as cnt FROM messages WHERE space_id = ?",
                    (space_id,),
                )
            else:
                cursor.execute("SELECT COUNT(*) as cnt FROM messages")
            row = cursor.fetchone()
            return row["cnt"]
