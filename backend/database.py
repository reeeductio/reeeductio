"""
Database layer for E2EE messaging system using SQLite

Note: This class now only handles messages. State operations have been
moved to StateStore implementations (see state_store.py).
"""

import sqlite3
import json
from typing import Optional, List, Dict, Any, Union
from contextlib import contextmanager


class Database:
    """SQLite database for storing messages"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
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

    def _init_db(self):
        """Initialize database schema"""
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

    # ========================================================================
    # Message Operations
    # ========================================================================
    
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
    ):
        """Add a new message to a topic"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO messages
                (channel_id, topic_id, message_hash, prev_hash,
                 encrypted_payload, sender, signature, server_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                channel_id, topic_id, message_hash, prev_hash,
                encrypted_payload, sender, signature, server_timestamp
            ))
    
    def get_messages(
        self,
        channel_id: str,
        topic_id: str,
        from_ts: Optional[int] = None,
        to_ts: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query messages with time-based filtering"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT message_hash, topic_id, prev_hash,
                       encrypted_payload, sender, signature, server_timestamp
                FROM messages
                WHERE channel_id = ? AND topic_id = ?
            """
            params = [channel_id, topic_id]
            
            if from_ts is not None:
                query += " AND server_timestamp >= ?"
                params.append(from_ts)
            
            if to_ts is not None:
                query += " AND server_timestamp <= ?"
                params.append(to_ts)
            
            query += " ORDER BY server_timestamp DESC LIMIT ?"
            params.append(limit)
            
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
        message_hash: str
    ) -> Optional[Dict[str, Any]]:
        """Get a specific message by its hash"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT message_hash, topic_id, prev_hash,
                       encrypted_payload, sender, signature, server_timestamp
                FROM messages
                WHERE channel_id = ? AND message_hash = ?
            """, (channel_id, message_hash))

            row = cursor.fetchone()
            if not row:
                return None

            return {
                "message_hash": row["message_hash"],
                "topic_id": row["topic_id"],
                "prev_hash": row["prev_hash"],
                "encrypted_payload": row["encrypted_payload"],
                "sender": row["sender"],
                "signature": row["signature"],
                "server_timestamp": row["server_timestamp"]
            }
    
    def get_chain_head(
        self,
        channel_id: str,
        topic_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get the most recent message in a topic (chain head)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT message_hash
                FROM messages
                WHERE channel_id = ? AND topic_id = ?
                ORDER BY server_timestamp DESC
                LIMIT 1
            """, (channel_id, topic_id))

            row = cursor.fetchone()
            if not row:
                return None

            return {
                "message_hash": row["message_hash"]
            }
    
