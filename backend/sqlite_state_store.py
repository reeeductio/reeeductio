"""
SQLite implementation of StateStore

Stores channel state in a SQLite database with support for both
plaintext and encrypted state values.
"""

import sqlite3
import json
from typing import Optional, List, Dict, Any, Union
from contextlib import contextmanager
from state_store import StateStore


class SqliteStateStore(StateStore):
    """Store channel state in SQLite database"""

    def __init__(self, db_path: str):
        """
        Initialize SQLite state storage

        Args:
            db_path: Path to SQLite database file
        """
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

            # State table - stores all channel state (members, capabilities, metadata)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS state (
                    channel_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    data TEXT NOT NULL,
                    encrypted BOOLEAN NOT NULL,
                    updated_by TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (channel_id, path)
                )
            """)

            # Create index for faster state queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_state_channel
                ON state(channel_id)
            """)

            conn.commit()

    def get_state(
        self,
        channel_id: str,
        path: str
    ) -> Optional[Dict[str, Any]]:
        """Get state value by path"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT data, encrypted, updated_by, updated_at
                FROM state
                WHERE channel_id = ? AND path = ?
            """, (channel_id, path))

            row = cursor.fetchone()
            if not row:
                return None

            # Parse data (JSON if not encrypted, string if encrypted)
            data = row["data"]
            if not row["encrypted"]:
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    pass  # Keep as string if not valid JSON

            return {
                "data": data,
                "encrypted": bool(row["encrypted"]),
                "updated_by": row["updated_by"],
                "updated_at": row["updated_at"]
            }

    def set_state(
        self,
        channel_id: str,
        path: str,
        data: Union[Dict, str],
        encrypted: bool,
        updated_by: str,
        updated_at: int
    ) -> None:
        """Set state value"""
        # Serialize data
        if isinstance(data, dict):
            data_str = json.dumps(data)
        else:
            data_str = data

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO state
                (channel_id, path, data, encrypted, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (channel_id, path, data_str, encrypted, updated_by, updated_at))

    def delete_state(self, channel_id: str, path: str) -> bool:
        """Delete state value"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM state
                WHERE channel_id = ? AND path = ?
            """, (channel_id, path))
            return cursor.rowcount > 0

    def list_state(
        self,
        channel_id: str,
        prefix: str
    ) -> List[Dict[str, Any]]:
        """List all state entries matching a prefix"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT path, data, encrypted, updated_by, updated_at
                FROM state
                WHERE channel_id = ? AND path LIKE ?
                ORDER BY path
            """, (channel_id, f"{prefix}%"))

            results = []
            for row in cursor.fetchall():
                data = row["data"]
                if not row["encrypted"]:
                    try:
                        data = json.loads(data)
                    except json.JSONDecodeError:
                        pass

                results.append({
                    "path": row["path"],
                    "data": data,
                    "encrypted": bool(row["encrypted"]),
                    "updated_by": row["updated_by"],
                    "updated_at": row["updated_at"]
                })

            return results
