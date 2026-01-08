"""
SQLite implementation of DataStore

Stores space state in a SQLite database. All state data is stored
as base64-encoded strings; interpretation is context-dependent.
"""

import sqlite3
from contextlib import contextmanager
from sql_data_store import SqlDataStore
from lru_cache import LRUCache


class SqliteDataStore(SqlDataStore):
    """Store space state in SQLite database"""

    def __init__(self, db_path: str, cache_size: int = 1000):
        """
        Initialize SQLite state storage

        Args:
            db_path: Path to SQLite database file
            cache_size: Maximum number of items to cache (default: 1000)
        """
        super().__init__()
        self.db_path = db_path

        # Initialize LRU cache for local SQLite storage
        # Safe because SQLite is local to this process
        self._cache = LRUCache(max_size=cache_size)

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

    def _get_placeholder(self, position: int = 0) -> str:
        """SQLite uses ? for parameter placeholders"""
        return "?"
