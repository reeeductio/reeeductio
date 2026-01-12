"""
SQL-based implementation of DataStore

Provides a common base class for SQL database implementations (SQLite, PostgreSQL, MySQL)
with database-agnostic SQL queries. Concrete classes only need to implement connection
management and placeholder formatting.
"""

from abc import abstractmethod
from typing import Optional, List, Dict, Any, Union, ContextManager
from contextlib import contextmanager
from data_store import DataStore


class SqlDataStore(DataStore):
    """
    Abstract SQL-based data store

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
        """Initialize the SQL data store"""
        super().__init__()

    def _init_db(self):
        """Initialize database schema"""
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Key-value data table - stores space data (members, capabilities, metadata)
            # Data is always stored as base64 string; interpretation is context-dependent
            # Every entry must be cryptographically signed
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS kv_data (
                    space_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    data TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    signed_by TEXT NOT NULL,
                    signed_at INTEGER NOT NULL,
                    PRIMARY KEY (space_id, path)
                )
            """)

            # Create index for faster data queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_kv_data_space
                ON kv_data(space_id)
            """)

            conn.commit()

    def get_data(
        self,
        space_id: str,
        path: str
    ) -> Optional[Dict[str, Any]]:
        """Get state value by path (data is always returned as base64 string)"""
        # Check cache if present
        if self._cache is not None:
            cache_key = f"kv_data:{space_id}:{path}"
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT path, data, signature, signed_by, signed_at
                FROM kv_data
                WHERE space_id = {ph(0)} AND path = {ph(1)}
            """, (space_id, path))

            row = cursor.fetchone()
            if not row:
                return None

            result = {
                "path": row["path"],
                "data": row["data"],
                "signature": row["signature"],
                "signed_by": row["signed_by"],
                "signed_at": row["signed_at"]
            }

            # Store in cache if present
            if self._cache is not None:
                cache_key = f"kv_data:{space_id}:{path}"
                self._cache.set(cache_key, result)

            return result

    def set_data(
        self,
        space_id: str,
        path: str,
        data: str,
        signature: str,
        signed_by: str,
        signed_at: int
    ) -> None:
        """Set state value (data should be base64-encoded string, signature required)"""
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Try to update first
            cursor.execute(f"""
                UPDATE kv_data
                SET data = {ph(0)}, signature = {ph(1)}, signed_by = {ph(2)}, signed_at = {ph(3)}
                WHERE space_id = {ph(4)} AND path = {ph(5)}
            """, (data, signature, signed_by, signed_at, space_id, path))

            # If no rows were updated, insert a new row
            if cursor.rowcount == 0:
                placeholders = ", ".join([ph(i) for i in range(6)])
                cursor.execute(f"""
                    INSERT INTO kv_data
                    (space_id, path, data, signature, signed_by, signed_at)
                    VALUES ({placeholders})
                """, (space_id, path, data, signature, signed_by, signed_at))

        # Invalidate cache if present
        if self._cache is not None:
            cache_key = f"kv_data:{space_id}:{path}"
            self._cache.pop(cache_key, None)

    def delete_data(self, space_id: str, path: str) -> bool:
        """Delete state value"""
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                DELETE FROM kv_data
                WHERE space_id = {ph(0)} AND path = {ph(1)}
            """, (space_id, path))
            deleted = cursor.rowcount > 0

        # Invalidate cache if present
        if self._cache is not None:
            cache_key = f"kv_data:{space_id}:{path}"
            self._cache.pop(cache_key, None)

        return deleted

    def list_data(
        self,
        space_id: str,
        prefix: str
    ) -> List[Dict[str, Any]]:
        """List all state entries matching a prefix (data is always base64 string)"""
        ph = self._get_placeholder

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT path, data, signature, signed_by, signed_at
                FROM kv_data
                WHERE space_id = {ph(0)} AND path LIKE {ph(1)}
                ORDER BY path
            """, (space_id, f"{prefix}%"))

            results = []
            for row in cursor.fetchall():
                results.append({
                    "path": row["path"],
                    "data": row["data"],
                    "signature": row["signature"],
                    "signed_by": row["signed_by"],
                    "signed_at": row["signed_at"]
                })

            return results
