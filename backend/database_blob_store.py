"""
Database-backed blob storage implementation

Stores encrypted blobs in SQLite database using the existing
Database class infrastructure.
"""

import time
from typing import Optional, TYPE_CHECKING

from blob_store import BlobStore

if TYPE_CHECKING:
    from database import Database


class DatabaseBlobStore(BlobStore):
    """Store blobs in SQLite database using shared Database connection"""

    def __init__(self, db: 'Database'):
        """
        Initialize database blob storage

        Args:
            db: Database instance to use for blob operations
        """
        self.db = db
        self._init_schema()

    def _init_schema(self):
        """Initialize blob storage schema"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            # Blobs table - content-addressed binary storage
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blobs (
                    blob_id TEXT NOT NULL PRIMARY KEY,
                    data BLOB NOT NULL,
                    size INTEGER NOT NULL,
                    uploaded_at INTEGER NOT NULL
                )
            """)

            conn.commit()

    def add_blob(self, blob_id: str, data: bytes) -> None:
        """Store a blob in the database"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO blobs
                (blob_id, data, size, uploaded_at)
                VALUES (?, ?, ?, ?)
            """, (blob_id, data, len(data), int(time.time() * 1000)))

    def get_blob(self, blob_id: str) -> Optional[bytes]:
        """Retrieve a blob from the database"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT data FROM blobs WHERE blob_id = ?
            """, (blob_id,))

            row = cursor.fetchone()
            return row["data"] if row else None

    def delete_blob(self, blob_id: str) -> bool:
        """Delete a blob from the database"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM blobs WHERE blob_id = ?
            """, (blob_id,))
            return cursor.rowcount > 0
