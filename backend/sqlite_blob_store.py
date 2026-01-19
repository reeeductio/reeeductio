"""
Database-backed blob storage implementation

Stores encrypted blobs in SQLite database.
"""

import sqlite3
import time
from typing import Optional
from contextlib import contextmanager

from blob_store import BlobStore, BlobMetadata, BlobReference


class SqliteBlobStore(BlobStore):
    """Store blobs in SQLite database"""

    def __init__(self, db_path: str):
        """
        Initialize database blob storage

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._init_schema()

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

    def _init_schema(self):
        """Initialize blob storage schema with reference counting"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Blobs table - content-addressed binary storage (content only)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blobs (
                    blob_id TEXT NOT NULL PRIMARY KEY,
                    data BLOB NOT NULL,
                    size INTEGER NOT NULL
                )
            """)

            # Blob references table - tracks which spaces reference which blobs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blob_references (
                    blob_id TEXT NOT NULL,
                    space_id TEXT NOT NULL,
                    uploaded_by TEXT NOT NULL,
                    uploaded_at INTEGER NOT NULL,
                    PRIMARY KEY (blob_id, space_id, uploaded_by),
                    FOREIGN KEY (blob_id) REFERENCES blobs(blob_id) ON DELETE CASCADE
                )
            """)

            # Create indices for faster lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_blob_references_space_id
                ON blob_references(space_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_blob_references_blob_id
                ON blob_references(blob_id)
            """)

            conn.commit()

    def add_blob(self, blob_id: str, data: bytes, space_id: str, uploaded_by: str) -> None:
        """
        Store a blob with reference counting.
        Only writes content if blob doesn't exist, but always adds reference.

        Raises:
            ValueError: If blob_id is invalid or not a BLOB type
            FileExistsError: If this exact reference already exists
        """
        # Validate blob_id format and type
        self._validate_blob_id(blob_id)

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Check if blob content already exists
                cursor.execute("SELECT blob_id FROM blobs WHERE blob_id = ?", (blob_id,))
                blob_exists = cursor.fetchone() is not None

                # Only write content if it doesn't exist
                if not blob_exists:
                    cursor.execute("""
                        INSERT INTO blobs (blob_id, data, size)
                        VALUES (?, ?, ?)
                    """, (blob_id, data, len(data)))

                # Always add the reference (will fail if duplicate)
                cursor.execute("""
                    INSERT INTO blob_references
                    (blob_id, space_id, uploaded_by, uploaded_at)
                    VALUES (?, ?, ?, ?)
                """, (blob_id, space_id, uploaded_by, int(time.time() * 1000)))
        except sqlite3.IntegrityError as e:
            # Convert SQLite UNIQUE constraint error to FileExistsError
            if "UNIQUE constraint failed" in str(e):
                raise FileExistsError(
                    f"Blob {blob_id} already has reference from {space_id}/{uploaded_by}"
                )
            raise

    def get_blob(self, blob_id: str) -> Optional[bytes]:
        """Retrieve a blob from the database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT data FROM blobs WHERE blob_id = ?
            """, (blob_id,))

            row = cursor.fetchone()
            return row["data"] if row else None

    def get_blob_metadata(self, blob_id: str) -> Optional[BlobMetadata]:
        """Retrieve blob metadata with all references for authorization checks"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT space_id, uploaded_by, uploaded_at
                FROM blob_references WHERE blob_id = ?
            """, (blob_id,))

            rows = cursor.fetchall()
            if not rows:
                return None

            # Build list of references
            references = [
                BlobReference(
                    space_id=row["space_id"],
                    uploaded_by=row["uploaded_by"],
                    uploaded_at=row["uploaded_at"]
                )
                for row in rows
            ]

            return BlobMetadata(references=references)

    def remove_blob_reference(self, blob_id: str, space_id: str, uploaded_by: str) -> bool:
        """
        Remove a reference to a blob. Deletes blob content if no references remain.

        Returns:
            True if blob content was deleted (no references remain), False otherwise
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Remove the reference
            cursor.execute("""
                DELETE FROM blob_references
                WHERE blob_id = ? AND space_id = ? AND uploaded_by = ?
            """, (blob_id, space_id, uploaded_by))

            if cursor.rowcount == 0:
                # Reference didn't exist
                return False

            # Check if any references remain
            cursor.execute("""
                SELECT COUNT(*) as count FROM blob_references WHERE blob_id = ?
            """, (blob_id,))

            row = cursor.fetchone()
            reference_count = row["count"] if row else 0

            # If no references remain, delete the blob content
            if reference_count == 0:
                cursor.execute("DELETE FROM blobs WHERE blob_id = ?", (blob_id,))
                return True

            return False

    def delete_blob(self, blob_id: str) -> bool:
        """
        Unconditionally delete a blob and all its references (admin operation).

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            True if blob was deleted, False if blob did not exist
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Delete all references first (foreign key constraint)
            cursor.execute(
                "DELETE FROM blob_references WHERE blob_id = ?",
                (blob_id,)
            )

            # Delete the blob content
            cursor.execute(
                "DELETE FROM blobs WHERE blob_id = ?",
                (blob_id,)
            )

            return cursor.rowcount > 0
