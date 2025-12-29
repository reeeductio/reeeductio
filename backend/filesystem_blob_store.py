"""
Filesystem-backed blob storage implementation

Stores encrypted blobs as individual files in a directory structure.
Each blob is stored with its blob_id as the filename.
"""

import os
from pathlib import Path
from typing import Optional

from blob_store import BlobStore
from identifiers import decode_identifier, IdType


class FilesystemBlobStore(BlobStore):
    """Store blobs as files in the filesystem"""

    def __init__(self, blob_dir: str = "blobs"):
        """
        Initialize filesystem blob storage

        Args:
            blob_dir: Directory path where blobs will be stored (default: "blobs")
        """
        self.blob_dir = Path(blob_dir)
        self._init_storage()

    def _init_storage(self):
        """Create blob storage directory if it doesn't exist"""
        self.blob_dir.mkdir(parents=True, exist_ok=True)

    def _get_blob_path(self, blob_id: str) -> Path:
        """
        Get the filesystem path for a blob

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            Path object for the blob file
        """
        return self.blob_dir / blob_id

    def _validate_blob_id(self, blob_id: str) -> None:
        """
        Validate that blob_id is a valid typed identifier of BLOB type

        Args:
            blob_id: Content-addressed identifier to validate

        Raises:
            ValueError: If blob_id is invalid or not a BLOB type
        """
        try:
            tid = decode_identifier(blob_id)
        except (ValueError, KeyError) as e:
            raise ValueError(f"Invalid blob_id format: {e}")

        if tid.id_type != IdType.BLOB:
            raise ValueError(
                f"blob_id must be BLOB type, got {tid.id_type.name}"
            )

    def add_blob(self, blob_id: str, data: bytes) -> None:
        """
        Store a blob as a file

        Args:
            blob_id: Content-addressed identifier for the blob
            data: Raw binary blob data (typically encrypted)

        Raises:
            ValueError: If blob_id is invalid or not a BLOB type
            FileExistsError: If blob already exists
        """
        # Validate blob_id format and type
        self._validate_blob_id(blob_id)

        blob_path = self._get_blob_path(blob_id)

        # Check if blob already exists
        if blob_path.exists():
            raise FileExistsError(
                f"Blob {blob_id} already exists"
            )

        # Write atomically using a temporary file
        temp_path = blob_path.with_suffix('.tmp')
        try:
            temp_path.write_bytes(data)
            temp_path.replace(blob_path)
        except Exception:
            # Clean up temp file if write failed
            if temp_path.exists():
                temp_path.unlink()
            raise

    def get_blob(self, blob_id: str) -> Optional[bytes]:
        """
        Retrieve a blob from the filesystem

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            Blob data if found, None otherwise
        """
        blob_path = self._get_blob_path(blob_id)

        if not blob_path.exists():
            return None

        try:
            return blob_path.read_bytes()
        except Exception:
            # File may have been deleted between exists() check and read
            return None

    def delete_blob(self, blob_id: str) -> bool:
        """
        Delete a blob from the filesystem

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            True if blob was deleted, False if it didn't exist
        """
        blob_path = self._get_blob_path(blob_id)

        if not blob_path.exists():
            return False

        try:
            blob_path.unlink()
            return True
        except FileNotFoundError:
            # File was deleted between exists() check and unlink
            return False
