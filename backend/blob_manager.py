"""
Blob storage abstraction layer for E2EE messaging system

Provides a base BlobStore interface and concrete implementations for
storing encrypted blobs in different backends (database, filesystem, S3, etc.)
"""

from abc import ABC, abstractmethod
from typing import Optional


class BlobStore(ABC):
    """Abstract base class for blob storage backends"""

    @abstractmethod
    def add_blob(self, blob_id: str, data: bytes) -> None:
        """
        Store a blob

        Args:
            blob_id: Content-addressed identifier for the blob
            data: Raw binary blob data (typically encrypted)
        """
        pass

    @abstractmethod
    def get_blob(self, blob_id: str) -> Optional[bytes]:
        """
        Retrieve a blob by its ID

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            Blob data if found, None otherwise
        """
        pass

    @abstractmethod
    def delete_blob(self, blob_id: str) -> bool:
        """
        Delete a blob

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            True if blob was deleted, False if it didn't exist
        """
        pass

    def get_upload_url(self, blob_id: str) -> Optional[str]:
        """
        Get a pre-signed URL for uploading a blob (optional, for S3-compatible backends)

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            Pre-signed URL for upload, or None if direct upload not supported
        """
        return None

    def get_download_url(self, blob_id: str) -> Optional[str]:
        """
        Get a pre-signed URL for downloading a blob (optional, for S3-compatible backends)

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            Pre-signed URL for download, or None if direct download not supported
        """
        return None
