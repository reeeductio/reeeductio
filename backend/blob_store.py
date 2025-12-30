"""
Blob storage abstraction layer for E2EE messaging system

Provides a base BlobStore interface and concrete implementations for
storing encrypted blobs in different backends (database, filesystem, S3, etc.)
"""

from abc import ABC, abstractmethod
from typing import Optional, List


class BlobReference:
    """A single reference to a blob from a channel/user"""
    def __init__(self, channel_id: str, uploaded_by: str, uploaded_at: int):
        self.channel_id = channel_id
        self.uploaded_by = uploaded_by
        self.uploaded_at = uploaded_at


class BlobMetadata:
    """Metadata about a blob with reference counting for deduplication"""
    def __init__(self, references: List[BlobReference]):
        self.references = references

    def add_reference(self, channel_id: str, uploaded_by: str, uploaded_at: int):
        """Add a new reference to this blob"""
        self.references.append(BlobReference(channel_id, uploaded_by, uploaded_at))

    def remove_reference(self, channel_id: str, uploaded_by: str) -> bool:
        """
        Remove a reference from this blob.

        Returns:
            True if blob should be deleted (no references remain), False otherwise
        """
        self.references = [r for r in self.references
                          if not (r.channel_id == channel_id and r.uploaded_by == uploaded_by)]
        return len(self.references) == 0

    def has_reference(self, channel_id: str) -> bool:
        """Check if channel has any reference to this blob"""
        return any(r.channel_id == channel_id for r in self.references)

    def get_reference(self, channel_id: str, uploaded_by: str) -> Optional[BlobReference]:
        """Get a specific reference if it exists"""
        for ref in self.references:
            if ref.channel_id == channel_id and ref.uploaded_by == uploaded_by:
                return ref
        return None


class BlobStore(ABC):
    """Abstract base class for blob storage backends with reference counting"""

    @abstractmethod
    def add_blob(self, blob_id: str, data: bytes, channel_id: str, uploaded_by: str) -> None:
        """
        Store a blob with reference counting.

        If the blob content already exists, only adds a new reference.
        If the blob content doesn't exist, stores the content and creates the first reference.

        Args:
            blob_id: Content-addressed identifier for the blob
            data: Raw binary blob data (typically encrypted)
            channel_id: ID of the channel this blob belongs to
            uploaded_by: Public key of the user who uploaded this blob
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
    def get_blob_metadata(self, blob_id: str) -> Optional[BlobMetadata]:
        """
        Retrieve blob metadata for authorization checks

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            BlobMetadata with all references if found, None otherwise
        """
        pass

    @abstractmethod
    def remove_blob_reference(self, blob_id: str, channel_id: str, uploaded_by: str) -> bool:
        """
        Remove a reference to a blob. Deletes the blob content if no references remain.

        Args:
            blob_id: Content-addressed identifier for the blob
            channel_id: ID of the channel removing the reference
            uploaded_by: Public key of the user who uploaded this reference

        Returns:
            True if blob content was deleted (no references remain), False otherwise
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
