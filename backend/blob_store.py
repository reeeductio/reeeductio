"""
Blob storage abstraction layer for E2EE messaging system

Provides a base BlobStore interface and concrete implementations for
storing encrypted blobs in different backends (database, filesystem, S3, etc.)
"""

from abc import ABC, abstractmethod
from typing import Optional, List
from identifiers import decode_identifier, IdType


class BlobReference:
    """A single reference to a blob from a space/user"""
    def __init__(self, space_id: str, uploaded_by: str, uploaded_at: int):
        self.space_id = space_id
        self.uploaded_by = uploaded_by
        self.uploaded_at = uploaded_at


class BlobMetadata:
    """Metadata about a blob with reference counting for deduplication"""
    def __init__(self, references: List[BlobReference]):
        self.references = references

    def add_reference(self, space_id: str, uploaded_by: str, uploaded_at: int):
        """Add a new reference to this blob"""
        self.references.append(BlobReference(space_id, uploaded_by, uploaded_at))

    def remove_reference(self, space_id: str, uploaded_by: str) -> bool:
        """
        Remove a reference from this blob.

        Returns:
            True if blob should be deleted (no references remain), False otherwise
        """
        self.references = [r for r in self.references
                          if not (r.space_id == space_id and r.uploaded_by == uploaded_by)]
        return len(self.references) == 0

    def has_reference(self, space_id: str) -> bool:
        """Check if space has any reference to this blob"""
        return any(r.space_id == space_id for r in self.references)

    def get_reference(self, space_id: str, uploaded_by: str) -> Optional[BlobReference]:
        """Get a specific reference if it exists"""
        for ref in self.references:
            if ref.space_id == space_id and ref.uploaded_by == uploaded_by:
                return ref
        return None


class BlobStore(ABC):
    """Abstract base class for blob storage backends with reference counting"""

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

    def _get_reference_key(self, space_id: str, uploaded_by: str) -> str:
        """Generate a unique key for a reference"""
        return f"{space_id}:{uploaded_by}"

    @abstractmethod
    def add_blob(self, blob_id: str, data: bytes, space_id: str, uploaded_by: str) -> None:
        """
        Store a blob with reference counting.

        If the blob content already exists, only adds a new reference.
        If the blob content doesn't exist, stores the content and creates the first reference.

        Args:
            blob_id: Content-addressed identifier for the blob
            data: Raw binary blob data (typically encrypted)
            space_id: ID of the space this blob belongs to
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
    def remove_blob_reference(self, blob_id: str, space_id: str, uploaded_by: str) -> bool:
        """
        Remove a reference to a blob. Deletes the blob content if no references remain.

        Args:
            blob_id: Content-addressed identifier for the blob
            space_id: ID of the space removing the reference
            uploaded_by: Public key of the user who uploaded this reference

        Returns:
            True if blob content was deleted (no references remain), False otherwise
        """
        pass

    def add_blob_reference(self, blob_id: str, space_id: str, uploaded_by: str) -> None:
        """
        Add a reference to a blob without providing content data.

        Used for presigned URL uploads where the client uploads directly to S3.
        Creates metadata with the reference, but doesn't store blob content
        (content will be uploaded directly by the client).

        Args:
            blob_id: Content-addressed identifier for the blob
            space_id: ID of the space this blob belongs to
            uploaded_by: Public key of the user who uploaded this blob

        Raises:
            ValueError: If blob_id is invalid or not a BLOB type
            FileExistsError: If this exact reference already exists
        """
        raise NotImplementedError(
            "add_blob_reference not implemented for this blob store"
        )

    def get_upload_url(self, blob_id: str, max_size: Optional[int] = None) -> Optional[str]:
        """
        Get a pre-signed URL for uploading a blob (optional, for S3-compatible backends)

        Args:
            blob_id: Content-addressed identifier for the blob
            max_size: Maximum allowed size in bytes (enforced in presigned URL if supported)

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

    @abstractmethod
    def delete_blob(self, blob_id: str) -> bool:
        """
        Unconditionally delete a blob and all its references (admin operation).

        This bypasses reference counting and deletes the blob entirely.
        Use with caution - intended for admin cleanup operations.

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            True if blob was deleted, False if blob did not exist
        """
        pass
