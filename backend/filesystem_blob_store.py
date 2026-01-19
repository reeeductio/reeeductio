"""
Filesystem-backed blob storage implementation

Stores encrypted blobs as individual files in a directory structure.
Each blob is stored with its blob_id as the filename.
"""

import os
import json
import time
from pathlib import Path
from typing import Optional

from blob_store import BlobStore, BlobMetadata, BlobReference


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

    def _get_metadata_path(self, blob_id: str) -> Path:
        """
        Get the filesystem path for a blob's metadata (all references)

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            Path object for the metadata file
        """
        return self.blob_dir / f"{blob_id}.meta"

    def add_blob(self, blob_id: str, data: bytes, space_id: str, uploaded_by: str) -> None:
        """
        Store a blob with reference counting.
        Only writes content if blob doesn't exist, but always adds reference.

        Args:
            blob_id: Content-addressed identifier for the blob
            data: Raw binary blob data (typically encrypted)
            space_id: ID of the space this blob belongs to
            uploaded_by: Public key of the user who uploaded this blob

        Raises:
            ValueError: If blob_id is invalid or not a BLOB type
            FileExistsError: If this exact reference already exists
        """
        # Validate blob_id format and type
        self._validate_blob_id(blob_id)

        blob_path = self._get_blob_path(blob_id)
        metadata_path = self._get_metadata_path(blob_id)

        # Read existing metadata or initialize empty
        if metadata_path.exists():
            try:
                metadata_json = metadata_path.read_text()
                metadata = json.loads(metadata_json)
            except Exception:
                metadata = {"references": {}}
        else:
            metadata = {"references": {}}

        # Check if this exact reference already exists
        ref_key = self._get_reference_key(space_id, uploaded_by)
        if ref_key in metadata["references"]:
            raise FileExistsError(
                f"Blob {blob_id} already has reference from {space_id}/{uploaded_by}"
            )

        # Add the new reference
        metadata["references"][ref_key] = {
            "space_id": space_id,
            "uploaded_by": uploaded_by,
            "uploaded_at": int(time.time() * 1000)
        }

        # Write atomically using temporary files
        temp_meta_path = Path(str(metadata_path) + '.tmp')

        try:
            # Write blob content only if it doesn't exist
            if not blob_path.exists():
                temp_blob_path = Path(str(blob_path) + '.tmp')
                temp_blob_path.write_bytes(data)
                temp_blob_path.replace(blob_path)

            # Always write updated metadata
            temp_meta_path.write_text(json.dumps(metadata))
            temp_meta_path.replace(metadata_path)
        except Exception:
            # Clean up temp files if write failed
            if temp_meta_path.exists():
                temp_meta_path.unlink()
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

    def get_blob_metadata(self, blob_id: str) -> Optional[BlobMetadata]:
        """
        Retrieve blob metadata with all references for authorization checks

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            BlobMetadata with all references if found, None otherwise
        """
        metadata_path = self._get_metadata_path(blob_id)

        if not metadata_path.exists():
            return None

        try:
            metadata_json = metadata_path.read_text()
            metadata = json.loads(metadata_json)

            # Convert references dict to list of BlobReference objects
            references = [
                BlobReference(
                    space_id=ref_data["space_id"],
                    uploaded_by=ref_data["uploaded_by"],
                    uploaded_at=ref_data["uploaded_at"]
                )
                for ref_data in metadata.get("references", {}).values()
            ]

            if not references:
                return None

            return BlobMetadata(references=references)
        except Exception:
            # Metadata file may be corrupt or deleted
            return None

    def remove_blob_reference(self, blob_id: str, space_id: str, uploaded_by: str) -> bool:
        """
        Remove a reference to a blob. Deletes blob content if no references remain.

        Args:
            blob_id: Content-addressed identifier for the blob
            space_id: ID of the space removing the reference
            uploaded_by: Public key of the user who uploaded this reference

        Returns:
            True if blob content was deleted (no references remain), False otherwise
        """
        blob_path = self._get_blob_path(blob_id)
        metadata_path = self._get_metadata_path(blob_id)

        if not metadata_path.exists():
            return False

        try:
            # Read metadata
            metadata_json = metadata_path.read_text()
            metadata = json.loads(metadata_json)

            # Remove the reference
            ref_key = self._get_reference_key(space_id, uploaded_by)
            if ref_key not in metadata.get("references", {}):
                return False

            del metadata["references"][ref_key]

            # Check if any references remain
            if len(metadata["references"]) == 0:
                # No references remain - delete blob and metadata
                if blob_path.exists():
                    blob_path.unlink()
                metadata_path.unlink()
                return True
            else:
                # References remain - update metadata
                temp_meta_path = Path(str(metadata_path) + '.tmp')
                temp_meta_path.write_text(json.dumps(metadata))
                temp_meta_path.replace(metadata_path)
                return False

        except Exception:
            # Error reading or updating metadata
            return False

    def delete_blob(self, blob_id: str) -> bool:
        """
        Unconditionally delete a blob and all its references (admin operation).

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            True if blob was deleted, False if blob did not exist
        """
        blob_path = self._get_blob_path(blob_id)
        metadata_path = self._get_metadata_path(blob_id)

        deleted = False

        # Delete blob content if it exists
        if blob_path.exists():
            blob_path.unlink()
            deleted = True

        # Delete metadata if it exists
        if metadata_path.exists():
            metadata_path.unlink()
            deleted = True

        return deleted
