"""
S3-compatible blob storage implementation

Stores encrypted blobs in S3-compatible object storage (AWS S3, MinIO, etc.)
and provides pre-signed URLs for direct client uploads/downloads.
"""

import base64
import json
import time
from typing import Optional
from blob_store import BlobStore, BlobMetadata, BlobReference
from identifiers import decode_identifier, IdType, extract_hash
from config import S3BlobConfig

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError as e:
    raise ImportError(
        "boto3 is required for S3BlobStore. Install it with: pip install boto3"
    ) from e


class S3BlobStore(BlobStore):
    """Store blobs in S3-compatible object storage with pre-signed URL support"""

    def __init__(
        self,
        config: S3BlobConfig
    ):
        """
        Initialize S3 blob storage

        Args:
            bucket_name: S3 bucket name for blob storage
            endpoint_url: Custom S3 endpoint (for MinIO, etc.). None for AWS S3
            access_key_id: AWS access key ID (or None to use environment/IAM)
            secret_access_key: AWS secret access key (or None to use environment/IAM)
            region_name: AWS region name (default: us-east-1)
            presigned_url_expiration: Pre-signed URL expiration in seconds (default: 3600)
        """
        self.bucket_name = config.bucket_name
        self.presigned_url_expiration = config.presigned_url_expiration
        self.ClientError = ClientError

        # Create S3 client
        session_kwargs = {}
        if config.access_key_id and config.secret_access_key:
            session_kwargs["aws_access_key_id"] = config.access_key_id
            session_kwargs["aws_secret_access_key"] = config.secret_access_key

        session = boto3.Session(**session_kwargs)

        # Create S3 client with appropriate configuration
        if config.endpoint_url:
            self.s3_client = session.client(
                "s3",
                region_name=config.region_name,
                endpoint_url=config.endpoint_url
            )
        else:
            self.s3_client = session.client("s3", region_name=config.region_name)

        # Ensure bucket exists
        self._ensure_bucket_exists()

    def _ensure_bucket_exists(self):
        """Create bucket if it doesn't exist"""
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
        except self.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "404":
                # Bucket doesn't exist, create it
                self.s3_client.create_bucket(Bucket=self.bucket_name)
            else:
                raise

    def _get_s3_key(self, blob_id: str) -> str:
        """
        Get S3 object key for a blob

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            S3 object key (path within bucket)
        """
        # Use blob_id directly as the key for flat structure
        # Could add prefixes for sharding: f"blobs/{blob_id[:2]}/{blob_id}"
        return f"blobs/{blob_id}"

    def _get_metadata_key(self, blob_id: str) -> str:
        """
        Get S3 object key for blob metadata (all references)

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            S3 object key for metadata
        """
        return f"blobs/{blob_id}.meta"

    def add_blob(self, blob_id: str, data: bytes, channel_id: str, uploaded_by: str) -> None:
        """
        Store a blob with reference counting.
        Only writes content if blob doesn't exist, but always adds reference.

        Args:
            blob_id: Content-addressed identifier for the blob
            data: Raw binary blob data (typically encrypted)
            channel_id: ID of the channel this blob belongs to
            uploaded_by: Public key of the user who uploaded this blob

        Raises:
            ValueError: If blob_id is invalid or not a BLOB type
            FileExistsError: If this exact reference already exists
        """
        # Validate blob_id format and type
        self._validate_blob_id(blob_id)

        s3_key = self._get_s3_key(blob_id)
        metadata_key = self._get_metadata_key(blob_id)

        # Check if blob content exists
        blob_exists = False
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=s3_key)
            blob_exists = True
        except self.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code != "404":
                raise

        # Read existing metadata or initialize empty
        metadata = {"references": {}}
        if blob_exists:
            try:
                response = self.s3_client.get_object(
                    Bucket=self.bucket_name,
                    Key=metadata_key
                )
                metadata_json = response["Body"].read().decode('utf-8')
                metadata = json.loads(metadata_json)
            except self.ClientError:
                metadata = {"references": {}}

        # Check if this exact reference already exists
        ref_key = self._get_reference_key(channel_id, uploaded_by)
        if ref_key in metadata.get("references", {}):
            raise FileExistsError(
                f"Blob {blob_id} already has reference from {channel_id}/{uploaded_by}"
            )

        # Add the new reference
        metadata["references"][ref_key] = {
            "channel_id": channel_id,
            "uploaded_by": uploaded_by,
            "uploaded_at": int(time.time() * 1000)
        }

        # Upload blob content only if it doesn't exist
        if not blob_exists:
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=s3_key,
                Body=data,
                ContentType="application/octet-stream"
            )

        # Always upload updated metadata
        self.s3_client.put_object(
            Bucket=self.bucket_name,
            Key=metadata_key,
            Body=json.dumps(metadata),
            ContentType="application/json"
        )

    def get_blob(self, blob_id: str) -> Optional[bytes]:
        """
        Retrieve a blob from S3

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            Blob data if found, None otherwise
        """
        s3_key = self._get_s3_key(blob_id)

        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=s3_key
            )
            return response["Body"].read()
        except self.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("NoSuchKey", "404"):
                return None
            raise

    def get_blob_metadata(self, blob_id: str) -> Optional[BlobMetadata]:
        """
        Retrieve blob metadata with all references for authorization checks

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            BlobMetadata with all references if found, None otherwise
        """
        metadata_key = self._get_metadata_key(blob_id)

        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=metadata_key
            )
            metadata_json = response["Body"].read().decode('utf-8')
            metadata = json.loads(metadata_json)

            # Convert references dict to list of BlobReference objects
            references = [
                BlobReference(
                    channel_id=ref_data["channel_id"],
                    uploaded_by=ref_data["uploaded_by"],
                    uploaded_at=ref_data["uploaded_at"]
                )
                for ref_data in metadata.get("references", {}).values()
            ]

            if not references:
                return None

            return BlobMetadata(references=references)
        except self.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("NoSuchKey", "404"):
                return None
            raise

    def remove_blob_reference(self, blob_id: str, channel_id: str, uploaded_by: str) -> bool:
        """
        Remove a reference to a blob. Deletes blob content if no references remain.

        Args:
            blob_id: Content-addressed identifier for the blob
            channel_id: ID of the channel removing the reference
            uploaded_by: Public key of the user who uploaded this reference

        Returns:
            True if blob content was deleted (no references remain), False otherwise
        """
        s3_key = self._get_s3_key(blob_id)
        metadata_key = self._get_metadata_key(blob_id)

        # Read metadata
        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=metadata_key
            )
            metadata_json = response["Body"].read().decode('utf-8')
            metadata = json.loads(metadata_json)
        except self.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("NoSuchKey", "404"):
                return False
            raise

        # Remove the reference
        ref_key = self._get_reference_key(channel_id, uploaded_by)
        if ref_key not in metadata.get("references", {}):
            return False

        del metadata["references"][ref_key]

        # Check if any references remain
        if len(metadata["references"]) == 0:
            # No references remain - delete blob and metadata
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=s3_key)
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=metadata_key)
            return True
        else:
            # References remain - update metadata
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=metadata_key,
                Body=json.dumps(metadata),
                ContentType="application/json"
            )
            return False

    def get_upload_url(self, blob_id: str, max_size: Optional[int] = None) -> Optional[str]:
        """
        Get a pre-signed URL for uploading a blob to S3 with SHA256 checksum enforcement

        The presigned URL will require the client to provide a matching SHA256 checksum
        when uploading, ensuring data integrity. The client must include the
        'x-amz-checksum-sha256' header with the base64-encoded SHA256 hash.

        Note: S3 presigned PUT URLs cannot enforce content-length restrictions directly.
        Size limits must be enforced client-side or via S3 bucket policies. The max_size
        parameter is accepted for interface compatibility but not enforced in the URL.
        Consider implementing S3 Object Lambda or bucket size policies for server-side
        enforcement.

        Args:
            blob_id: Content-addressed identifier for the blob
            max_size: Maximum allowed size in bytes (not enforced in presigned URL)

        Returns:
            Pre-signed URL for PUT upload with checksum enforcement
        """
        # Validate blob_id
        self._validate_blob_id(blob_id)

        s3_key = self._get_s3_key(blob_id)

        # Check if blob already exists
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=s3_key)
            # If we get here, object exists - raise error
            raise FileExistsError(f"Blob {blob_id} already exists")
        except self.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code != "404":
                raise

        # Extract SHA256 hash from blob_id and encode as base64 for S3
        hash_bytes = extract_hash(blob_id)
        checksum_sha256 = base64.b64encode(hash_bytes).decode('ascii')

        params = {
            "Bucket": self.bucket_name,
            "Key": s3_key,
            "ContentType": "application/octet-stream",
            "ChecksumSHA256": checksum_sha256
        }

        # Note: max_size cannot be enforced in S3 presigned PUT URLs
        # Size enforcement must be done via:
        # 1. Client-side validation before upload
        # 2. S3 bucket policies with size limits
        # 3. S3 Object Lambda for request filtering
        # 4. Server-side validation when metadata is added via add_blob()

        # Generate pre-signed URL for PUT with checksum enforcement
        presigned_url = self.s3_client.generate_presigned_url(
            ClientMethod="put_object",
            Params=params,
            ExpiresIn=self.presigned_url_expiration
        )

        return presigned_url

    def get_download_url(self, blob_id: str) -> Optional[str]:
        """
        Get a pre-signed URL for downloading a blob from S3

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            Pre-signed URL for GET download, or None if blob doesn't exist
        """
        s3_key = self._get_s3_key(blob_id)

        # Check if blob exists
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=s3_key)
        except self.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "404":
                return None
            raise

        # Generate pre-signed URL for GET
        presigned_url = self.s3_client.generate_presigned_url(
            ClientMethod="get_object",
            Params={
                "Bucket": self.bucket_name,
                "Key": s3_key
            },
            ExpiresIn=self.presigned_url_expiration
        )

        return presigned_url
