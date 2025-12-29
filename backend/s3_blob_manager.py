"""
S3-compatible blob storage implementation

Stores encrypted blobs in S3-compatible object storage (AWS S3, MinIO, etc.)
and provides pre-signed URLs for direct client uploads/downloads.
"""

from typing import Optional
from blob_manager import BlobStore
from identifiers import decode_identifier, IdType


class S3BlobStore(BlobStore):
    """Store blobs in S3-compatible object storage with pre-signed URL support"""

    def __init__(
        self,
        bucket_name: str,
        endpoint_url: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        region_name: str = "us-east-1",
        presigned_url_expiration: int = 3600
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
        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError:
            raise ImportError(
                "boto3 is required for S3BlobManager. Install it with: pip install boto3"
            )

        self.bucket_name = bucket_name
        self.presigned_url_expiration = presigned_url_expiration
        self.ClientError = ClientError

        # Create S3 client
        session_kwargs = {}
        if access_key_id and secret_access_key:
            session_kwargs["aws_access_key_id"] = access_key_id
            session_kwargs["aws_secret_access_key"] = secret_access_key

        session = boto3.session.Session(**session_kwargs)

        client_kwargs = {"region_name": region_name}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url

        self.s3_client = session.client("s3", **client_kwargs)

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
        Store a blob in S3

        Args:
            blob_id: Content-addressed identifier for the blob
            data: Raw binary blob data (typically encrypted)

        Raises:
            ValueError: If blob_id is invalid or not a BLOB type
            FileExistsError: If blob already exists
        """
        # Validate blob_id format and type
        self._validate_blob_id(blob_id)

        s3_key = self._get_s3_key(blob_id)

        # Check if blob already exists
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=s3_key)
            # If we get here, object exists
            raise FileExistsError(f"Blob {blob_id} already exists")
        except self.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code != "404":
                # Some other error occurred
                raise

        # Upload blob to S3
        self.s3_client.put_object(
            Bucket=self.bucket_name,
            Key=s3_key,
            Body=data,
            ContentType="application/octet-stream"
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

    def delete_blob(self, blob_id: str) -> bool:
        """
        Delete a blob from S3

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            True if blob was deleted, False if it didn't exist
        """
        s3_key = self._get_s3_key(blob_id)

        # Check if object exists first
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=s3_key)
        except self.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "404":
                return False
            raise

        # Delete the object
        self.s3_client.delete_object(Bucket=self.bucket_name, Key=s3_key)
        return True

    def get_upload_url(self, blob_id: str) -> Optional[str]:
        """
        Get a pre-signed URL for uploading a blob to S3

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            Pre-signed URL for PUT upload
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

        # Generate pre-signed URL for PUT
        presigned_url = self.s3_client.generate_presigned_url(
            ClientMethod="put_object",
            Params={
                "Bucket": self.bucket_name,
                "Key": s3_key,
                "ContentType": "application/octet-stream"
            },
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
