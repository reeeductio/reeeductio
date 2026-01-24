"""
End-to-end tests for basic API functionality.

Run with: pytest backend/tests/e2e/ --e2e
Requires: docker-compose -f docker-compose.e2e.yml up -d
"""
import pytest
import base64
import json
import time
import sys
import os
import httpx

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from crypto import CryptoUtils
from identifiers import decode_identifier


pytestmark = pytest.mark.e2e


class TestHealthCheck:
    """Test health check endpoint"""

    def test_health_returns_healthy(self, e2e_client):
        """Health endpoint should return healthy status"""
        response = e2e_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


class TestAuthentication:
    """Test authentication flow"""

    def test_challenge_and_verify_flow(self, e2e_client, e2e_keypair):
        """Full authentication flow should work"""
        space_id = e2e_keypair['space_id']
        user_id = e2e_keypair['user_id']
        private_key = e2e_keypair['private']

        # Request challenge
        response = e2e_client.post(
            f"/spaces/{space_id}/auth/challenge",
            json={"public_key": user_id}
        )
        assert response.status_code == 200
        challenge_data = response.json()
        assert "challenge" in challenge_data
        assert "expires_at" in challenge_data

        # Sign challenge
        challenge = challenge_data['challenge']
        signature_bytes = private_key.sign(challenge.encode('utf-8'))
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        # Verify and get token
        response = e2e_client.post(
            f"/spaces/{space_id}/auth/verify",
            json={
                "public_key": user_id,
                "challenge": challenge,
                "signature": signature
            }
        )
        assert response.status_code == 200
        token_data = response.json()
        assert "token" in token_data
        assert "expires_at" in token_data

    def test_invalid_signature_rejected(self, e2e_client, e2e_keypair):
        """Invalid signature should be rejected"""
        space_id = e2e_keypair['space_id']
        user_id = e2e_keypair['user_id']

        # Request challenge
        response = e2e_client.post(
            f"/spaces/{space_id}/auth/challenge",
            json={"public_key": user_id}
        )
        assert response.status_code == 200
        challenge = response.json()['challenge']

        # Use invalid signature
        invalid_signature = base64.b64encode(b"invalid" * 8).decode('utf-8')

        response = e2e_client.post(
            f"/spaces/{space_id}/auth/verify",
            json={
                "public_key": user_id,
                "challenge": challenge,
                "signature": invalid_signature
            }
        )
        assert response.status_code == 401


class TestDataStore:
    """Test data (simple key-value) endpoints"""

    def test_put_and_get_data(self, e2e_client, e2e_auth_token, e2e_auth_headers):
        """Should be able to store and retrieve data"""
        space_id = e2e_auth_token['space_id']
        user_id = e2e_auth_token['user_id']
        keypair = e2e_auth_token['keypair']

        path = "test/data/item1"
        content = {"message": "Hello, e2e test!"}
        data_b64 = base64.b64encode(json.dumps(content).encode()).decode()
        signed_at = int(time.time() * 1000)

        # Create signature
        message = f"{space_id}|{path}|{data_b64}|{signed_at}".encode('utf-8')
        signature_bytes = keypair['private'].sign(message)
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        # Store data
        response = e2e_client.put(
            f"/spaces/{space_id}/data/{path}",
            headers=e2e_auth_headers,
            json={
                "data": data_b64,
                "signature": signature,
                "signed_by": user_id,
                "signed_at": signed_at
            }
        )
        assert response.status_code == 200, f"PUT failed: {response.text}"

        # Retrieve data
        response = e2e_client.get(
            f"/spaces/{space_id}/data/{path}",
            headers=e2e_auth_headers
        )
        assert response.status_code == 200, f"GET failed: {response.text}"

        data = response.json()
        assert data["data"] == data_b64
        assert data["signed_by"] == user_id

        # Verify content
        retrieved_content = json.loads(base64.b64decode(data["data"]))
        assert retrieved_content == content


class TestMessages:
    """Test message endpoints"""

    def test_post_and_get_message(self, e2e_client, e2e_auth_token, e2e_auth_headers):
        """Should be able to post and retrieve messages"""
        space_id = e2e_auth_token['space_id']
        user_id = e2e_auth_token['user_id']
        keypair = e2e_auth_token['keypair']

        topic_id = "test-topic"
        content = {"text": "Hello from e2e test!"}
        data_b64 = base64.b64encode(json.dumps(content).encode()).decode()

        crypto = CryptoUtils()

        # Compute message hash (first message, no prev_hash)
        message_hash = crypto.compute_message_hash(
            space_id,
            topic_id,
            None,  # prev_hash
            data_b64,
            user_id
        )

        # Sign the message hash
        message_tid = decode_identifier(message_hash)
        message_bytes = message_tid.to_bytes()
        signature_bytes = keypair['private'].sign(message_bytes)
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        # Post message
        response = e2e_client.post(
            f"/spaces/{space_id}/topics/{topic_id}/messages",
            headers=e2e_auth_headers,
            json={
                "type": "chat.text",
                "prev_hash": None,
                "data": data_b64,
                "message_hash": message_hash,
                "signature": signature
            }
        )
        assert response.status_code == 201, f"POST failed: {response.text}"
        post_data = response.json()
        assert post_data["message_hash"] == message_hash

        # Get messages
        response = e2e_client.get(
            f"/spaces/{space_id}/topics/{topic_id}/messages",
            headers=e2e_auth_headers
        )
        assert response.status_code == 200, f"GET failed: {response.text}"

        data = response.json()
        assert "messages" in data
        assert len(data["messages"]) >= 1

        # Find our message
        our_message = next(
            (m for m in data["messages"] if m["message_hash"] == message_hash),
            None
        )
        assert our_message is not None
        assert our_message["data"] == data_b64
        assert our_message["sender"] == user_id


class TestState:
    """Test state (event-sourced) endpoints"""

    def test_put_and_get_state(self, e2e_client, e2e_auth_token, e2e_auth_headers):
        """Should be able to set and retrieve state"""
        space_id = e2e_auth_token['space_id']
        user_id = e2e_auth_token['user_id']
        keypair = e2e_auth_token['keypair']

        path = "settings/theme"
        content = {"theme": "dark", "language": "en"}
        data_b64 = base64.b64encode(json.dumps(content).encode()).decode()

        crypto = CryptoUtils()

        # Compute message hash for state (topic_id = "state")
        message_hash = crypto.compute_message_hash(
            space_id,
            "state",
            None,  # prev_hash
            data_b64,
            user_id
        )

        # Sign the message hash
        message_tid = decode_identifier(message_hash)
        message_bytes = message_tid.to_bytes()
        signature_bytes = keypair['private'].sign(message_bytes)
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        # Set state
        response = e2e_client.put(
            f"/spaces/{space_id}/state/{path}",
            headers=e2e_auth_headers,
            json={
                "type": path,
                "prev_hash": None,
                "data": data_b64,
                "message_hash": message_hash,
                "signature": signature
            }
        )
        assert response.status_code == 200, f"PUT state failed: {response.text}"

        # Get state
        response = e2e_client.get(
            f"/spaces/{space_id}/state/{path}",
            headers=e2e_auth_headers
        )
        assert response.status_code == 200, f"GET state failed: {response.text}"

        data = response.json()
        assert data["data"] == data_b64

        # Verify content
        retrieved_content = json.loads(base64.b64decode(data["data"]))
        assert retrieved_content == content


class TestBlobs:
    """Test blob upload/download endpoints"""

    @staticmethod
    def _fix_minio_url(url: str) -> str:
        """
        Fix MinIO presigned URLs for local testing.

        In Docker, the backend uses 'minio:9000' as the endpoint, but from
        the host machine we need to use 'localhost:9000'.
        """
        return url.replace("http://minio:9000", "http://localhost:9000")

    def test_upload_and_download_blob(self, e2e_backend_url, e2e_auth_token):
        """Should be able to upload and download blobs"""
        space_id = e2e_auth_token['space_id']
        token = e2e_auth_token['token']

        # Create test blob content
        blob_content = b"This is test blob content for e2e testing!"

        # Blob ID must be a proper typed identifier (hash of content)
        blob_id = CryptoUtils.compute_blob_id(blob_content)

        # Use a fresh client that doesn't follow redirects automatically
        with httpx.Client(base_url=e2e_backend_url, timeout=30.0, follow_redirects=False) as client:
            # Upload blob
            response = client.put(
                f"/spaces/{space_id}/blobs/{blob_id}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/octet-stream"
                },
                content=blob_content
            )

            # Check response - might be 201 (direct) or 307 (redirect to MinIO)
            if response.status_code == 307:
                # Follow redirect to MinIO (pre-signed URL, no auth needed)
                upload_url = response.headers.get("location")
                assert upload_url is not None, "No redirect location for upload"

                # Fix MinIO URL for local testing
                upload_url = self._fix_minio_url(upload_url)

                # The presigned URL requires a SHA256 checksum header that matches the blob_id
                # Extract the checksum from the URL or compute it from the content
                import hashlib
                checksum_sha256 = base64.b64encode(hashlib.sha256(blob_content).digest()).decode('ascii')

                # Upload directly to MinIO using pre-signed URL
                upload_response = httpx.put(
                    upload_url,
                    content=blob_content,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "x-amz-checksum-sha256": checksum_sha256
                    }
                )
                assert upload_response.status_code in (200, 201), f"MinIO upload failed: {upload_response.text}"
            else:
                assert response.status_code == 201, f"Upload failed: {response.text}"

            # Download blob
            response = client.get(
                f"/spaces/{space_id}/blobs/{blob_id}",
                headers={"Authorization": f"Bearer {token}"}
            )

            # Check response - might be 200 (direct) or 307 (redirect to MinIO)
            if response.status_code == 307:
                # Follow redirect to MinIO (pre-signed URL)
                download_url = response.headers.get("location")
                assert download_url is not None, "No redirect location for download"

                # Fix MinIO URL for local testing
                download_url = self._fix_minio_url(download_url)

                download_response = httpx.get(download_url)
                assert download_response.status_code == 200, f"MinIO download failed: {download_response.text}"
                assert download_response.content == blob_content
            else:
                assert response.status_code == 200, f"Download failed: {response.text}"
                assert response.content == blob_content
