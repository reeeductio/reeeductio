"""
E2EE PubSub Messaging System - Main Application

A capability-based, end-to-end encrypted messaging system with:
- Channel-scoped access control
- Blockchain-style message chains per topic
- Granular, signed capabilities
- Zero-knowledge server design
"""

from fastapi import FastAPI, HTTPException, Depends, Header, Query, Path as PathParam, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import Response, RedirectResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import time
import re
import secrets
import jwt

from crypto import CryptoUtils
from config import get_config
from s3_blob_store import S3BlobStore
from sqlite_blob_store import SqliteBlobStore
from filesystem_blob_store import FilesystemBlobStore
from channel_manager import ChannelManager

# Load configuration
config = get_config()

# Initialize FastAPI app
app = FastAPI(
    title="E2EE PubSub Messaging API",
    description="End-to-end encrypted messaging with capability-based authorization",
    version="1.0.0"
)

# JWT configuration
JWT_SECRET = config.server.jwt_secret or secrets.token_urlsafe(32)
JWT_ALGORITHM = config.server.jwt_algorithm
JWT_EXPIRY_HOURS = config.server.jwt_expiry_hours

# Initialize blob store based on configuration
if config.blob_store.type == "filesystem":
    blob_store = FilesystemBlobStore(config.blob_store.path)
elif config.blob_store.type == "s3":
    blob_store = S3BlobStore(config.blob_store)
elif config.blob_store.type == "sqlite":
    blob_store = SqliteBlobStore(config.blob_store.db_path)
else:
    raise ValueError(f"Unsupported blob store type: {config.blob_store.type}")

# Initialize components
channel_manager = ChannelManager(
    base_storage_dir="channels",
    max_cached_channels=1000,
    blob_store=blob_store,
    jwt_secret=JWT_SECRET,
    jwt_algorithm=JWT_ALGORITHM,
    jwt_expiry_hours=JWT_EXPIRY_HOURS
)
crypto = CryptoUtils()
security = HTTPBearer()

CHALLENGE_EXPIRY_SECONDS = config.server.challenge_expiry_seconds

# Topic ID validation (slug format)
TOPIC_ID_PATTERN = re.compile(r'^[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]$')


def validate_topic_id(topic_id: str) -> None:
    """Validate topic_id matches slug format"""
    if not TOPIC_ID_PATTERN.match(topic_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid topic_id format. Must be 2-64 characters, lowercase alphanumeric with hyphens/underscores, starting and ending with alphanumeric."
        )


# ============================================================================
# Request/Response Models
# ============================================================================

class ChallengeRequest(BaseModel):
    public_key: str = Field(..., description="Typed user identifier (44-char base64)")


class ChallengeResponse(BaseModel):
    challenge: str = Field(..., description="Base64-encoded random nonce")
    expires_at: int = Field(..., description="Unix timestamp")


class VerifyRequest(BaseModel):
    public_key: str
    signature: str = Field(..., description="Base64-encoded signature of challenge")
    challenge: str


class TokenResponse(BaseModel):
    token: str
    expires_at: int


class StateData(BaseModel):
    data: str = Field(..., description="Base64-encoded state data")
    signature: Optional[str] = None
    signed_by: Optional[str] = None


class StateResponse(BaseModel):
    data: str
    updated_at: int
    updated_by: str


class MessagePost(BaseModel):
    prev_hash: Optional[str] = Field(None, description="SHA256 of previous message")
    encrypted_payload: str = Field(..., description="Base64-encoded encrypted content")
    message_hash: str = Field(..., description="SHA256 hash of this message")
    signature: str = Field(..., description="Base64-encoded Ed25519 signature over message_hash")


class Message(BaseModel):
    message_hash: str
    topic_id: str
    prev_hash: Optional[str]
    encrypted_payload: str
    sender: str
    signature: str
    server_timestamp: int


class MessagesResponse(BaseModel):
    messages: List[Message]
    has_more: bool


class BlobUploadResponse(BaseModel):
    blob_id: str
    size: int


class ErrorResponse(BaseModel):
    error: str
    code: str
    details: Optional[Dict[str, Any]] = None


# ============================================================================
# Authentication Endpoints
# ============================================================================

@app.post("/channels/{channel_id}/auth/challenge", response_model=ChallengeResponse)
async def auth_challenge(
    channel_id: str,
    request: ChallengeRequest
):
    """Request an authentication challenge (random nonce to sign)"""
    channel = channel_manager.get_channel(channel_id)
    result = channel.create_challenge(request.public_key, CHALLENGE_EXPIRY_SECONDS)

    return ChallengeResponse(
        challenge=result["challenge"],
        expires_at=result["expires_at"]
    )


@app.post("/channels/{channel_id}/auth/verify", response_model=TokenResponse)
async def auth_verify(
    channel_id: str,
    request: VerifyRequest
):
    """Verify signed challenge and issue JWT token"""
    channel = channel_manager.get_channel(channel_id)

    try:
        channel.verify_challenge(
            request.public_key,
            request.challenge,
            request.signature
        )
    except ValueError as e:
        # Map ValueError to appropriate HTTP status
        error_msg = str(e)
        if "not found" in error_msg or "expired" in error_msg or "mismatch" in error_msg:
            raise HTTPException(status_code=401, detail=error_msg)
        elif "Invalid" in error_msg:
            if "identifier" in error_msg:
                raise HTTPException(status_code=400, detail=error_msg)
            else:
                raise HTTPException(status_code=401, detail=error_msg)
        elif "Not a member" in error_msg:
            raise HTTPException(status_code=403, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)

    # Issue JWT
    return channel.create_jwt(request.public_key)


@app.post("/channels/{channel_id}/auth/refresh", response_model=TokenResponse)
async def auth_refresh(
    channel_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Refresh JWT token"""
    channel = channel_manager.get_channel(channel_id)

    try:
        return channel.refresh_jwt(credentials.credentials)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


# ============================================================================
# State Endpoints
# ============================================================================

@app.get("/channels/{channel_id}/state/{path:path}", response_model=StateResponse)
async def get_state(
    channel_id: str,
    path: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get state value from channel"""
    channel = channel_manager.get_channel(channel_id)

    try:
        state = channel.get_state(path, credentials.credentials)
        return StateResponse(**state)
    except ValueError as e:
        error_msg = str(e)
        if "not found" in error_msg.lower():
            raise HTTPException(status_code=404, detail=error_msg)
        elif "permission" in error_msg.lower():
            raise HTTPException(status_code=403, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)


@app.put("/channels/{channel_id}/state/{path:path}")
async def put_state(
    channel_id: str,
    path: str,
    state_data: StateData,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Set state value in channel"""
    channel = channel_manager.get_channel(channel_id)

    try:
        updated_at = channel.set_state(
            path,
            state_data.data,
            credentials.credentials,
            state_data.signature,
            state_data.signed_by
        )
        return {"path": path, "updated_at": updated_at}
    except ValueError as e:
        error_msg = str(e)
        if "permission" in error_msg.lower():
            raise HTTPException(status_code=403, detail=error_msg)
        elif "required" in error_msg.lower() or "must be" in error_msg.lower():
            raise HTTPException(status_code=400, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)


@app.delete("/channels/{channel_id}/state/{path:path}")
async def delete_state(
    channel_id: str,
    path: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Delete state value from channel"""
    channel = channel_manager.get_channel(channel_id)

    try:
        channel.delete_state(path, credentials.credentials)
        return Response(status_code=204)
    except ValueError as e:
        error_msg = str(e)
        if "not found" in error_msg.lower():
            raise HTTPException(status_code=404, detail=error_msg)
        elif "permission" in error_msg.lower():
            raise HTTPException(status_code=403, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)


# ============================================================================
# Message Endpoints
# ============================================================================

@app.get("/channels/{channel_id}/topics/{topic_id}/messages", response_model=MessagesResponse)
async def get_messages(
    channel_id: str,
    topic_id: str,
    from_ts: Optional[int] = Query(None, alias="from"),
    to_ts: Optional[int] = Query(None, alias="to"),
    limit: int = Query(100, ge=1, le=1000),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Query messages in a topic with time-based filtering"""
    validate_topic_id(topic_id)
    channel = channel_manager.get_channel(channel_id)

    try:
        messages = channel.get_messages(topic_id, credentials.credentials, from_ts, to_ts, limit + 1)

        has_more = len(messages) > limit
        if has_more:
            messages = messages[:limit]

        return MessagesResponse(
            messages=[Message(**msg) for msg in messages],
            has_more=has_more
        )
    except ValueError as e:
        error_msg = str(e)
        if "permission" in error_msg.lower():
            raise HTTPException(status_code=403, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)


@app.post("/channels/{channel_id}/topics/{topic_id}/messages", status_code=201)
async def post_message(
    channel_id: str,
    topic_id: str,
    message: MessagePost,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Post a new message to a topic"""
    validate_topic_id(topic_id)
    channel = channel_manager.get_channel(channel_id)

    try:
        server_timestamp = await channel.post_message(
            topic_id=topic_id,
            message_hash=message.message_hash,
            prev_hash=message.prev_hash,
            encrypted_payload=message.encrypted_payload,
            signature=message.signature,
            token=credentials.credentials
        )

        return {
            "message_hash": message.message_hash,
            "server_timestamp": server_timestamp
        }
    except ValueError as e:
        error_msg = str(e)
        if "permission" in error_msg.lower():
            raise HTTPException(status_code=403, detail=error_msg)
        elif "conflict" in error_msg.lower():
            raise HTTPException(status_code=409, detail=error_msg)
        elif "mismatch" in error_msg.lower() or "signature" in error_msg.lower() or "must have" in error_msg.lower():
            raise HTTPException(status_code=400, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)


@app.get("/channels/{channel_id}/messages/{message_hash}", response_model=Message)
async def get_message_by_hash(
    channel_id: str,
    message_hash: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get a specific message by its hash"""
    channel = channel_manager.get_channel(channel_id)

    try:
        message = channel.get_message_by_hash(message_hash, credentials.credentials)
        return Message(**message)
    except ValueError as e:
        error_msg = str(e)
        if "not found" in error_msg.lower():
            raise HTTPException(status_code=404, detail=error_msg)
        elif "permission" in error_msg.lower():
            raise HTTPException(status_code=403, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)


# ============================================================================
# Blob Endpoints
# ============================================================================

@app.put("/channels/{channel_id}/blobs/{blob_id}", status_code=201, response_model=BlobUploadResponse)
async def upload_blob(
    channel_id: str,
    blob_id: str,
    request: bytes = Depends(lambda: None),  # Will be overridden by actual request body
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Upload an encrypted blob with explicit blob_id"""
    # Get channel and extract user from token
    channel = channel_manager.get_channel(channel_id)
    payload = channel.verify_jwt(credentials.credentials)
    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token: missing user ID")

    # Check if blob store supports pre-signed URLs
    upload_url = blob_store.get_upload_url(blob_id)
    if upload_url:
        # Authorize before returning pre-signed URL
        try:
            channel.authorize_blob_upload(user_id, credentials.credentials)
        except ValueError as e:
            raise HTTPException(status_code=403, detail=str(e))

        # Redirect client to upload directly to S3
        return RedirectResponse(
            url=upload_url,
            status_code=307  # Temporary redirect, preserving method (PUT)
        )

    # Direct upload to server - read request body
    blob_data = request

    # Use Channel method for upload (handles authorization, validation, and storage)
    try:
        result = channel.upload_blob(user_id, credentials.credentials, blob_id, blob_data)
        return BlobUploadResponse(**result)
    except FileExistsError:
        raise HTTPException(status_code=409, detail="Blob already exists")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/channels/{channel_id}/blobs/{blob_id}")
async def download_blob(
    channel_id: str,
    blob_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Download a blob by its ID"""
    # Get channel and extract user from token
    channel = channel_manager.get_channel(channel_id)
    payload = channel.verify_jwt(credentials.credentials)
    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token: missing user ID")

    # Check if blob store supports pre-signed URLs (authorization happens inside method)
    try:
        download_url = channel.get_blob_download_url(user_id, credentials.credentials, blob_id)
        if download_url:
            # Redirect client to download directly from S3
            return RedirectResponse(
                url=download_url,
                status_code=307  # Temporary redirect
            )
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    # Direct download from server - use Channel method (authorization happens inside)
    try:
        blob_data = channel.download_blob(user_id, credentials.credentials, blob_id)
        if not blob_data:
            raise HTTPException(status_code=404, detail="Blob not found")
        return Response(content=blob_data, media_type="application/octet-stream")
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))


@app.delete("/channels/{channel_id}/blobs/{blob_id}", status_code=204)
async def delete_blob(
    channel_id: str,
    blob_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Delete a blob (only by uploader or channel admin)"""
    # Get channel and extract user from token
    channel = channel_manager.get_channel(channel_id)
    payload = channel.verify_jwt(credentials.credentials)
    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token: missing user ID")

    # Use Channel method for deletion (handles authorization and reference removal)
    try:
        channel.delete_blob(user_id, credentials.credentials, blob_id)
        return Response(status_code=204)
    except ValueError as e:
        # Blob not found or authorization failed
        if "not found" in str(e).lower():
            raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=403, detail=str(e))


# ============================================================================
# WebSocket Endpoint
# ============================================================================

async def authenticate_websocket(channel_id: str, token: Optional[str]) -> dict:
    """Authenticate WebSocket connection using JWT token"""
    if not token:
        raise WebSocketDisconnect(code=1008, reason="Authentication required")

    channel = channel_manager.get_channel(channel_id)

    try:
        payload = channel.verify_jwt(token)
        return payload
    except ValueError as e:
        raise WebSocketDisconnect(code=1008, reason=str(e))


@app.websocket("/channels/{channel_id}/stream")
async def websocket_stream(
    websocket: WebSocket,
    channel_id: str,
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint for streaming real-time messages from a channel.

    Authentication: Provide JWT token via query parameter ?token=<jwt>
    """
    # Authenticate the connection
    try:
        current_user = await authenticate_websocket(channel_id, token)
    except WebSocketDisconnect as e:
        await websocket.close(code=e.code, reason=e.reason)
        return

    channel = channel_manager.get_channel(channel_id)

    # Handle the WebSocket connection (accept, keep-alive, broadcast, cleanup)
    await channel.handle_websocket(websocket)


# ============================================================================
# Health Check
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": int(time.time() * 1000)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.server.host, port=config.server.port)
