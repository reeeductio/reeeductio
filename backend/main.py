"""
E2EE PubSub Messaging System - Main Application

A capability-based, end-to-end encrypted messaging system with:
- Space-scoped access control
- Blockchain-style message chains per topic
- Granular, signed capabilities
- Zero-knowledge server design
"""

from fastapi import FastAPI, HTTPException, Depends, Header, Query, Path as PathParam, WebSocket, WebSocketDisconnect, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import Response, RedirectResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import time
import re
import secrets
import jwt

from crypto import CryptoUtils
from config import get_config, FirestoreDatabaseConfig
from s3_blob_store import S3BlobStore
from sqlite_blob_store import SqliteBlobStore
from filesystem_blob_store import FilesystemBlobStore
from firestore_data_store import FirestoreDataStore
from firestore_message_store import FirestoreMessageStore
from space_manager import SpaceManager
from logging_config import setup_logging, get_logger

# Load configuration
config = get_config()

# Setup logging
setup_logging(
    level=config.logging.level,
    log_format=config.logging.format,
    log_file=config.logging.file,
    max_bytes=config.logging.max_bytes,
    backup_count=config.logging.backup_count,
    enable_access_log=config.logging.enable_access_log
)

logger = get_logger(__name__)

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
logger.info(f"Initializing blob store: type={config.blob_store.type}")
if config.blob_store.type == "filesystem":
    blob_store = FilesystemBlobStore(config.blob_store.path)
elif config.blob_store.type == "s3":
    blob_store = S3BlobStore(config.blob_store)
    logger.info(f"S3 blob store configured: bucket={config.blob_store.bucket_name}")
elif config.blob_store.type == "sqlite":
    blob_store = SqliteBlobStore(config.blob_store.db_path)
else:
    raise ValueError(f"Unsupported blob store type: {config.blob_store.type}")

# Initialize store factories based on database config
state_store_factory = None
message_store_factory = None

if isinstance(config.database, FirestoreDatabaseConfig):
    # Firestore: create factories that return shared store instances
    project_id = config.database.project_id
    database_id = config.database.database_id
    logger.info(f"Using Firestore database: project={project_id}, database={database_id}")

    state_store_factory = lambda: FirestoreDataStore(project_id, database_id)
    message_store_factory = lambda: FirestoreMessageStore(project_id, database_id)
else:
    logger.info("Using SQLite database (per-space stores)")
# else: SQLite (default) - SpaceManager creates per-space stores

# Initialize components
logger.info("Initializing space manager")
space_manager = SpaceManager(
    base_storage_dir="spaces",
    max_cached_spaces=1000,
    state_store_factory=state_store_factory,
    message_store_factory=message_store_factory,
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


class KVData(BaseModel):
    """Data item for use with /data endpoints."""
    data: str = Field(..., description="Base64-encoded state data")
    signature: str = Field(..., description="Ed25519 signature over (space_id|path|data|signed_at)")
    signed_by: str = Field(..., description="Typed user/tool identifier of signer")
    signed_at: int = Field(..., description="Unix timestamp in milliseconds when entry was signed")


class MessagePost(BaseModel):
    type: str = Field(default="chat.text", description="Message type (e.g., 'chat.text', 'chat.image')")
    prev_hash: Optional[str] = Field(None, description="SHA256 of previous message")
    data: str = Field(..., description="Base64-encoded message content", max_length=102_400)
    message_hash: str = Field(..., description="SHA256 hash of this message")
    signature: str = Field(..., description="Base64-encoded Ed25519 signature over message_hash")


class Message(BaseModel):
    message_hash: str
    topic_id: str
    type: str
    prev_hash: Optional[str]
    data: str
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

@app.post("/spaces/{space_id}/auth/challenge", response_model=ChallengeResponse)
async def auth_challenge(
    space_id: str,
    request: ChallengeRequest
):
    """Request an authentication challenge (random nonce to sign)"""
    logger.debug(f"Challenge requested: space={space_id}, user={request.public_key[:16]}...")
    space = space_manager.get_space(space_id)
    result = space.create_challenge(request.public_key, CHALLENGE_EXPIRY_SECONDS)

    return ChallengeResponse(
        challenge=result["challenge"],
        expires_at=result["expires_at"]
    )


@app.post("/spaces/{space_id}/auth/verify", response_model=TokenResponse)
async def auth_verify(
    space_id: str,
    request: VerifyRequest
):
    """Verify signed challenge and issue JWT token"""
    space = space_manager.get_space(space_id)

    try:
        space.verify_challenge(
            request.public_key,
            request.challenge,
            request.signature
        )
        logger.info(f"User authenticated: space={space_id}, user={request.public_key[:16]}...")
    except ValueError as e:
        # Map ValueError to appropriate HTTP status
        error_msg = str(e)
        logger.warning(f"Authentication failed: space={space_id}, user={request.public_key[:16]}..., error={error_msg}")
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
    return space.create_jwt(request.public_key)


@app.post("/spaces/{space_id}/auth/refresh", response_model=TokenResponse)
async def auth_refresh(
    space_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Refresh JWT token"""
    space = space_manager.get_space(space_id)

    try:
        return space.refresh_jwt(credentials.credentials)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


# ============================================================================
# Data Endpoints (Simple Key-Value Store)
# ============================================================================

@app.get("/spaces/{space_id}/data/{path:path}", response_model=KVData)
async def get_data(
    space_id: str,
    path: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get simple key-value data from space"""
    space = space_manager.get_space(space_id)

    try:
        state = space.get_data(path, credentials.credentials)
        return KVData(**state)
    except ValueError as e:
        error_msg = str(e)
        if "not found" in error_msg.lower():
            raise HTTPException(status_code=404, detail=error_msg)
        elif "permission" in error_msg.lower():
            raise HTTPException(status_code=403, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)


@app.put("/spaces/{space_id}/data/{path:path}")
async def put_data(
    space_id: str,
    path: str,
    kv_data: KVData,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Set simple key-value data in space"""
    space = space_manager.get_space(space_id)

    try:
        updated_at = space.set_data(
            path,
            kv_data.data,
            kv_data.signature,
            kv_data.signed_by,
            kv_data.signed_at,
            credentials.credentials
        )
        return {"path": path, "signed_at": updated_at}
    except ValueError as e:
        error_msg = str(e)
        if "permission" in error_msg.lower():
            raise HTTPException(status_code=403, detail=error_msg)
        elif "required" in error_msg.lower() or "must be" in error_msg.lower() or "invalid" in error_msg.lower() or "signature" in error_msg.lower():
            raise HTTPException(status_code=400, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)


@app.delete("/spaces/{space_id}/data/{path:path}")
async def delete_data(
    space_id: str,
    path: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Delete simple key-value data from space"""
    space = space_manager.get_space(space_id)

    try:
        space.delete_data(path, credentials.credentials)
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
# State Endpoints (Event-Sourced Key-Value Store)
# ============================================================================

@app.get("/spaces/{space_id}/state", response_model=MessagesResponse)
async def list_state(
    space_id: str,
    from_ts: Optional[int] = Query(None, alias="from"),
    to_ts: Optional[int] = Query(None, alias="to"),
    limit: int = Query(100, ge=1, le=1000),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Query all state messages from the 'state' topic.

    This is effectively an alias for GET /topics/state/messages.
    State is stored as messages with the state path in the 'type' field.
    """
    space = space_manager.get_space(space_id)

    try:
        messages = space.get_messages("state", credentials.credentials, from_ts, to_ts, limit + 1)

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


@app.get("/spaces/{space_id}/state/{path:path}", response_model=Message)
async def get_state(
    space_id: str,
    path: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Get current materialized state at a specific path.

    The server computes this from the state store (materialized view of state topic).
    """
    space = space_manager.get_space(space_id)

    try:
        state = space.get_state(path, credentials.credentials)
        return Message(**state)
    except ValueError as e:
        error_msg = str(e)
        if "not found" in error_msg.lower():
            raise HTTPException(status_code=404, detail=error_msg)
        elif "permission" in error_msg.lower():
            raise HTTPException(status_code=403, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)


@app.put("/spaces/{space_id}/state/{path:path}")
async def put_state(
    space_id: str,
    path: str,
    msg: MessagePost,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Set state value by posting a message to the 'state' topic"""
    if path != msg.type:
        raise HTTPException(400, detail="Path mismatch")

    space = space_manager.get_space(space_id)

    try:
        server_timestamp = await space.set_state(
            path=path,
            prev_hash=msg.prev_hash,
            data=msg.data,
            message_hash=msg.message_hash,
            signature=msg.signature,
            token=credentials.credentials
        )
        return {"message_hash": msg.message_hash, "server_timestamp": server_timestamp}
    except ValueError as e:
        error_msg = str(e)
        if "permission" in error_msg.lower():
            raise HTTPException(status_code=403, detail=error_msg)
        elif "required" in error_msg.lower() or "must be" in error_msg.lower() or "invalid" in error_msg.lower() or "signature" in error_msg.lower():
            raise HTTPException(status_code=400, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)


# ============================================================================
# Message Endpoints
# ============================================================================

@app.get("/spaces/{space_id}/topics/{topic_id}/messages", response_model=MessagesResponse)
async def get_messages(
    space_id: str,
    topic_id: str,
    from_ts: Optional[int] = Query(None, alias="from"),
    to_ts: Optional[int] = Query(None, alias="to"),
    limit: int = Query(100, ge=1, le=1000),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Query messages in a topic with time-based filtering"""
    validate_topic_id(topic_id)
    space = space_manager.get_space(space_id)

    try:
        messages = space.get_messages(topic_id, credentials.credentials, from_ts, to_ts, limit + 1)

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


@app.post("/spaces/{space_id}/topics/{topic_id}/messages", status_code=201)
async def post_message(
    space_id: str,
    topic_id: str,
    message: MessagePost,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Post a new message to a topic"""
    validate_topic_id(topic_id)
    space = space_manager.get_space(space_id)

    try:
        server_timestamp = await space.post_message(
            topic_id=topic_id,
            message_hash=message.message_hash,
            msg_type=message.type,
            prev_hash=message.prev_hash,
            data=message.data,
            signature=message.signature,
            token=credentials.credentials
        )
        logger.debug(f"Message posted: space={space_id}, topic={topic_id}, hash={message.message_hash[:16]}...")

        return {
            "message_hash": message.message_hash,
            "server_timestamp": server_timestamp
        }
    except ValueError as e:
        error_msg = str(e)
        logger.warning(f"Message post failed: space={space_id}, topic={topic_id}, error={error_msg}")
        if "permission" in error_msg.lower():
            raise HTTPException(status_code=403, detail=error_msg)
        elif "conflict" in error_msg.lower():
            raise HTTPException(status_code=409, detail=error_msg)
        elif "mismatch" in error_msg.lower() or "signature" in error_msg.lower() or "must have" in error_msg.lower():
            raise HTTPException(status_code=400, detail=error_msg)
        else:
            raise HTTPException(status_code=401, detail=error_msg)


@app.get("/spaces/{space_id}/topics/{topic_id}/messages/{message_hash}", response_model=Message)
async def get_message_by_hash(
    space_id: str,
    topic_id: str,
    message_hash: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get a specific message by its hash from a topic"""
    space = space_manager.get_space(space_id)

    try:
        message = space.get_message_by_hash(topic_id, message_hash, credentials.credentials)
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

@app.put("/spaces/{space_id}/blobs/{blob_id}", status_code=201, response_model=BlobUploadResponse)
async def upload_blob(
    space_id: str,
    blob_id: str,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Upload an encrypted blob with explicit blob_id"""
    # Get space and extract user from token
    space = space_manager.get_space(space_id)
    payload = space.verify_jwt(credentials.credentials)
    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token: missing user ID")

    # Get max blob size from config
    max_blob_size = config.server.max_blob_size

    # Check if blob store supports pre-signed URLs
    upload_url = blob_store.get_upload_url(blob_id, max_size=max_blob_size)
    if upload_url:
        # Authorize before returning pre-signed URL
        try:
            space.authorize_blob_upload(user_id, credentials.credentials)
        except ValueError as e:
            raise HTTPException(status_code=403, detail=str(e))

        # Note: For S3 presigned URLs, size limit cannot be enforced in the URL itself.
        # Clients should validate size before upload. Size will be checked when metadata
        # is added via add_blob() or via S3 bucket policies.

        # Redirect client to upload directly to S3
        return RedirectResponse(
            url=upload_url,
            status_code=307  # Temporary redirect, preserving method (PUT)
        )

    # Direct upload to server - read request body with size limit
    content_length = request.headers.get("content-length")

    if content_length and int(content_length) > max_blob_size:
        raise HTTPException(
            status_code=413,
            detail=f"Blob too large. Maximum size is {max_blob_size} bytes ({max_blob_size // (1024*1024)} MB)"
        )

    # Read body in chunks to enforce size limit
    blob_data = bytearray()
    async for chunk in request.stream():
        blob_data.extend(chunk)
        if len(blob_data) > max_blob_size:
            raise HTTPException(
                status_code=413,
                detail=f"Blob too large. Maximum size is {max_blob_size} bytes ({max_blob_size // (1024*1024)} MB)"
            )

    # Use Space method for upload (handles authorization, validation, and storage)
    try:
        result = space.upload_blob(user_id, credentials.credentials, blob_id, bytes(blob_data))
        return BlobUploadResponse(**result)
    except FileExistsError:
        raise HTTPException(status_code=409, detail="Blob already exists")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/spaces/{space_id}/blobs/{blob_id}")
async def download_blob(
    space_id: str,
    blob_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Download a blob by its ID"""
    # Get space and extract user from token
    space = space_manager.get_space(space_id)
    payload = space.verify_jwt(credentials.credentials)
    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token: missing user ID")

    # Check if blob store supports pre-signed URLs (authorization happens inside method)
    try:
        download_url = space.get_blob_download_url(user_id, credentials.credentials, blob_id)
        if download_url:
            # Redirect client to download directly from S3
            return RedirectResponse(
                url=download_url,
                status_code=307  # Temporary redirect
            )
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    # Direct download from server - use Space method (authorization happens inside)
    try:
        blob_data = space.download_blob(user_id, credentials.credentials, blob_id)
        if not blob_data:
            raise HTTPException(status_code=404, detail="Blob not found")
        return Response(content=blob_data, media_type="application/octet-stream")
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))


@app.delete("/spaces/{space_id}/blobs/{blob_id}", status_code=204)
async def delete_blob(
    space_id: str,
    blob_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Delete a blob (only by uploader or space admin)"""
    # Get space and extract user from token
    space = space_manager.get_space(space_id)
    payload = space.verify_jwt(credentials.credentials)
    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token: missing user ID")

    # Use Space method for deletion (handles authorization and reference removal)
    try:
        space.delete_blob(user_id, credentials.credentials, blob_id)
        return Response(status_code=204)
    except ValueError as e:
        # Blob not found or authorization failed
        if "not found" in str(e).lower():
            raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=403, detail=str(e))


# ============================================================================
# WebSocket Endpoint
# ============================================================================

async def authenticate_websocket(space_id: str, token: Optional[str]) -> dict:
    """Authenticate WebSocket connection using JWT token"""
    if not token:
        raise WebSocketDisconnect(code=1008, reason="Authentication required")

    space = space_manager.get_space(space_id)

    try:
        payload = space.verify_jwt(token)
        return payload
    except ValueError as e:
        raise WebSocketDisconnect(code=1008, reason=str(e))


@app.websocket("/spaces/{space_id}/stream")
async def websocket_stream(
    websocket: WebSocket,
    space_id: str,
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint for streaming real-time messages from a space.

    Authentication: Provide JWT token via query parameter ?token=<jwt>
    """
    # Authenticate the connection
    try:
        current_user = await authenticate_websocket(space_id, token)
    except WebSocketDisconnect as e:
        await websocket.close(code=e.code, reason=e.reason)
        return

    space = space_manager.get_space(space_id)

    # Handle the WebSocket connection (accept, keep-alive, broadcast, cleanup)
    await space.handle_websocket(websocket)


# ============================================================================
# Health Check
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": int(time.time() * 1000)}


# Application startup/shutdown events
@app.on_event("startup")
async def startup_event():
    """Log application startup"""
    logger.info(f"Application starting: environment={config.environment}, debug={config.debug}")
    logger.info(f"Server listening on {config.server.host}:{config.server.port}")


@app.on_event("shutdown")
async def shutdown_event():
    """Log application shutdown"""
    logger.info("Application shutting down")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.server.host, port=config.server.port)
