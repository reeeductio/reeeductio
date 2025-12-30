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
from typing import Optional, List, Dict, Any, Set
import jwt
import hashlib
import time
import json
import re
from datetime import datetime, timedelta
import secrets
import base64
import asyncio

from sqlite_message_store import SqliteMessageStore
from sqlite_state_store import SqliteStateStore
from crypto import CryptoUtils
from authorization import AuthorizationEngine
from identifiers import (
    encode_channel_id, encode_user_id, encode_message_id, encode_blob_id,
    extract_public_key, extract_hash, decode_identifier, IdType
)
from config import get_config
from s3_blob_store import S3BlobStore
from sqlite_blob_store import SqliteBlobStore
from filesystem_blob_store import FilesystemBlobStore
from websocket_manager import WebSocketManager

# Load configuration
config = get_config()

# Initialize FastAPI app
app = FastAPI(
    title="E2EE PubSub Messaging API",
    description="End-to-end encrypted messaging with capability-based authorization",
    version="1.0.0"
)

# Initialize components
message_store = SqliteMessageStore(config.database.message_db_path)
state_store = SqliteStateStore(config.database.state_db_path)
crypto = CryptoUtils()
authz = AuthorizationEngine(state_store, crypto)
security = HTTPBearer()

# Initialize blob store based on configuration
if config.blob_store.type == "filesystem":
    blob_store = FilesystemBlobStore(config.blob_store.path)
elif config.blob_store.type == "s3":
    blob_store = S3BlobStore(config.blob_store)
elif config.blob_store.type == "sqlite":
    blob_store = SqliteBlobStore(config.blob_store.db_path)
else:
    raise ValueError(f"Unsupported blob store type: {config.blob_store.type}")

# JWT configuration
JWT_SECRET = config.server.jwt_secret or secrets.token_urlsafe(32)
JWT_ALGORITHM = config.server.jwt_algorithm
JWT_EXPIRY_HOURS = config.server.jwt_expiry_hours
CHALLENGE_EXPIRY_SECONDS = config.server.challenge_expiry_seconds

# Topic ID validation (slug format)
TOPIC_ID_PATTERN = re.compile(r'^[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]$')

# In-memory challenge storage (in production, use Redis)
challenges: Dict[str, Dict[str, Any]] = {}

# Initialize connection manager
ws_manager = WebSocketManager()


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
# JWT Utilities
# ============================================================================

def create_jwt(channel_id: str, public_key: str) -> dict:
    """Create a JWT token for authenticated user"""
    now_seconds = int(time.time())  # JWT standard uses seconds
    expiry_seconds = now_seconds + (JWT_EXPIRY_HOURS * 3600)

    payload = {
        "channel_id": channel_id,
        "public_key": public_key,
        "iat": now_seconds,
        "exp": expiry_seconds
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"token": token, "expires_at": expiry_seconds * 1000}  # Return milliseconds for API consistency


def verify_jwt(token: str) -> dict:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Dependency to get current authenticated user from JWT"""
    return verify_jwt(credentials.credentials)


# ============================================================================
# Authentication Endpoints
# ============================================================================

@app.post("/channels/{channel_id}/auth/challenge", response_model=ChallengeResponse)
async def auth_challenge(
    channel_id: str,
    request: ChallengeRequest
):
    """Request an authentication challenge (random nonce to sign)"""
    # Generate random challenge
    challenge_bytes = secrets.token_bytes(32)
    challenge = crypto.base64_encode(challenge_bytes)

    expires_at = int(time.time() * 1000) + (CHALLENGE_EXPIRY_SECONDS * 1000)  # milliseconds
    
    # Store challenge (in production, use Redis with TTL)
    challenge_key = f"{channel_id}:{request.public_key}"
    challenges[challenge_key] = {
        "challenge": challenge,
        "expires_at": expires_at
    }
    
    return ChallengeResponse(
        challenge=challenge,
        expires_at=expires_at
    )


@app.post("/channels/{channel_id}/auth/verify", response_model=TokenResponse)
async def auth_verify(
    channel_id: str,
    request: VerifyRequest
):
    """Verify signed challenge and issue JWT token"""
    challenge_key = f"{channel_id}:{request.public_key}"
    
    # Check if challenge exists and is valid
    if challenge_key not in challenges:
        raise HTTPException(status_code=401, detail="Challenge not found")
    
    stored = challenges[challenge_key]

    if stored["expires_at"] < int(time.time() * 1000):
        del challenges[challenge_key]
        raise HTTPException(status_code=401, detail="Challenge expired")
    
    if stored["challenge"] != request.challenge:
        raise HTTPException(status_code=401, detail="Challenge mismatch")
    
    # Extract public key from typed user identifier and verify signature
    try:
        user_pubkey_bytes = extract_public_key(request.public_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid user identifier: {e}")

    message = request.challenge.encode('utf-8')
    if not crypto.verify_signature(
        message,
        crypto.base64_decode(request.signature),
        user_pubkey_bytes
    ):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Check if user is a member of this channel
    member = state_store.get_state(channel_id, f"members/{request.public_key}")
    if not member and request.public_key != channel_id:
        raise HTTPException(
            status_code=403,
            detail="Not a member of this channel"
        )
    
    # Clean up challenge
    del challenges[challenge_key]
    
    # Issue JWT
    return create_jwt(channel_id, request.public_key)


@app.post("/channels/{channel_id}/auth/refresh", response_model=TokenResponse)
async def auth_refresh(
    channel_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Refresh JWT token"""
    if current_user["channel_id"] != channel_id:
        raise HTTPException(status_code=403, detail="Token channel mismatch")
    
    return create_jwt(channel_id, current_user["public_key"])


# ============================================================================
# State Endpoints
# ============================================================================

@app.get("/channels/{channel_id}/state/{path:path}", response_model=StateResponse)
async def get_state(
    channel_id: str,
    path: str,
    current_user: dict = Depends(get_current_user)
):
    """Get state value from channel"""
    if current_user["channel_id"] != channel_id:
        raise HTTPException(status_code=403, detail="Wrong channel")
    
    # Check read permission
    if not authz.check_permission(
        channel_id,
        current_user["public_key"],
        "read",
        path
    ):
        raise HTTPException(status_code=403, detail="No read permission")
    
    state = state_store.get_state(channel_id, path)
    if state is None:
        raise HTTPException(status_code=404, detail="State not found")

    return StateResponse(**state)


@app.put("/channels/{channel_id}/state/{path:path}")
async def put_state(
    channel_id: str,
    path: str,
    state_data: StateData,
    current_user: dict = Depends(get_current_user)
):
    """Set state value in channel"""
    if current_user["channel_id"] != channel_id:
        raise HTTPException(status_code=403, detail="Wrong channel")
    
    # Check if state already exists
    existing = state_store.get_state(channel_id, path)
    operation = "write" if existing else "create"
    
    # Check permission
    if not authz.check_permission(
        channel_id,
        current_user["public_key"],
        operation,
        path
    ):
        raise HTTPException(
            status_code=403,
            detail=f"No {operation} permission for path: {path}"
        )
    
    # For sensitive paths (like capabilities), validate signature and subset
    if authz.is_capability_path(path):
        if not state_data.signature or not state_data.signed_by:
            raise HTTPException(
                status_code=400,
                detail="Signature required for capability grants"
            )

        # Capability grants must be base64-encoded JSON objects
        # Decode and parse to verify structure
        try:
            decoded = base64.b64decode(state_data.data)
            capability_dict = json.loads(decoded)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Capability grants must be base64-encoded JSON objects: {e}"
            )

        # Verify the capability itself
        if not authz.verify_capability_grant(
            channel_id,
            path,
            capability_dict,
            state_data.signed_by,
            state_data.signature
        ):
            raise HTTPException(
                status_code=403,
                detail="Invalid capability grant or privilege escalation"
            )

    # Store state
    now = int(time.time() * 1000)  # milliseconds
    state_store.set_state(
        channel_id,
        path,
        state_data.data,
        current_user["public_key"],
        now
    )

    return {"path": path, "updated_at": now}


@app.delete("/channels/{channel_id}/state/{path:path}")
async def delete_state(
    channel_id: str,
    path: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete state value from channel"""
    if current_user["channel_id"] != channel_id:
        raise HTTPException(status_code=403, detail="Wrong channel")
    
    # Check write permission for deletion
    if not authz.check_permission(
        channel_id,
        current_user["public_key"],
        "write",
        path
    ):
        raise HTTPException(status_code=403, detail="No delete permission")
    
    if not state_store.delete_state(channel_id, path):
        raise HTTPException(status_code=404, detail="State not found")

    return Response(status_code=204)


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
    current_user: dict = Depends(get_current_user)
):
    """Query messages in a topic with time-based filtering"""
    validate_topic_id(topic_id)

    if current_user["channel_id"] != channel_id:
        raise HTTPException(status_code=403, detail="Wrong channel")
    
    # Check read permission for topic messages
    if not authz.check_permission(
        channel_id,
        current_user["public_key"],
        "read",
        f"topics/{topic_id}/messages/"
    ):
        raise HTTPException(status_code=403, detail="No read permission for topic")
    
    messages = message_store.get_messages(channel_id, topic_id, from_ts, to_ts, limit + 1)
    
    has_more = len(messages) > limit
    if has_more:
        messages = messages[:limit]
    
    return MessagesResponse(
        messages=[Message(**msg) for msg in messages],
        has_more=has_more
    )


@app.post("/channels/{channel_id}/topics/{topic_id}/messages", status_code=201)
async def post_message(
    channel_id: str,
    topic_id: str,
    message: MessagePost,
    current_user: dict = Depends(get_current_user)
):
    """Post a new message to a topic"""
    validate_topic_id(topic_id)

    if current_user["channel_id"] != channel_id:
        raise HTTPException(status_code=403, detail="Wrong channel")
    
    # Check create permission
    if not authz.check_permission(
        channel_id,
        current_user["public_key"],
        "create",
        f"topics/{topic_id}/messages/"
    ):
        raise HTTPException(status_code=403, detail="No post permission")
    
    # Sender must match authenticated user
    sender = current_user["public_key"]

    # Validate message hash (includes sender)
    expected_hash = crypto.compute_message_hash(
        channel_id,
        topic_id,
        message.prev_hash,
        message.encrypted_payload,
        sender
    )

    if expected_hash != message.message_hash:
        raise HTTPException(
            status_code=400,
            detail="Message hash mismatch"
        )

    # Verify signature over message hash
    try:
        signature_bytes = crypto.base64_decode(message.signature)
        sender_bytes = extract_public_key(sender)

        if not crypto.verify_message_signature(
            message.message_hash,
            signature_bytes,
            sender_bytes
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid message signature"
            )
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid identifier: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Signature verification failed: {str(e)}"
        )

    # Get current chain head
    current_head = message_store.get_chain_head(channel_id, topic_id)

    # Validate prev_hash
    if current_head is None:
        # First message in topic
        if message.prev_hash is not None:
            raise HTTPException(
                status_code=400,
                detail="First message must have prev_hash=null"
            )
    else:
        if message.prev_hash != current_head["message_hash"]:
            raise HTTPException(
                status_code=409,
                detail=f"Chain conflict: expected prev_hash={current_head['message_hash']}"
            )

    # Store message
    server_timestamp = int(time.time() * 1000)  # milliseconds
    message_store.add_message(
        channel_id=channel_id,
        topic_id=topic_id,
        message_hash=message.message_hash,
        prev_hash=message.prev_hash,
        encrypted_payload=message.encrypted_payload,
        sender=sender,
        signature=message.signature,
        server_timestamp=server_timestamp
    )

    # Broadcast to WebSocket subscribers
    message_dict = {
        "message_hash": message.message_hash,
        "topic_id": topic_id,
        "prev_hash": message.prev_hash,
        "encrypted_payload": message.encrypted_payload,
        "sender": sender,
        "signature": message.signature,
        "server_timestamp": server_timestamp
    }
    await ws_manager.broadcast_message(channel_id, message_dict)

    return {
        "message_hash": message.message_hash,
        "server_timestamp": server_timestamp
    }


@app.get("/channels/{channel_id}/messages/{message_hash}", response_model=Message)
async def get_message_by_hash(
    channel_id: str,
    message_hash: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a specific message by its hash"""
    if current_user["channel_id"] != channel_id:
        raise HTTPException(status_code=403, detail="Wrong channel")
    
    message = message_store.get_message_by_hash(channel_id, message_hash)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    # Check read permission for the message's topic
    if not authz.check_permission(
        channel_id,
        current_user["public_key"],
        "read",
        f"topics/{message['topic_id']}/messages/"
    ):
        raise HTTPException(status_code=403, detail="No read permission")
    
    return Message(**message)


# ============================================================================
# Blob Endpoints
# ============================================================================

@app.put("/blobs/{blob_id}", status_code=201, response_model=BlobUploadResponse)
async def upload_blob(
    blob_id: str,
    request: bytes = Depends(lambda: None),  # Will be overridden by actual request body
    current_user: dict = Depends(get_current_user)
):
    """Upload an encrypted blob with explicit blob_id"""
    # Check if blob store supports pre-signed URLs
    upload_url = blob_store.get_upload_url(blob_id)
    if upload_url:
        # Redirect client to upload directly to S3
        return RedirectResponse(
            url=upload_url,
            status_code=307  # Temporary redirect, preserving method (PUT)
        )

    # Direct upload to server
    # In real implementation, read from request.body()
    # For now, this is a placeholder
    blob_data = request

    # Compute expected blob ID from content to verify integrity
    expected_blob_id = crypto.compute_blob_id(blob_data)

    # Verify that provided blob_id matches the content hash
    if blob_id != expected_blob_id:
        raise HTTPException(
            status_code=400,
            detail=f"blob_id mismatch: provided {blob_id}, expected {expected_blob_id}"
        )

    # Store blob
    try:
        blob_store.add_blob(blob_id, blob_data)
    except FileExistsError:
        raise HTTPException(
            status_code=409,
            detail=f"Blob {blob_id} already exists"
        )
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid blob: {str(e)}"
        )

    return BlobUploadResponse(
        blob_id=blob_id,
        size=len(blob_data)
    )


@app.get("/blobs/{blob_id}")
async def download_blob(
    blob_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Download a blob by its ID"""
    # Check if blob store supports pre-signed URLs
    download_url = blob_store.get_download_url(blob_id)
    if download_url:
        # Redirect client to download directly from S3
        return RedirectResponse(
            url=download_url,
            status_code=307  # Temporary redirect
        )

    # Direct download from server
    blob_data = blob_store.get_blob(blob_id)
    if not blob_data:
        raise HTTPException(status_code=404, detail="Blob not found")

    return Response(content=blob_data, media_type="application/octet-stream")


@app.delete("/blobs/{blob_id}", status_code=204)
async def delete_blob(
    blob_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a blob"""
    if not blob_store.delete_blob(blob_id):
        raise HTTPException(status_code=404, detail="Blob not found")

    return Response(status_code=204)


# ============================================================================
# WebSocket Endpoint
# ============================================================================

async def authenticate_websocket(channel_id: str, token: Optional[str]) -> dict:
    """Authenticate WebSocket connection using JWT token"""
    if not token:
        raise WebSocketDisconnect(code=1008, reason="Authentication required")

    try:
        payload = verify_jwt(token)
        if payload["channel_id"] != channel_id:
            raise WebSocketDisconnect(code=1008, reason="Token channel mismatch")
        return payload
    except HTTPException as e:
        raise WebSocketDisconnect(code=1008, reason=e.detail)


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

    # Connect to the channel
    await ws_manager.connect(channel_id, websocket)

    try:
        # Keep connection alive and handle incoming messages (if needed)
        while True:
            # Wait for any client messages (ping/pong, etc.)
            # In this implementation, we primarily send messages to clients
            # but we need to keep the connection open
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                # Handle ping/pong or other control messages if needed
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send periodic ping to keep connection alive
                try:
                    await websocket.send_text(json.dumps({"type": "ping"}))
                except Exception:
                    break
            except WebSocketDisconnect:
                break

    except Exception as e:
        # Log error if needed
        pass
    finally:
        # Clean up connection
        ws_manager.disconnect(channel_id, websocket)


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
