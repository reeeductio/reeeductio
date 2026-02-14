"""
Data models for reeeductio Spaces API.

All models use dataclasses for clean serialization and type safety.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


@dataclass
class Message:
    """
    Message in a topic chain.

    Messages form blockchain-like chains with hash pointers.
    For state messages, the type field contains the state path.
    """

    message_hash: str  # 44-char base64 with type header
    topic_id: str  # slug format
    type: str  # message category or state path
    sender: str  # 44-char base64 user ID
    signature: str  # base64-encoded Ed25519 signature
    data: str  # base64-encoded encrypted data
    prev_hash: str | None  # 44-char base64 hash of previous message
    server_timestamp: int  # Unix timestamp in milliseconds

    def is_state_message(self) -> bool:
        """Check if this is a state message (in 'state' topic)."""
        return self.topic_id == "state"

@dataclass
class DecryptedMessage(Message):
    decrypted: str  # base64-encoded decrypted data

class CapabilityOp(str, Enum):
    """Capability operation types."""

    READ = "read"
    CREATE = "create"
    WRITE = "write"  # superset of create


@dataclass
class Capability:
    """
    Permission to perform an operation on a path pattern.

    Supports wildcards: {self}, {any}, {other}, trailing /
    """

    op: CapabilityOp
    path: str  # path pattern with optional wildcards

    def __post_init__(self):
        if isinstance(self.op, str):
            self.op = CapabilityOp(self.op)


@dataclass
class Member:
    """Space member information."""

    public_key: str  # 44-char base64 user ID
    added_at: int  # Unix timestamp in milliseconds
    added_by: str  # 44-char base64 user ID


@dataclass
class Role:
    """
    Role definition with assigned capabilities.

    Stored at: auth/roles/{role_id}
    """

    role_id: str  # human-readable role identifier
    description: str
    created_by: str  # 44-char base64 user ID
    created_at: int  # Unix timestamp in milliseconds
    signature: str  # base64-encoded Ed25519 signature


@dataclass
class RoleGrant:
    """
    Grant of a role to a user.

    Stored at: auth/users/{user_id}/roles/{role_id}
    """

    user_id: str  # 44-char base64
    role_id: str
    granted_by: str  # 44-char base64 user ID
    granted_at: int  # Unix timestamp in milliseconds
    signature: str  # base64-encoded Ed25519 signature
    expires_at: int | None = None  # Optional expiration


@dataclass
class DataEntry:
    """
    Key-value data entry in the simple data store.

    Every entry is cryptographically signed.
    """

    data: str  # base64-encoded data
    signature: str  # base64-encoded Ed25519 signature
    signed_by: str  # 44-char base64 user/tool ID
    signed_at: int  # Unix timestamp in milliseconds


@dataclass
class Error:
    """API error response."""

    error: str
    code: str | None = None
    details: dict[str, Any] | None = None


@dataclass
class AuthChallenge:
    """Authentication challenge response."""

    challenge: str  # base64-encoded nonce
    expires_at: int  # Unix timestamp in milliseconds


@dataclass
class AuthToken:
    """JWT token response."""

    token: str  # JWT bearer token
    expires_at: int  # Unix timestamp in milliseconds


@dataclass
class MessageCreated:
    """Response when a message is successfully created."""

    message_hash: str  # 44-char base64
    server_timestamp: int  # Unix timestamp in milliseconds


@dataclass
class BlobCreated:
    """Response when a blob is successfully uploaded."""

    blob_id: str  # 44-char base64 SHA256 hash
    size: int  # bytes


@dataclass
class MessageList:
    """List of messages from a topic query."""

    messages: list[Message] = field(default_factory=list)
