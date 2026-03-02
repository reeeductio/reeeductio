"""
reeeductio - Python SDK for the reeeductio Spaces API.

A clean, modern SDK for end-to-end encrypted messaging with capability-based authorization.
"""

from .auth import AsyncAuthSession, AuthSession
from .client import AdminClient, AsyncAdminClient, AsyncSpace, Space
from .local_store import LocalMessageStore
from .crypto import (
    Ed25519KeyPair,
    compute_hash,
    decode_base64,
    decode_urlsafe_base64,
    derive_key,
    encode_base64,
    encode_urlsafe_base64,
    generate_keypair,
    get_identifier_type,
    sign_data,
    to_blob_id,
    to_message_id,
    verify_signature,
)
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    BlobError,
    ChainError,
    ConflictError,
    NetworkError,
    NotFoundError,
    OpaqueError,
    OpaqueNotEnabledError,
    ReeeductioError,
    StreamError,
    ValidationError,
)
from .opaque import (
    OpaqueCredentials,
    opaque_login,
    opaque_login_async,
)
from .models import (
    AuthChallenge,
    AuthToken,
    BlobCreated,
    Capability,
    CapabilityOp,
    DataEntry,
    Error,
    Member,
    Message,
    MessageCreated,
    MessageList,
    Role,
    RoleGrant,
)

try:
    from importlib.metadata import version as _version
    __version__ = _version("reeeductio")
except Exception:
    __version__ = "unknown"

__all__ = [
    # Main clients
    "Space",
    "AsyncSpace",
    # Admin clients
    "AdminClient",
    "AsyncAdminClient",
    # Local storage
    "LocalMessageStore",
    # Authentication
    "AuthSession",
    "AsyncAuthSession",
    # OPAQUE password-based key recovery
    "opaque_login",
    "opaque_login_async",
    "OpaqueCredentials",
    # Crypto utilities
    "Ed25519KeyPair",
    "generate_keypair",
    "sign_data",
    "verify_signature",
    "compute_hash",
    "derive_key",
    "to_message_id",
    "to_blob_id",
    "get_identifier_type",
    "encode_base64",
    "decode_base64",
    "encode_urlsafe_base64",
    "decode_urlsafe_base64",
    # Models
    "Message",
    "MessageCreated",
    "MessageList",
    "Capability",
    "CapabilityOp",
    "Member",
    "Role",
    "RoleGrant",
    "DataEntry",
    "BlobCreated",
    "AuthChallenge",
    "AuthToken",
    "Error",
    # Exceptions
    "ReeeductioError",
    "AuthenticationError",
    "AuthorizationError",
    "ValidationError",
    "ChainError",
    "ConflictError",
    "NotFoundError",
    "BlobError",
    "NetworkError",
    "StreamError",
    "OpaqueError",
    "OpaqueNotEnabledError",
]
