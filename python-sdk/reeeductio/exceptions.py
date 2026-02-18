"""
Custom exceptions for reeeductio SDK.
"""


class ReeeductioError(Exception):
    """Base exception for all reeeductio SDK errors."""

    pass


class AuthenticationError(ReeeductioError):
    """Raised when authentication fails."""

    pass


class AuthorizationError(ReeeductioError):
    """Raised when user lacks permission for an operation."""

    pass


class ValidationError(ReeeductioError):
    """Raised when input validation fails."""

    pass


class ChainError(ReeeductioError):
    """Raised when message chain integrity is violated."""

    pass


class ConflictError(ReeeductioError):
    """Raised when a chain conflict occurs (prev_hash mismatch)."""

    pass


class NotFoundError(ReeeductioError):
    """Raised when a requested resource is not found."""

    pass


class BlobError(ReeeductioError):
    """Raised for blob-related errors (hash mismatch, too large, etc.)."""

    pass


class NetworkError(ReeeductioError):
    """Raised for network/transport errors."""

    pass


class StreamError(ReeeductioError):
    """Raised for WebSocket streaming errors."""

    pass


class OpaqueError(ReeeductioError):
    """Raised for OPAQUE protocol errors."""

    pass


class OpaqueNotEnabledError(OpaqueError):
    """Raised when OPAQUE is not enabled for a space."""

    pass
