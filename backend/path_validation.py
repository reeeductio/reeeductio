"""
Path validation for Reeeductio authorization system.

Validates user-created paths and capability path patterns to prevent
wildcard injection and ensure consistent path syntax.
"""

import re
from typing import Set


# Path segment pattern: alphanumeric, dot, underscore, hyphen
# Dots allowed for file extensions and versioning (e.g., "photo.jpg", "v1.0")
PATH_SEGMENT_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')

# Reserved wildcards that can only appear in capability patterns
RESERVED_WILDCARDS: Set[str] = {'{self}', '{any}', '{other}', '{...}'}


class PathValidationError(ValueError):
    """Raised when a path fails validation"""
    pass


def validate_path_segment(segment: str, allow_wildcards: bool = False) -> bool:
    """
    Validate a single path segment.

    Args:
        segment: The path segment to validate
        allow_wildcards: If True, allow reserved wildcards like {self}, {any}

    Returns:
        True if segment is valid, False otherwise
    """
    if not segment:
        return False

    # Check if it's a reserved wildcard
    if segment in RESERVED_WILDCARDS:
        return allow_wildcards

    # Check if it contains braces (potential wildcard attempt)
    if '{' in segment or '}' in segment:
        return False

    # Must match slug pattern
    return PATH_SEGMENT_PATTERN.match(segment) is not None


def validate_user_path(path: str) -> None:
    """
    Validate a user-created path for state writes or message topics.

    User paths must use slug format with no wildcards or special characters.

    Args:
        path: The path to validate

    Raises:
        PathValidationError: If path is invalid

    Examples:
        validate_user_path("profiles/alice")           # ✅ OK
        validate_user_path("topics/general/messages")  # ✅ OK
        validate_user_path("files/photo.jpg")          # ✅ OK
        validate_user_path("api/v1.0/users")           # ✅ OK
        validate_user_path("profiles/{self}")          # ❌ Raises error
        validate_user_path("topics/{any}/messages")    # ❌ Raises error
        validate_user_path("files/my file.txt")        # ❌ Raises error
    """
    # Normalize - remove leading/trailing slashes
    normalized = path.strip('/')

    if not normalized:
        raise PathValidationError("Path cannot be empty")

    # Check each segment
    segments = normalized.split('/')
    for i, segment in enumerate(segments):
        if not validate_path_segment(segment, allow_wildcards=False):
            # Provide helpful error message
            if segment in RESERVED_WILDCARDS:
                raise PathValidationError(
                    f"Invalid path '{path}': Segment '{segment}' is a reserved wildcard. "
                    f"Reserved wildcards ({', '.join(sorted(RESERVED_WILDCARDS))}) "
                    f"cannot be used in user-created paths."
                )
            elif '{' in segment or '}' in segment:
                raise PathValidationError(
                    f"Invalid path '{path}': Segment '{segment}' contains braces. "
                    f"Braced expressions are not allowed in user-created paths."
                )
            else:
                raise PathValidationError(
                    f"Invalid path '{path}': Segment '{segment}' contains invalid characters. "
                    f"Path segments must contain only alphanumeric characters, dots, hyphens, and underscores."
                )


def validate_capability_path(path: str) -> None:
    """
    Validate a capability path pattern.

    Capability paths can contain reserved wildcards ({self}, {any}, {other})
    in addition to normal slug segments.

    Args:
        path: The capability path pattern to validate

    Raises:
        PathValidationError: If path pattern is invalid

    Examples:
        validate_capability_path("profiles/{self}/")         # ✅ OK
        validate_capability_path("topics/{any}/messages/")   # ✅ OK
        validate_capability_path("auth/users/{self}/roles/") # ✅ OK
        validate_capability_path("files/{custom}/")          # ❌ Unknown wildcard
        validate_capability_path("api/{self.id}")            # ❌ Invalid syntax
        validate_capability_path("users/{}")                 # ❌ Empty braces
    """
    # Normalize
    normalized = path.strip('/')

    if not normalized:
        raise PathValidationError("Capability path cannot be empty")

    # Check each segment
    segments = normalized.split('/')
    for segment in segments:
        # Allow empty segments (from trailing slash)
        if segment == '':
            continue

        if not validate_path_segment(segment, allow_wildcards=True):
            # Check for unknown wildcards
            if '{' in segment and '}' in segment:
                if segment not in RESERVED_WILDCARDS:
                    raise PathValidationError(
                        f"Invalid capability path '{path}': Unknown wildcard '{segment}'. "
                        f"Allowed wildcards are: {', '.join(sorted(RESERVED_WILDCARDS))}"
                    )

            # Invalid characters
            raise PathValidationError(
                f"Invalid capability path '{path}': Segment '{segment}' contains invalid characters. "
                f"Path segments must be either reserved wildcards or contain only "
                f"alphanumeric characters, dots, hyphens, and underscores."
            )


def normalize_path(path: str) -> str:
    """
    Normalize a path by removing leading/trailing slashes.

    Args:
        path: The path to normalize

    Returns:
        Normalized path without leading/trailing slashes
    """
    return path.strip('/')


def is_valid_user_path(path: str) -> bool:
    """
    Check if a path is valid for user-created content.

    Args:
        path: The path to check

    Returns:
        True if valid, False otherwise (does not raise exceptions)
    """
    try:
        validate_user_path(path)
        return True
    except PathValidationError:
        return False


def is_valid_capability_path(path: str) -> bool:
    """
    Check if a path is valid for capability patterns.

    Args:
        path: The capability path pattern to check

    Returns:
        True if valid, False otherwise (does not raise exceptions)
    """
    try:
        validate_capability_path(path)
        return True
    except PathValidationError:
        return False
