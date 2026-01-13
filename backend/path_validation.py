"""
Path validation for Reeeductio authorization system.

Validates user-created paths and capability path patterns to prevent
wildcard injection and ensure consistent path syntax.

Unified Namespace:
- state/{path}      - State paths (auth/users/..., profiles/..., etc.)
- data/{path}       - Data storage paths (key-value store)
- messages/{topic}  - Message topic access
- blobs/{blob_id}   - Blob storage access
"""

import re
from typing import Set, Tuple, Optional


# Path segment pattern: alphanumeric, dot, underscore, hyphen
# Dots allowed for file extensions and versioning (e.g., "photo.jpg", "v1.0")
PATH_SEGMENT_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')

# Reserved wildcards that can only appear in capability patterns
RESERVED_WILDCARDS: Set[str] = {'{self}', '{any}', '{other}', '{...}'}

# Valid resource type prefixes for unified namespace
RESOURCE_TYPES: Set[str] = {'state', 'data', 'topics', 'blobs'}


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
    Validate a user-created path within a specific namespace (state, data, messages).

    User paths must use slug format with no wildcards or special characters.
    These paths do NOT include the resource type prefix - they are the actual
    paths within a namespace (e.g., state path "auth/users/U_xxx", not "state/auth/users/U_xxx").

    The resource type prefix is only used in:
    - Capability patterns (validate_capability_path)
    - Permission checks (check_permission)

    Args:
        path: The path to validate (without resource type prefix)

    Raises:
        PathValidationError: If path is invalid

    Examples:
        validate_user_path("profiles/alice")           # ✅ OK - state path
        validate_user_path("auth/users/U_xxx")         # ✅ OK - state path
        validate_user_path("files/photo.jpg")          # ✅ OK - data path
        validate_user_path("api/v1.0/users")           # ✅ OK - state path
        validate_user_path("profiles/{self}")          # ❌ Raises error (wildcards not allowed)
        validate_user_path("topics/{any}/messages")    # ❌ Raises error (wildcards not allowed)
        validate_user_path("files/my file.txt")        # ❌ Raises error (spaces not allowed)
        validate_user_path("state/auth/users/U_xxx")   # ❌ Would work but shouldn't include prefix
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
    Validate a capability path pattern with unified namespace prefix.

    Capability paths MUST start with a resource type prefix (state/, data/, topics/, blobs/)
    OR use a top-level wildcard ({any} or {...}) to match across all resource types.

    Args:
        path: The capability path pattern to validate

    Raises:
        PathValidationError: If path pattern is invalid

    Examples:
        validate_capability_path("state/profiles/{self}/")         # ✅ OK
        validate_capability_path("topics/{any}")                   # ✅ OK
        validate_capability_path("{...}")                          # ✅ OK - matches all resources
        validate_capability_path("{any}")                          # ✅ OK - matches any resource type
        validate_capability_path("state/auth/users/{self}/roles/") # ✅ OK
        validate_capability_path("blobs/{...}")                    # ✅ OK
        validate_capability_path("profiles/{self}/")               # ❌ Missing resource type prefix
        validate_capability_path("files/{custom}/")                # ❌ Unknown resource type
        validate_capability_path("state/api/{self.id}")            # ❌ Invalid wildcard syntax
    """

    print(f"Validating capability path: {path}")

    # Normalize
    normalized = path.strip('/')

    if not normalized:
        print("Capability path is empty")
        raise PathValidationError("Capability path cannot be empty")

    # Special case: top-level wildcards {any} and {...} are allowed
    # These match across all resource types
    if normalized in ('{any}', '{...}'):
        print(f"Top-level wildcard allowed: {normalized}")
        return

    # Parse and validate resource type prefix
    try:
        resource_type, subpath = parse_resource_path(normalized)
    except PathValidationError as e:
        print(f"Invalid resource path: {e}")
        raise

    print(f"Resource type: {resource_type}, Subpath: {subpath}")

    # For some resource types, subpath can be empty (e.g., "messages" to grant access to all topics)
    # But we still validate the segments if present
    if subpath:
        # Check each segment in the subpath
        segments = subpath.split('/')
        print("Found subpath segments =", segments)
        for segment in segments:
            # Allow empty segments (from trailing slash)
            if segment == '':
                continue

            if not validate_path_segment(segment, allow_wildcards=True):
                # Check for unknown wildcards
                if '{' in segment and '}' in segment:
                    print(f"Found wildcard: {segment}")
                    if segment not in RESERVED_WILDCARDS:
                        print(f"Unknown wildcard: {segment}")
                        raise PathValidationError(
                            f"Invalid capability path '{path}': Unknown wildcard '{segment}'. "
                            f"Allowed wildcards are: {', '.join(sorted(RESERVED_WILDCARDS))}"
                        )

                # Invalid characters
                print(f"Invalid segment: {segment}")
                raise PathValidationError(
                    f"Invalid capability path '{path}': Segment '{segment}' contains invalid characters. "
                    f"Path segments must be either reserved wildcards or contain only "
                    f"alphanumeric characters, dots, hyphens, and underscores."
                )


def parse_resource_path(path: str) -> Tuple[str, str]:
    """
    Parse a prefixed resource path into resource type and subpath.

    Args:
        path: Prefixed resource path (e.g., "state/auth/users/U_xxx")

    Returns:
        Tuple of (resource_type, subpath)

    Raises:
        PathValidationError: If path doesn't have a valid resource type prefix

    Examples:
        parse_resource_path("state/auth/users/U_xxx") -> ("state", "auth/users/U_xxx")
        parse_resource_path("topics/general") -> ("topics", "general")
        parse_resource_path("blobs/B_xxx") -> ("blobs", "B_xxx")
    """
    normalized = path.strip('/')

    if not normalized:
        raise PathValidationError("Resource path cannot be empty")

    parts = normalized.split('/', 1)
    resource_type = parts[0]

    if resource_type not in RESOURCE_TYPES:
        raise PathValidationError(
            f"Invalid resource type '{resource_type}'. "
            f"Must be one of: {', '.join(sorted(RESOURCE_TYPES))}"
        )

    # Subpath is everything after the resource type (may be empty for some resources)
    subpath = parts[1] if len(parts) > 1 else ""

    return resource_type, subpath


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
