"""
Tests for path validation
"""

import pytest
from path_validation import (
    validate_user_path,
    validate_capability_path,
    validate_path_segment,
    normalize_path,
    is_valid_user_path,
    is_valid_capability_path,
    PathValidationError,
    RESERVED_WILDCARDS,
)


class TestPathSegmentValidation:
    """Test individual path segment validation"""

    def test_valid_segments(self):
        """Test valid path segments"""
        valid_segments = [
            "alice",
            "user123",
            "my-topic",
            "my_file",
            "file.txt",
            "v1.0",
            "2024-12-31",
            "U_abc123",
            "admin",
        ]
        for segment in valid_segments:
            assert validate_path_segment(segment, allow_wildcards=False), \
                f"Expected '{segment}' to be valid"

    def test_invalid_segments_without_wildcards(self):
        """Test invalid segments when wildcards not allowed"""
        invalid_segments = [
            "{self}",       # Reserved wildcard
            "{any}",        # Reserved wildcard
            "{other}",      # Reserved wildcard
            "{custom}",     # Unknown wildcard
            "my file",      # Space
            "user@email",   # Special char
            "path/sub",     # Slash
            "test{var}",    # Partial wildcard
            "",             # Empty
        ]
        for segment in invalid_segments:
            assert not validate_path_segment(segment, allow_wildcards=False), \
                f"Expected '{segment}' to be invalid"

    def test_wildcards_when_allowed(self):
        """Test reserved wildcards are valid when allowed"""
        for wildcard in RESERVED_WILDCARDS:
            assert validate_path_segment(wildcard, allow_wildcards=True), \
                f"Expected '{wildcard}' to be valid when wildcards allowed"

    def test_unknown_wildcards_always_invalid(self):
        """Test unknown wildcards are invalid even when wildcards allowed"""
        unknown_wildcards = ["{custom}", "{id}", "{foo}"]
        for wildcard in unknown_wildcards:
            assert not validate_path_segment(wildcard, allow_wildcards=True), \
                f"Expected '{wildcard}' to be invalid"


class TestUserPathValidation:
    """Test user-created path validation"""

    def test_valid_user_paths(self):
        """Test valid user paths"""
        valid_paths = [
            "profiles/alice",
            "topics/general/messages",
            "files/photo.jpg",
            "api/v1.0/users",
            "data/2024-12-31",
            "auth/users/U_abc123",
            "settings/theme",
            "a/b/c/d/e/f",  # Deeply nested
        ]
        for path in valid_paths:
            validate_user_path(path)  # Should not raise

    def test_valid_user_paths_with_leading_trailing_slash(self):
        """Test paths are normalized (leading/trailing slashes removed)"""
        paths_with_slashes = [
            "/profiles/alice",
            "profiles/alice/",
            "/profiles/alice/",
        ]
        for path in paths_with_slashes:
            validate_user_path(path)  # Should not raise

    def test_invalid_user_paths_with_wildcards(self):
        """Test user paths cannot contain reserved wildcards"""
        invalid_paths = [
            "profiles/{self}",
            "topics/{any}/messages",
            "auth/users/{other}/roles",
            "data/{self}/{any}",
        ]
        for path in invalid_paths:
            with pytest.raises(PathValidationError) as exc_info:
                validate_user_path(path)
            assert "reserved wildcard" in str(exc_info.value).lower()

    def test_invalid_user_paths_with_braces(self):
        """Test user paths cannot contain any braced expressions"""
        invalid_paths = [
            "users/{custom}",
            "data/{id}",
            "files/{foo}/bar",
        ]
        for path in invalid_paths:
            with pytest.raises(PathValidationError) as exc_info:
                validate_user_path(path)
            assert "braces" in str(exc_info.value).lower()

    def test_invalid_user_paths_with_special_chars(self):
        """Test user paths cannot contain special characters"""
        invalid_paths = [
            "my file",          # Space
            "user@email/data",  # @
            "test/path?query",  # ?
            "data#anchor",      # #
        ]
        for path in invalid_paths:
            with pytest.raises(PathValidationError) as exc_info:
                validate_user_path(path)
            assert "invalid characters" in str(exc_info.value).lower()

    def test_dots_allowed_in_user_paths(self):
        """Test that dots and dot-only segments are allowed in user paths"""
        # These are NOT Unix filesystem paths, so . and .. are just valid segment names
        valid_paths = [
            "path/../etc",      # .. is a valid segment name
            "data/./file",      # . is a valid segment name
            "files/...",        # Multiple dots
            "config/..hidden",  # Starts with dots
        ]
        for path in valid_paths:
            validate_user_path(path)  # Should not raise

    def test_empty_path_invalid(self):
        """Test empty paths are invalid"""
        with pytest.raises(PathValidationError) as exc_info:
            validate_user_path("")
        assert "empty" in str(exc_info.value).lower()

        with pytest.raises(PathValidationError) as exc_info:
            validate_user_path("/")
        assert "empty" in str(exc_info.value).lower()


class TestCapabilityPathValidation:
    """Test capability path pattern validation"""

    def test_valid_capability_paths(self):
        """Test valid capability paths with wildcards"""
        valid_paths = [
            "state/profiles/{self}/",
            "topics/{any}/messages/",
            "state/auth/users/{self}/roles/",
            "topics/{self}/{any}/",
            "state/auth/users/{other}/banned",
            "data/{any}/public/",
            "data/files/{self}/{any}/{any}",
            "blobs/{any}"
        ]
        for path in valid_paths:
            validate_capability_path(path)  # Should not raise

    def test_valid_capability_paths_without_wildcards(self):
        """Test capability paths can be literal (no wildcards)"""
        valid_paths = [
            "state/auth/roles/admin",
            "data/settings/global",
            "topics/general/messages",
        ]
        for path in valid_paths:
            validate_capability_path(path)  # Should not raise

    def test_invalid_capability_paths_unknown_wildcards(self):
        """Test capability paths cannot use unknown wildcards"""
        invalid_paths = [
            "state/users/{custom}",
            "data/{id}",
            "state/api/{version}/users",
            "data/files/{self.id}",
        ]
        for path in invalid_paths:
            with pytest.raises(PathValidationError) as exc_info:
                validate_capability_path(path)
            assert "unknown wildcard" in str(exc_info.value).lower()

    def test_invalid_capability_paths_special_chars(self):
        """Test capability paths cannot contain special characters"""
        invalid_paths = [
            "state/my path/{self}",       # Space
            "data/user@{self}/data",     # @ (caught as unknown wildcard)
            "state/path?query/{any}",     # ? (caught as unknown wildcard)
        ]
        for path in invalid_paths:
            with pytest.raises(PathValidationError) as exc_info:
                validate_capability_path(path)
            # May be caught as either "unknown wildcard" or "invalid characters"
            error_msg = str(exc_info.value).lower()
            assert "unknown wildcard" in error_msg or "invalid characters" in error_msg

    def test_empty_capability_path_invalid(self):
        """Test empty capability paths are invalid"""
        with pytest.raises(PathValidationError) as exc_info:
            validate_capability_path("")
        assert "empty" in str(exc_info.value).lower()


class TestHelperFunctions:
    """Test helper functions"""

    def test_normalize_path(self):
        """Test path normalization"""
        assert normalize_path("profiles/alice") == "profiles/alice"
        assert normalize_path("/profiles/alice") == "profiles/alice"
        assert normalize_path("profiles/alice/") == "profiles/alice"
        assert normalize_path("/profiles/alice/") == "profiles/alice"
        assert normalize_path("///profiles/alice///") == "profiles/alice"

    def test_is_valid_user_path(self):
        """Test boolean user path check"""
        assert is_valid_user_path("profiles/alice") is True
        assert is_valid_user_path("profiles/{self}") is False
        assert is_valid_user_path("my file") is False
        assert is_valid_user_path("") is False

    def test_is_valid_capability_path(self):
        """Test boolean capability path check"""
        assert is_valid_capability_path("data/profiles/{self}/") is True
        assert is_valid_capability_path("topics/{any}/messages/") is True
        assert is_valid_capability_path("users/{custom}") is False
        assert is_valid_capability_path("my path/{self}") is False
        assert is_valid_capability_path("") is False


class TestRealWorldExamples:
    """Test real-world path examples from the codebase"""

    def test_auth_paths(self):
        """Test authentication and authorization paths"""
        # User paths - literal IDs
        assert is_valid_user_path("state/auth/users/U_abc123")
        assert is_valid_user_path("state/auth/users/U_abc123/rights/cap_001")
        assert is_valid_user_path("state/auth/users/U_abc123/roles/admin")
        assert is_valid_user_path("state/auth/tools/T_join_key/rights/cap_002")

        # Capability paths - with wildcards
        assert is_valid_capability_path("state/auth/users/{any}/rights/")
        assert is_valid_capability_path("state/auth/users/{self}/roles/")
        assert is_valid_capability_path("state/auth/users/{other}/banned")
        assert is_valid_capability_path("state/auth/tools/{any}/")

    def test_message_paths(self):
        """Test message and topic paths"""
        # User paths
        assert is_valid_user_path("topics/general/messages/msg_001")
        assert is_valid_user_path("topics/random/messages/msg_002")

        # Capability paths
        assert is_valid_capability_path("topics/{any}/messages/")
        assert is_valid_capability_path("topics/general/messages/")

    def test_profile_paths(self):
        """Test profile and user data paths"""
        # User paths
        assert is_valid_user_path("profiles/U_alice/avatar")
        assert is_valid_user_path("profiles/U_alice/settings/theme")

        # Capability paths
        assert is_valid_capability_path("data/profiles/{self}/")
        assert is_valid_capability_path("data/profiles/{self}/settings/")
        assert is_valid_capability_path("data/profiles/{any}/public/")
