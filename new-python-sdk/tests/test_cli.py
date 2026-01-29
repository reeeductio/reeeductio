"""Tests for the reeeductio-admin CLI."""

import json
import os

import pytest
from click.testing import CliRunner

from reeeductio.cli.main import cli

# Admin private key from e2e config (32 bytes of 0x01)
ADMIN_PRIVATE_KEY_HEX = "01" * 32

# Backend URL for e2e tests
E2E_BASE_URL = os.environ.get("E2E_BASE_URL", "http://localhost:8000")


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


class TestSpaceCommands:
    """Tests for space management commands."""

    def test_space_create_text_output(self, runner):
        """Test space create with default text output."""
        result = runner.invoke(cli, ["space", "create"])

        assert result.exit_code == 0
        assert "Space created successfully!" in result.output
        assert "Space ID:" in result.output
        assert "User ID:" in result.output
        assert "Private Key:" in result.output
        assert "Symmetric Root:" in result.output
        assert "IMPORTANT:" in result.output

    def test_space_create_json_output(self, runner):
        """Test space create with JSON output."""
        result = runner.invoke(cli, ["space", "create", "--output-format", "json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "space_id" in data
        assert "user_id" in data
        assert "private_key_hex" in data
        assert "public_key_hex" in data
        assert "symmetric_root_hex" in data
        # Verify formats
        assert data["space_id"].startswith("C")
        assert data["user_id"].startswith("U")
        assert len(data["private_key_hex"]) == 64
        assert len(data["symmetric_root_hex"]) == 64

    def test_space_info_valid_key(self, runner):
        """Test space info with a valid private key."""
        # First generate a key
        gen_result = runner.invoke(cli, ["key", "generate", "--output-format", "json"])
        key_data = json.loads(gen_result.output)
        private_key = key_data["private_key_hex"]

        # Then get info
        result = runner.invoke(cli, ["space", "info", "-k", private_key])

        assert result.exit_code == 0
        assert "Space ID:" in result.output
        assert "User ID:" in result.output
        assert "Tool ID:" in result.output
        # Verify the IDs match what was generated
        assert key_data["space_id"] in result.output
        assert key_data["user_id"] in result.output

    def test_space_info_invalid_key_length(self, runner):
        """Test space info with invalid key length."""
        result = runner.invoke(cli, ["space", "info", "-k", "abc123"])

        assert result.exit_code != 0
        assert "64 hex characters" in result.output

    def test_space_info_invalid_hex(self, runner):
        """Test space info with invalid hex characters."""
        result = runner.invoke(cli, ["space", "info", "-k", "g" * 64])

        assert result.exit_code != 0
        assert "Invalid hex" in result.output

    def test_space_info_missing_key(self, runner):
        """Test space info without providing key."""
        result = runner.invoke(cli, ["space", "info"])

        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()


class TestKeyCommands:
    """Tests for key generation and management commands."""

    def test_key_generate_text_output(self, runner):
        """Test key generate with default text output."""
        result = runner.invoke(cli, ["key", "generate"])

        assert result.exit_code == 0
        assert "Generated new Ed25519 keypair" in result.output
        assert "Private Key:" in result.output
        assert "Public Key:" in result.output
        assert "User ID:" in result.output
        assert "Space ID:" in result.output
        assert "Tool ID:" in result.output

    def test_key_generate_json_output(self, runner):
        """Test key generate with JSON output."""
        result = runner.invoke(cli, ["key", "generate", "--output-format", "json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "private_key_hex" in data
        assert "public_key_hex" in data
        assert "user_id" in data
        assert "space_id" in data
        assert "tool_id" in data
        # Verify formats
        assert len(data["private_key_hex"]) == 64
        assert len(data["public_key_hex"]) == 64
        assert data["user_id"].startswith("U")
        assert data["space_id"].startswith("C")
        assert data["tool_id"].startswith("T")

    def test_key_generate_unique_keys(self, runner):
        """Test that key generate produces unique keys each time."""
        result1 = runner.invoke(cli, ["key", "generate", "--output-format", "json"])
        result2 = runner.invoke(cli, ["key", "generate", "--output-format", "json"])

        data1 = json.loads(result1.output)
        data2 = json.loads(result2.output)

        assert data1["private_key_hex"] != data2["private_key_hex"]
        assert data1["public_key_hex"] != data2["public_key_hex"]

    def test_key_info_space_id(self, runner):
        """Test key info with a Space ID."""
        # Generate a key to get a valid space ID
        gen_result = runner.invoke(cli, ["key", "generate", "--output-format", "json"])
        key_data = json.loads(gen_result.output)

        result = runner.invoke(cli, ["key", "info", key_data["space_id"]])

        assert result.exit_code == 0
        assert "Type: SPACE" in result.output
        assert key_data["space_id"] in result.output

    def test_key_info_user_id(self, runner):
        """Test key info with a User ID."""
        gen_result = runner.invoke(cli, ["key", "generate", "--output-format", "json"])
        key_data = json.loads(gen_result.output)

        result = runner.invoke(cli, ["key", "info", key_data["user_id"]])

        assert result.exit_code == 0
        assert "Type: USER" in result.output

    def test_key_info_tool_id(self, runner):
        """Test key info with a Tool ID."""
        gen_result = runner.invoke(cli, ["key", "generate", "--output-format", "json"])
        key_data = json.loads(gen_result.output)

        result = runner.invoke(cli, ["key", "info", key_data["tool_id"]])

        assert result.exit_code == 0
        assert "Type: TOOL" in result.output

    def test_key_info_invalid_length(self, runner):
        """Test key info with invalid identifier length."""
        result = runner.invoke(cli, ["key", "info", "short"])

        assert result.exit_code != 0
        assert "44 characters" in result.output

    def test_key_info_missing_identifier(self, runner):
        """Test key info without providing identifier."""
        result = runner.invoke(cli, ["key", "info"])

        assert result.exit_code != 0
        assert "Missing argument" in result.output


class TestBlobCommands:
    """Tests for blob management commands."""

    def test_blob_delete_missing_key(self, runner):
        """Test blob delete without providing key."""
        result = runner.invoke(cli, ["blob", "delete", "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"])

        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_blob_delete_invalid_key(self, runner):
        """Test blob delete with invalid key format."""
        result = runner.invoke(
            cli,
            ["blob", "delete", "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "-k", "invalid"],
        )

        assert result.exit_code != 0
        assert "64 hex characters" in result.output


class TestAuthCommands:
    """Tests for authentication commands."""

    def test_auth_test_missing_key(self, runner):
        """Test auth test without providing key."""
        result = runner.invoke(cli, ["auth", "test"])

        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_auth_test_invalid_key(self, runner):
        """Test auth test with invalid key format."""
        result = runner.invoke(cli, ["auth", "test", "-k", "tooshort"])

        assert result.exit_code != 0
        assert "64 hex characters" in result.output


class TestGlobalOptions:
    """Tests for global CLI options."""

    def test_help(self, runner):
        """Test --help option."""
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "Reeeductio admin CLI" in result.output
        assert "space" in result.output
        assert "key" in result.output
        assert "blob" in result.output
        assert "auth" in result.output

    def test_version(self, runner):
        """Test --version option."""
        result = runner.invoke(cli, ["--version"])

        assert result.exit_code == 0
        assert "version" in result.output.lower()

    def test_subcommand_help(self, runner):
        """Test help for subcommands."""
        for cmd in ["space", "key", "blob", "auth"]:
            result = runner.invoke(cli, [cmd, "--help"])
            assert result.exit_code == 0, f"{cmd} --help failed"

    def test_base_url_option(self, runner):
        """Test --base-url option is accepted."""
        result = runner.invoke(cli, ["--base-url", "http://example.com:9000", "space", "create"])

        assert result.exit_code == 0

    def test_output_option(self, runner):
        """Test --output option is accepted."""
        result = runner.invoke(cli, ["-o", "json", "key", "generate"])

        # Note: global -o option doesn't affect subcommand output format
        # Each command has its own --output-format option
        assert result.exit_code == 0


# =============================================================================
# End-to-end tests (require running backend)
# =============================================================================


@pytest.mark.e2e
class TestAuthCommandsE2E:
    """E2E tests for authentication commands."""

    def test_auth_test_success(self, runner):
        """Test successful admin authentication."""
        result = runner.invoke(
            cli,
            [
                "--base-url", E2E_BASE_URL,
                "auth", "test",
                "-k", ADMIN_PRIVATE_KEY_HEX,
            ],
        )

        assert result.exit_code == 0, f"Failed with: {result.output}"
        assert "Authentication successful!" in result.output
        assert "Admin Space ID:" in result.output

    def test_auth_test_invalid_credentials(self, runner):
        """Test authentication with wrong credentials."""
        # Use a random key that's not the admin key
        wrong_key = "ab" * 32

        result = runner.invoke(
            cli,
            [
                "--base-url", E2E_BASE_URL,
                "auth", "test",
                "-k", wrong_key,
            ],
        )

        assert result.exit_code != 0
        assert "Authentication failed" in result.output or "Permission denied" in result.output


@pytest.mark.e2e
class TestBlobCommandsE2E:
    """E2E tests for blob management commands."""

    def test_blob_delete_not_found(self, runner):
        """Test deleting a non-existent blob."""
        # Use a valid-format but non-existent blob ID
        fake_blob_id = "B" + "A" * 43

        result = runner.invoke(
            cli,
            [
                "--base-url", E2E_BASE_URL,
                "blob", "delete", fake_blob_id,
                "-k", ADMIN_PRIVATE_KEY_HEX,
            ],
        )

        assert result.exit_code != 0
        assert "Not found" in result.output

    def test_blob_delete_success(self, runner, fresh_keypair, symmetric_root):
        """Test successful blob deletion via CLI."""
        from reeeductio import Space

        # First, upload a blob using the SDK
        space_id = fresh_keypair.to_space_id()
        with Space(
            space_id=space_id,
            keypair=fresh_keypair,
            symmetric_root=symmetric_root,
            base_url=E2E_BASE_URL,
        ) as space:
            blob_created = space.upload_plaintext_blob(b"test blob data for CLI deletion")
            blob_id = blob_created.blob_id

        # Now delete it via CLI using admin credentials
        result = runner.invoke(
            cli,
            [
                "--base-url", E2E_BASE_URL,
                "blob", "delete", blob_id,
                "-k", ADMIN_PRIVATE_KEY_HEX,
            ],
        )

        assert result.exit_code == 0, f"Failed with: {result.output}"
        assert f"Blob deleted: {blob_id}" in result.output

        # Verify the blob is actually gone
        with Space(
            space_id=space_id,
            keypair=fresh_keypair,
            symmetric_root=symmetric_root,
            base_url=E2E_BASE_URL,
        ) as space:
            from reeeductio import NotFoundError
            with pytest.raises(NotFoundError):
                space.download_plaintext_blob(blob_id)
