"""Shared fixtures for e2e tests."""

import os
import subprocess
import time

import httpx
import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from reeeductio.crypto import Ed25519KeyPair, generate_keypair

# Backend URL for e2e tests (overridable via env var)
E2E_BASE_URL = os.environ.get("E2E_BASE_URL", "http://localhost:8000")

# Path to docker-compose file (relative to this repo)
_COMPOSE_FILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "backend", "docker-compose.e2e.yml"
)

# Admin credentials from backend/config.e2e.yaml
# Private key: 32 bytes of 0x01
ADMIN_PRIVATE_KEY = b"\x01" * 32
ADMIN_SPACE_ID = "SIqI4910CfGV_VLbLTy6XXLKZwm_HZQSG_N0iAG0D29c"


def _keypair_from_private(private_bytes: bytes) -> Ed25519KeyPair:
    """Construct an Ed25519KeyPair from a raw 32-byte private key."""
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return Ed25519KeyPair(private_key=private_bytes, public_key=public_bytes)


def _health_check(timeout: float = 2.0) -> bool:
    """Check if the e2e backend is reachable."""
    try:
        r = httpx.get(f"{E2E_BASE_URL}/health", timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


def _wait_for_backend(max_wait: int = 120, poll_interval: float = 2.0) -> bool:
    """Poll the health endpoint until the backend is ready or timeout."""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        if _health_check():
            return True
        time.sleep(poll_interval)
    return False


@pytest.fixture(scope="session", autouse=True)
def _e2e_backend(request):
    """Start the docker-compose backend before e2e tests, stop it after.

    Only acts when at least one e2e-marked test is collected.
    If the backend is already running, it is left alone (not stopped afterwards).
    """
    has_e2e = any(item.get_closest_marker("e2e") for item in request.session.items)
    if not has_e2e:
        yield
        return

    already_running = _health_check()
    if already_running:
        yield
        return

    compose_file = os.path.realpath(_COMPOSE_FILE)
    if not os.path.isfile(compose_file):
        pytest.skip(f"docker-compose file not found: {compose_file}")

    subprocess.run(
        ["docker", "compose", "-f", compose_file, "up", "-d", "--wait"],
        check=True,
        capture_output=True,
    )

    if not _wait_for_backend():
        logs = subprocess.run(
            ["docker", "compose", "-f", compose_file, "logs", "--tail=50"],
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["docker", "compose", "-f", compose_file, "down", "-v"],
            capture_output=True,
        )
        pytest.fail(
            f"Backend did not become healthy within timeout.\n{logs.stdout}\n{logs.stderr}"
        )

    yield

    subprocess.run(
        ["docker", "compose", "-f", compose_file, "down", "-v"],
        capture_output=True,
    )


@pytest.fixture(autouse=True)
def _skip_without_backend(request, _e2e_backend):
    """Auto-skip e2e tests when backend is not available."""
    if request.node.get_closest_marker("e2e") and not _health_check():
        pytest.skip("e2e backend not running")


@pytest.fixture
def admin_keypair() -> Ed25519KeyPair:
    """Admin keypair from e2e config (properly derived from private key)."""
    return _keypair_from_private(ADMIN_PRIVATE_KEY)


@pytest.fixture
def fresh_keypair() -> Ed25519KeyPair:
    """Generate a fresh random keypair for test isolation."""
    return generate_keypair()


@pytest.fixture
def symmetric_root() -> bytes:
    """Generate a fresh random symmetric root key."""
    return os.urandom(32)


@pytest.fixture
def user_symmetric_key() -> bytes:
    """Generate a fresh random user-private symmetric key."""
    return os.urandom(32)


@pytest.fixture
def space_id(fresh_keypair: Ed25519KeyPair) -> str:
    """Space ID derived from the fresh keypair."""
    return fresh_keypair.to_space_id()


@pytest.fixture
def base_url() -> str:
    """Backend base URL."""
    return E2E_BASE_URL


# Admin symmetric root (consistent across session for the admin space)
ADMIN_SYMMETRIC_ROOT = b"\x02" * 32


@pytest.fixture(scope="session")
def admin_symmetric_root() -> bytes:
    """Consistent symmetric root for admin space operations."""
    return ADMIN_SYMMETRIC_ROOT


@pytest.fixture(scope="session")
def cli_created_space(_e2e_backend) -> dict:
    """Create a space via CLI once per session and cache the credentials.

    Returns a dict with: space_id, private_key_hex, public_key_hex, symmetric_root_hex
    """
    import json
    from click.testing import CliRunner
    from reeeductio.cli.main import cli

    runner = CliRunner()
    admin_keypair = _keypair_from_private(ADMIN_PRIVATE_KEY)

    result = runner.invoke(
        cli,
        [
            "--base-url", E2E_BASE_URL,
            "space", "create",
            "-k", admin_keypair.private_key.hex(),
            "-s", ADMIN_SYMMETRIC_ROOT.hex(),
            "--output-format", "json",
        ],
    )

    if result.exit_code != 0:
        pytest.fail(f"Failed to create space via CLI: {result.output}")

    return json.loads(result.output)
