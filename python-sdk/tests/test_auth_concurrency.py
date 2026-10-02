"""
Tests that concurrent authentication does not invalidate itself.

The server keeps exactly one outstanding challenge per member
(`backend/space.py`: `self.challenges[member_id]`), and consumes it on a
successful verify. Two overlapping handshakes therefore clobber each other:
the loser's `/auth/verify` comes back 401, indistinguishable from genuinely
bad credentials. The fake server below reproduces that single-slot behaviour
exactly, so these tests fail against an unsynchronized session.
"""

import asyncio
import threading
import time
from datetime import datetime, timezone

import httpx
import pytest

from reeeductio.auth import AsyncAuthSession, AuthSession
from reeeductio.client import AdminClient, AsyncAdminClient
from reeeductio.crypto import generate_keypair
from reeeductio.exceptions import AuthenticationError

TOKEN_TTL_MS = 3_600_000


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


class FakeServer:
    """Single-challenge-slot auth server, mirroring the real backend."""

    def __init__(self, token_ttl_ms: int = TOKEN_TTL_MS):
        self.token_ttl_ms = token_ttl_ms
        self.challenge: str | None = None
        self.challenge_calls = 0
        self.verify_calls = 0
        self.refresh_calls = 0
        self.failed_verifies = 0
        self._counter = 0
        self.fail_next_challenge = False
        self.fail_all_challenges = False

    def _response(self, url: str, status: int, payload=None, text: str = "") -> httpx.Response:
        request = httpx.Request("POST", url)
        if payload is not None:
            return httpx.Response(status, json=payload, request=request)
        return httpx.Response(status, text=text, request=request)

    def _token(self, url: str) -> httpx.Response:
        self._counter += 1
        return self._response(
            url,
            200,
            {"token": f"token-{self._counter}", "expires_at": _now_ms() + self.token_ttl_ms},
        )

    def handle(self, url: str, json_body: dict | None) -> httpx.Response:
        if url.endswith("/auth/challenge"):
            self.challenge_calls += 1
            if self.fail_all_challenges or self.fail_next_challenge:
                self.fail_next_challenge = False
                return self._response(url, 401, text="unauthorized")
            self._counter += 1
            self.challenge = f"challenge-{self._counter}"
            return self._response(
                url, 200, {"challenge": self.challenge, "expires_at": _now_ms() + 300_000}
            )

        if url.endswith("/auth/verify"):
            self.verify_calls += 1
            offered = (json_body or {}).get("challenge")
            # The heart of the race: a challenge that was overwritten (or
            # already consumed) by a concurrent flow no longer matches.
            if self.challenge is None or offered != self.challenge:
                self.failed_verifies += 1
                return self._response(url, 401, text="challenge not found")
            self.challenge = None
            return self._token(url)

        if url.endswith("/auth/refresh"):
            self.refresh_calls += 1
            return self._token(url)

        return self._response(url, 404, text="not found")


class FakeAsyncClient:
    """Stands in for httpx.AsyncClient, yielding to the loop on every post."""

    def __init__(self, server: FakeServer, **kwargs):
        self._server = server

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def post(self, url: str, json=None, **kwargs) -> httpx.Response:
        # Yield twice so an unsynchronized implementation reliably interleaves
        # between requesting a challenge and verifying it.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return self._server.handle(url, json)


class FakeSyncClient:
    """
    Stands in for httpx.Client.

    Challenge requests take a beat, which is what makes the race observable:
    an instant fake server plus the GIL lets each thread finish its handshake
    before the next one starts, hiding the bug entirely.
    """

    CHALLENGE_DELAY = 0.05

    def __init__(self, server: FakeServer, **kwargs):
        self._server = server

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def post(self, url: str, json=None, **kwargs) -> httpx.Response:
        if url.endswith("/auth/challenge"):
            time.sleep(self.CHALLENGE_DELAY)
        return self._server.handle(url, json)


@pytest.fixture
def server() -> FakeServer:
    return FakeServer()


@pytest.fixture
def patch_sync(monkeypatch, server):
    monkeypatch.setattr(httpx, "Client", lambda **kw: FakeSyncClient(server, **kw))
    return server


@pytest.fixture
def patch_async(monkeypatch, server):
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: FakeAsyncClient(server, **kw))
    return server


def _session(**kwargs) -> AsyncAuthSession:
    keypair = generate_keypair()
    return AsyncAuthSession(
        space_id="S" + "A" * 43,
        public_key_typed=keypair.to_user_id(),
        private_key=keypair.private_key,
        **kwargs,
    )


def _sync_session() -> AuthSession:
    keypair = generate_keypair()
    return AuthSession(
        space_id="S" + "A" * 43,
        public_key_typed=keypair.to_user_id(),
        private_key=keypair.private_key,
    )


class TestAsyncAuthSessionConcurrency:
    @pytest.mark.asyncio
    async def test_concurrent_ensure_authenticated_issues_one_challenge(self, patch_async):
        session = _session()

        tokens = await asyncio.gather(*(session.ensure_authenticated() for _ in range(5)))

        assert patch_async.challenge_calls == 1
        assert patch_async.verify_calls == 1
        assert patch_async.failed_verifies == 0
        assert len(set(tokens)) == 1
        assert tokens[0] == session.token

    @pytest.mark.asyncio
    async def test_concurrent_authenticate_calls_all_succeed(self, patch_async):
        """Explicit authenticate() still runs a full flow, but serialized."""
        session = _session()

        tokens = await asyncio.gather(*(session.authenticate() for _ in range(3)))

        assert patch_async.challenge_calls == 3
        assert patch_async.failed_verifies == 0
        assert len(set(tokens)) == 3
        assert session.token == tokens[-1]

    @pytest.mark.asyncio
    async def test_concurrent_refresh_happens_once(self, patch_async):
        # Authenticate with a token that is already inside the 60s buffer.
        patch_async.token_ttl_ms = 30_000
        session = _session()
        await session.authenticate()
        assert not session.is_authenticated

        patch_async.token_ttl_ms = TOKEN_TTL_MS
        tokens = await asyncio.gather(*(session.ensure_authenticated() for _ in range(5)))

        assert patch_async.refresh_calls == 1
        assert patch_async.challenge_calls == 1  # only the initial authenticate
        assert len(set(tokens)) == 1

    @pytest.mark.asyncio
    async def test_failed_attempt_does_not_poison_session(self, patch_async):
        session = _session()
        patch_async.fail_next_challenge = True

        with pytest.raises(AuthenticationError):
            await session.authenticate()

        # The lock must be released, and no failure cached and replayed.
        token = await session.authenticate()
        assert token == session.token

    @pytest.mark.asyncio
    async def test_concurrent_failures_all_raise_and_release_lock(self, patch_async):
        session = _session()

        patch_async.fail_all_challenges = True
        results = await asyncio.gather(
            session.authenticate(), session.authenticate(), return_exceptions=True
        )
        assert all(isinstance(r, AuthenticationError) for r in results)

        # Both failures released the lock, so the session still works.
        patch_async.fail_all_challenges = False
        assert await session.ensure_authenticated() == session.token

    @pytest.mark.asyncio
    async def test_lock_is_created_lazily(self):
        """A session built outside a running loop must still work."""
        session = _session()
        assert session._lock is None
        assert session._get_lock() is session._get_lock()


class TestAuthSessionThreadSafety:
    def test_concurrent_ensure_authenticated_issues_one_challenge(self, patch_sync):
        threads = 4
        server = patch_sync
        session = _sync_session()

        results: list[str] = []
        errors: list[BaseException] = []
        start = threading.Barrier(threads)

        def worker():
            try:
                start.wait(timeout=5)
                results.append(session.ensure_authenticated())
            except BaseException as e:  # noqa: BLE001 - recorded and re-checked
                errors.append(e)

        workers = [threading.Thread(target=worker) for _ in range(threads)]
        for t in workers:
            t.start()
        for t in workers:
            t.join(timeout=10)

        assert errors == []
        assert server.challenge_calls == 1
        assert server.verify_calls == 1
        assert server.failed_verifies == 0
        assert len(set(results)) == 1

    def test_concurrent_authenticate_calls_are_serialized(self, patch_sync):
        threads = 4
        server = patch_sync
        session = _sync_session()

        results: list[str] = []
        errors: list[BaseException] = []
        start = threading.Barrier(threads)

        def worker():
            try:
                start.wait(timeout=5)
                results.append(session.authenticate())
            except BaseException as e:  # noqa: BLE001 - recorded and re-checked
                errors.append(e)

        workers = [threading.Thread(target=worker) for _ in range(threads)]
        for t in workers:
            t.start()
        for t in workers:
            t.join(timeout=10)

        # With the lock held, each handshake completes before the next starts,
        # so every verify sees its own challenge.
        assert errors == []
        assert server.challenge_calls == threads
        assert server.failed_verifies == 0
        assert len(set(results)) == threads


class TestAdminClientConcurrency:
    @pytest.mark.asyncio
    async def test_async_admin_authenticates_once(self, patch_async):
        client = AsyncAdminClient(keypair=generate_keypair())

        tokens = await asyncio.gather(*(client._ensure_authenticated() for _ in range(5)))

        assert patch_async.challenge_calls == 1
        assert patch_async.failed_verifies == 0
        assert len(set(tokens)) == 1

    def test_sync_admin_authenticates_once(self, patch_sync):
        server = patch_sync
        client = AdminClient(keypair=generate_keypair())

        results: list[str] = []
        errors: list[BaseException] = []
        start = threading.Barrier(4)

        def worker():
            try:
                start.wait(timeout=5)
                results.append(client._ensure_authenticated())
            except BaseException as e:  # noqa: BLE001 - recorded and re-checked
                errors.append(e)

        workers = [threading.Thread(target=worker) for _ in range(4)]
        for t in workers:
            t.start()
        for t in workers:
            t.join(timeout=10)

        assert errors == []
        assert server.challenge_calls == 1
        assert server.failed_verifies == 0
        assert len(set(results)) == 1
