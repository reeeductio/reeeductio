"""End-to-end tests for the async AsyncSpace client against a real backend."""

import json
import os
import uuid

import pytest
import pytest_asyncio

from reeeductio import AsyncSpace, Ed25519KeyPair, generate_keypair, NotFoundError

pytestmark = [pytest.mark.e2e, pytest.mark.asyncio]


@pytest_asyncio.fixture
async def space(fresh_keypair, symmetric_root, base_url):
    """Create an AsyncSpace client. Backend auto-creates spaces on first use."""
    space_id = fresh_keypair.to_space_id()
    async with AsyncSpace(
        space_id=space_id,
        keypair=fresh_keypair,
        symmetric_root=symmetric_root,
        base_url=base_url,
    ) as s:
        yield s


class TestAsyncAuthentication:
    async def test_authenticate_returns_token(self, space):
        token = await space.authenticate()
        assert isinstance(token, str)
        assert len(token) > 0

    async def test_auto_authenticate_on_request(self, fresh_keypair, symmetric_root, base_url):
        space_id = fresh_keypair.to_space_id()
        async with AsyncSpace(
            space_id=space_id,
            keypair=fresh_keypair,
            symmetric_root=symmetric_root,
            base_url=base_url,
            auto_authenticate=True,
        ) as s:
            msgs = await s.get_messages("nonexistent-topic")
            assert isinstance(msgs, list)


class TestAsyncPlaintextMessages:
    async def test_post_and_retrieve_message(self, space):
        topic = f"async-topic-{uuid.uuid4().hex[:8]}"
        content = b"async hello world"

        created = await space.post_message(topic, "test.message", content)
        assert created.message_hash is not None
        assert created.server_timestamp > 0

        msgs = await space.get_messages(topic)
        assert any(m.message_hash == created.message_hash for m in msgs)

    async def test_get_messages_empty_topic(self, space):
        msgs = await space.get_messages(f"empty-{uuid.uuid4().hex[:8]}")
        assert msgs == []

    async def test_post_multiple_messages(self, space):
        topic = f"async-multi-{uuid.uuid4().hex[:8]}"
        await space.post_message(topic, "msg", b"first")
        await space.post_message(topic, "msg", b"second")

        msgs = await space.get_messages(topic)
        assert len(msgs) >= 2


class TestAsyncEncryptedMessages:
    async def test_post_encrypted_and_retrieve(self, space):
        from reeeductio.crypto import encrypt_aes_gcm, decrypt_aes_gcm, derive_key
        import base64

        topic = f"async-enc-{uuid.uuid4().hex[:8]}"
        plaintext = b"async secret message"

        topic_key = derive_key(space.message_key, f"topic key | {topic}")
        encrypted = encrypt_aes_gcm(plaintext, topic_key)

        created = await space.post_message(topic, "encrypted.msg", encrypted)
        msgs = await space.get_messages(topic)
        msg = next(m for m in msgs if m.message_hash == created.message_hash)

        encrypted_data = base64.b64decode(msg.data)
        decrypted = decrypt_aes_gcm(encrypted_data, topic_key)
        assert decrypted == plaintext


class TestAsyncPlaintextState:
    async def test_set_and_get_state(self, space):
        path = f"test/async-state/{uuid.uuid4().hex[:8]}"
        await space.set_plaintext_state(path, "async hello")
        result = await space.get_plaintext_state(path)
        assert result == "async hello"

    async def test_overwrite_state(self, space):
        path = f"test/async-state/{uuid.uuid4().hex[:8]}"
        await space.set_plaintext_state(path, "v1")
        await space.set_plaintext_state(path, "v2")
        result = await space.get_plaintext_state(path)
        assert result == "v2"


class TestAsyncEncryptedState:
    async def test_set_and_get_encrypted_state(self, space):
        path = f"test/async-enc-state/{uuid.uuid4().hex[:8]}"
        await space.set_encrypted_state(path, "async secret state")
        result = await space.get_encrypted_state(path)
        assert result == "async secret state"


class TestAsyncStateHistory:
    async def test_state_history(self, space):
        path1 = f"test/async-hist/{uuid.uuid4().hex[:8]}"
        path2 = f"test/async-hist/{uuid.uuid4().hex[:8]}"

        await space.set_plaintext_state(path1, "a")
        await space.set_plaintext_state(path2, "b")
        await space.set_plaintext_state(path1, "c")

        history = await space.get_state_history()
        assert len(history) >= 3


class TestAsyncPlaintextBlobs:
    async def test_upload_and_download(self, space):
        data = b"async blob content"
        created = await space.upload_plaintext_blob(data)
        assert created.blob_id is not None

        downloaded = await space.download_plaintext_blob(created.blob_id)
        assert downloaded == data

    async def test_delete_blob(self, space):
        data = b"async to be deleted"
        created = await space.upload_plaintext_blob(data)
        await space.delete_blob(created.blob_id)

    async def test_upload_large_blob(self, space):
        data = os.urandom(1024 * 100)
        created = await space.upload_plaintext_blob(data)
        downloaded = await space.download_plaintext_blob(created.blob_id)
        assert downloaded == data


class TestAsyncEncryptedBlobs:
    async def test_encrypt_upload_download_decrypt(self, space):
        plaintext = b"async encrypted blob"
        created = await space.encrypt_and_upload_blob(plaintext)
        decrypted = await space.download_and_decrypt_blob(created.blob_id)
        assert decrypted == plaintext

    async def test_encrypted_blob_not_readable_as_plaintext(self, space):
        plaintext = b"async should be encrypted"
        created = await space.encrypt_and_upload_blob(plaintext)
        raw = await space.download_plaintext_blob(created.blob_id)
        assert raw != plaintext


class TestAsyncPlaintextKVData:
    async def test_set_and_get(self, space):
        path = f"test/async-data/{uuid.uuid4().hex[:8]}"
        data = b"async kv data"
        ts = await space.set_plaintext_data(path, data)
        assert ts > 0

        result = await space.get_plaintext_data(path)
        assert result == data

    async def test_overwrite(self, space):
        path = f"test/async-data/{uuid.uuid4().hex[:8]}"
        await space.set_plaintext_data(path, b"v1")
        await space.set_plaintext_data(path, b"v2")
        result = await space.get_plaintext_data(path)
        assert result == b"v2"


class TestAsyncEncryptedKVData:
    async def test_set_and_get_encrypted(self, space):
        path = f"test/async-enc-data/{uuid.uuid4().hex[:8]}"
        data = b"async secret kv"
        ts = await space.set_encrypted_data(path, data)
        assert ts > 0

        result = await space.get_encrypted_data(path)
        assert result == data

    async def test_encrypted_data_not_readable_as_plaintext(self, space):
        path = f"test/async-enc-data/{uuid.uuid4().hex[:8]}"
        data = b"async secret"
        await space.set_encrypted_data(path, data)
        raw = await space.get_plaintext_data(path)
        assert raw != data


class TestAsyncCreateTool:
    async def test_create_tool_stores_entry(self, space):
        """create_tool should store tool data at auth/tools/{tool_id}."""
        keypair = generate_keypair()
        tool_id = keypair.to_tool_id()

        result = await space.create_tool(tool_id, "Async test tool")
        assert result.message_hash is not None
        assert result.message_hash.startswith("M")

        tool_data = await space.get_plaintext_state(f"auth/tools/{tool_id}")
        tool = json.loads(tool_data)
        assert tool["tool_id"] == tool_id
        assert tool["description"] == "Async test tool"

    async def test_create_tool_without_description(self, space):
        """create_tool should work without a description."""
        keypair = generate_keypair()
        tool_id = keypair.to_tool_id()

        result = await space.create_tool(tool_id)
        assert result.message_hash is not None

        tool_data = await space.get_plaintext_state(f"auth/tools/{tool_id}")
        tool = json.loads(tool_data)
        assert tool["tool_id"] == tool_id
        assert "description" not in tool


class TestAsyncCreateInvitation:
    async def test_create_invitation_returns_keypair(self, space):
        """create_invitation should return an Ed25519KeyPair."""
        keypair = await space.create_invitation()
        assert isinstance(keypair, Ed25519KeyPair)
        assert len(keypair.private_key) == 32
        assert len(keypair.public_key) == 32

    async def test_create_invitation_creates_tool_entry(self, space):
        """create_invitation should create a tool entry for the keypair."""
        keypair = await space.create_invitation(description="Async test invitation")
        tool_id = keypair.to_tool_id()

        tool_data = await space.get_plaintext_state(f"auth/tools/{tool_id}")
        tool = json.loads(tool_data)
        assert tool["tool_id"] == tool_id
        assert tool["description"] == "Async test invitation"

    async def test_create_invitation_grants_create_user_capability(self, space):
        """create_invitation should grant the tool permission to create users."""
        keypair = await space.create_invitation()
        tool_id = keypair.to_tool_id()

        cap_data = await space.get_plaintext_state(
            f"auth/tools/{tool_id}/rights/can_create_user"
        )
        cap = json.loads(cap_data)
        assert cap["op"] == "create"
        assert cap["path"] == "state/auth/users/{any}"

    async def test_create_invitation_grants_assign_user_role_capability(self, space):
        """create_invitation should grant the tool permission to assign the user role."""
        keypair = await space.create_invitation()
        tool_id = keypair.to_tool_id()

        cap_data = await space.get_plaintext_state(
            f"auth/tools/{tool_id}/rights/can_grant_user_role"
        )
        cap = json.loads(cap_data)
        assert cap["op"] == "create"
        assert cap["path"] == "state/auth/users/{any}/roles/user"

    async def test_create_multiple_invitations_are_independent(self, space):
        """Each create_invitation call should produce a unique tool."""
        keypair1 = await space.create_invitation()
        keypair2 = await space.create_invitation()

        assert keypair1.to_tool_id() != keypair2.to_tool_id()

        tool1 = json.loads(
            await space.get_plaintext_state(f"auth/tools/{keypair1.to_tool_id()}")
        )
        tool2 = json.loads(
            await space.get_plaintext_state(f"auth/tools/{keypair2.to_tool_id()}")
        )
        assert tool1["tool_id"] == keypair1.to_tool_id()
        assert tool2["tool_id"] == keypair2.to_tool_id()
