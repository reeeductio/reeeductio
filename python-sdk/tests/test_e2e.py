"""End-to-end tests for the sync Space client against a real backend."""

import os
import uuid

import pytest

from reeeductio import Space, Ed25519KeyPair, generate_keypair, NotFoundError

pytestmark = pytest.mark.e2e


@pytest.fixture
def space(fresh_keypair, symmetric_root, base_url):
    """Create a Space client. Backend auto-creates spaces on first use."""
    space_id = fresh_keypair.to_space_id()
    with Space(
        space_id=space_id,
        keypair=fresh_keypair,
        symmetric_root=symmetric_root,
        base_url=base_url,
    ) as s:
        yield s


class TestAuthentication:
    def test_authenticate_returns_token(self, space):
        token = space.authenticate()
        assert isinstance(token, str)
        assert len(token) > 0

    def test_auto_authenticate_on_request(self, fresh_keypair, symmetric_root, base_url):
        """Space with auto_authenticate=True should auth transparently."""
        space_id = fresh_keypair.to_space_id()
        with Space(
            space_id=space_id,
            keypair=fresh_keypair,
            symmetric_root=symmetric_root,
            base_url=base_url,
            auto_authenticate=True,
        ) as s:
            # This triggers auto-auth internally
            msgs = s.get_messages("nonexistent-topic")
            assert isinstance(msgs, list)


class TestPlaintextMessages:
    def test_post_and_retrieve_message(self, space):
        topic = f"test-topic-{uuid.uuid4().hex[:8]}"
        content = b"hello world"

        created = space.post_message(topic, "test.message", content)
        assert created.message_hash is not None
        assert created.server_timestamp > 0

        msg = space.get_message(topic, created.message_hash)
        assert msg.message_hash == created.message_hash
        assert msg.type == "test.message"

    def test_get_messages_list(self, space):
        topic = f"test-topic-{uuid.uuid4().hex[:8]}"

        space.post_message(topic, "msg", b"first")
        space.post_message(topic, "msg", b"second")

        msgs = space.get_messages(topic)
        assert len(msgs) >= 2

    def test_get_messages_empty_topic(self, space):
        msgs = space.get_messages(f"empty-{uuid.uuid4().hex[:8]}")
        assert msgs == []

    def test_get_message_not_found(self, space):
        topic = f"test-topic-{uuid.uuid4().hex[:8]}"
        # Post one message so the topic exists
        space.post_message(topic, "msg", b"data")
        with pytest.raises(NotFoundError):
            space.get_message(topic, "M" + "A" * 43)


class TestEncryptedMessages:
    def test_post_encrypted_and_retrieve(self, space):
        """Post an encrypted message and verify we can read it back."""
        from reeeductio.crypto import encrypt_aes_gcm, decrypt_aes_gcm, derive_key
        import base64

        topic = f"enc-topic-{uuid.uuid4().hex[:8]}"
        plaintext = b"secret message content"

        # Derive a topic key the same way the SDK would
        topic_key = derive_key(space.message_key, f"topic key | {topic}")
        encrypted = encrypt_aes_gcm(plaintext, topic_key)

        created = space.post_message(topic, "encrypted.msg", encrypted)
        assert created.message_hash is not None

        msg = space.get_message(topic, created.message_hash)
        # Decode the data from base64 and decrypt
        encrypted_data = base64.b64decode(msg.data)
        decrypted = decrypt_aes_gcm(encrypted_data, topic_key)
        assert decrypted == plaintext


class TestPlaintextState:
    def test_set_and_get_state(self, space):
        path = f"test/state/{uuid.uuid4().hex[:8]}"
        space.set_plaintext_state(path, "hello state")
        result = space.get_plaintext_state(path)
        assert result == "hello state"

    def test_overwrite_state(self, space):
        path = f"test/state/{uuid.uuid4().hex[:8]}"
        space.set_plaintext_state(path, "v1")
        space.set_plaintext_state(path, "v2")
        result = space.get_plaintext_state(path)
        assert result == "v2"


class TestEncryptedState:
    def test_set_and_get_encrypted_state(self, space):
        path = f"test/enc-state/{uuid.uuid4().hex[:8]}"
        space.set_encrypted_state(path, "secret state value")
        result = space.get_encrypted_state(path)
        assert result == "secret state value"

    def test_encrypted_state_overwrite(self, space):
        path = f"test/enc-state/{uuid.uuid4().hex[:8]}"
        space.set_encrypted_state(path, "old secret")
        space.set_encrypted_state(path, "new secret")
        result = space.get_encrypted_state(path)
        assert result == "new secret"


class TestStateHistory:
    def test_state_history(self, space):
        path1 = f"test/hist/{uuid.uuid4().hex[:8]}"
        path2 = f"test/hist/{uuid.uuid4().hex[:8]}"

        space.set_plaintext_state(path1, "a")
        space.set_plaintext_state(path2, "b")
        space.set_plaintext_state(path1, "c")

        history = space.get_state_history()
        assert len(history) >= 3


class TestPlaintextBlobs:
    def test_upload_and_download(self, space):
        data = b"blob content here"
        created = space.upload_plaintext_blob(data)
        assert created.blob_id is not None

        downloaded = space.download_plaintext_blob(created.blob_id)
        assert downloaded == data

    def test_delete_blob(self, space):
        data = b"to be deleted"
        created = space.upload_plaintext_blob(data)
        space.delete_blob(created.blob_id)

    def test_upload_large_blob(self, space):
        data = os.urandom(1024 * 100)  # 100 KB
        created = space.upload_plaintext_blob(data)
        downloaded = space.download_plaintext_blob(created.blob_id)
        assert downloaded == data


class TestEncryptedBlobs:
    def test_encrypt_upload_download_decrypt(self, space):
        plaintext = b"encrypted blob content"
        created = space.encrypt_and_upload_blob(plaintext)
        assert created.blob_id is not None

        decrypted = space.download_and_decrypt_blob(created.blob_id)
        assert decrypted == plaintext

    def test_encrypted_blob_not_readable_as_plaintext(self, space):
        """Downloading encrypted blob as plaintext should NOT match original."""
        plaintext = b"this should be encrypted"
        created = space.encrypt_and_upload_blob(plaintext)
        raw = space.download_plaintext_blob(created.blob_id)
        assert raw != plaintext


class TestPlaintextKVData:
    def test_set_and_get(self, space):
        path = f"test/data/{uuid.uuid4().hex[:8]}"
        data = b"kv data value"
        ts = space.set_plaintext_data(path, data)
        assert ts > 0

        result = space.get_plaintext_data(path)
        assert result == data

    def test_overwrite(self, space):
        path = f"test/data/{uuid.uuid4().hex[:8]}"
        space.set_plaintext_data(path, b"v1")
        space.set_plaintext_data(path, b"v2")
        result = space.get_plaintext_data(path)
        assert result == b"v2"


class TestEncryptedKVData:
    def test_set_and_get_encrypted(self, space):
        path = f"test/enc-data/{uuid.uuid4().hex[:8]}"
        data = b"secret kv data"
        ts = space.set_encrypted_data(path, data)
        assert ts > 0

        result = space.get_encrypted_data(path)
        assert result == data

    def test_encrypted_data_not_readable_as_plaintext(self, space):
        """Reading encrypted data as plaintext should NOT match original."""
        path = f"test/enc-data/{uuid.uuid4().hex[:8]}"
        data = b"this is secret"
        space.set_encrypted_data(path, data)
        raw = space.get_plaintext_data(path)
        assert raw != data
