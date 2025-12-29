"""
Tests for database operations and state storage
"""
import pytest


def test_state_storage(state_store):
    """Test state storage operations"""
    state_store.set_state(
        "channel1",
        "members/alice",
        {"public_key": "alice_key", "added_at": 12345},
        encrypted=False,
        updated_by="admin",
        updated_at=12345
    )

    state = state_store.get_state("channel1", "members/alice")
    assert state is not None
    assert state["data"]["public_key"] == "alice_key"


def test_message_storage(db):
    """Test message storage operations"""
    db.add_message(
        channel_id="channel1",
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="encrypted_content",
        sender="alice_key",
        signature="dummy_signature",
        server_timestamp=12346000  # milliseconds
    )

    messages = db.get_messages("channel1", "general")
    assert len(messages) == 1
    assert messages[0]["message_hash"] == "hash1"


def test_chain_head_tracking(db):
    """Test chain head tracking"""
    db.add_message(
        channel_id="channel1",
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="encrypted_content",
        sender="alice_key",
        signature="dummy_signature",
        server_timestamp=12346000
    )

    head = db.get_chain_head("channel1", "general")
    assert head["message_hash"] == "hash1"


def test_time_based_queries(db):
    """Test message queries with time filters"""
    db.add_message(
        channel_id="channel1",
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="encrypted_content",
        sender="alice_key",
        signature="dummy_signature",
        server_timestamp=12346000  # milliseconds
    )

    # Query within time range
    messages = db.get_messages("channel1", "general", from_ts=12340000, to_ts=12350000)
    assert len(messages) == 1

    # Query outside time range
    messages = db.get_messages("channel1", "general", from_ts=12350000, to_ts=12360000)
    assert len(messages) == 0
