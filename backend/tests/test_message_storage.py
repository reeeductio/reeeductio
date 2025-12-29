"""
Tests for message storage operations
"""
import pytest


def test_message_storage(message_store):
    """Test message storage operations"""
    message_store.add_message(
        channel_id="channel1",
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="encrypted_content",
        sender="alice_key",
        signature="dummy_signature",
        server_timestamp=12346000  # milliseconds
    )

    messages = message_store.get_messages("channel1", "general")
    assert len(messages) == 1
    assert messages[0]["message_hash"] == "hash1"


def test_chain_head_tracking(message_store):
    """Test chain head tracking"""
    message_store.add_message(
        channel_id="channel1",
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="encrypted_content",
        sender="alice_key",
        signature="dummy_signature",
        server_timestamp=12346000
    )

    head = message_store.get_chain_head("channel1", "general")
    assert head["message_hash"] == "hash1"


def test_time_based_queries(message_store):
    """Test message queries with time filters"""
    message_store.add_message(
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
    messages = message_store.get_messages("channel1", "general", from_ts=12340000, to_ts=12350000)
    assert len(messages) == 1

    # Query outside time range
    messages = message_store.get_messages("channel1", "general", from_ts=12350000, to_ts=12360000)
    assert len(messages) == 0
