"""
Tests for state storage operations
"""
import pytest
import json
import base64


def test_state_storage(state_store):
    """Test state storage operations"""
    # Encode data as base64 JSON
    data = {"public_key": "alice_key", "added_at": 12345}
    data_json = json.dumps(data)
    data_b64 = base64.b64encode(data_json.encode()).decode()

    state_store.set_state(
        "channel1",
        "members/alice",
        data_b64,
        updated_by="admin",
        updated_at=12345
    )

    state = state_store.get_state("channel1", "members/alice")
    assert state is not None
    # Decode the base64 data to verify
    decoded_data = json.loads(base64.b64decode(state["data"]))
    assert decoded_data["public_key"] == "alice_key"
