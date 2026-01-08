"""
Generic tests for state storage backends

These test functions can be used with any DataStore implementation.
"""
import pytest
import json
import base64
import sys
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

from data_store import DataStore
import conftest
sign_state_entry = conftest.sign_state_entry
sign_and_store_state = conftest.sign_and_store_state

# ============================================================================
# Generic Test Functions
# ============================================================================

def generic_state_set_and_get(state_store: DataStore, space_id: str, admin_keypair: dict):
    """Generic test for basic state set and get operations"""
    data = {"public_key": "alice_key", "added_at": 12345}

    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path="members/alice",
        contents=data,
        signer_private_key=admin_keypair['private'],
        signer_user_id=admin_keypair['user_id'],
        signed_at=12345
    )

    state = state_store.get_state(space_id, "members/alice")
    assert state is not None
    decoded_data = json.loads(base64.b64decode(state["data"]))
    assert decoded_data["public_key"] == "alice_key"
    assert state["signed_by"] == admin_keypair['user_id']
    assert state["signed_at"] == 12345


def generic_state_update(state_store: DataStore, space_id: str, admin_keypair: dict, user_keypair: dict):
    """Generic test for updating existing state"""
    data1 = {"value": 1}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path="config/setting",
        contents=data1,
        signer_private_key=admin_keypair['private'],
        signer_user_id=admin_keypair["user_id"],
        signed_at=100
    )


    data2 = {"value": 2}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path="config/setting",
        contents=data2,
        signer_private_key=admin_keypair['private'],
        signer_user_id=admin_keypair["user_id"],
        signed_at=200
    )

    state = state_store.get_state(space_id, "config/setting")
    assert state is not None
    decoded_data = json.loads(base64.b64decode(state["data"]))
    assert decoded_data["value"] == 2
    assert state["signed_by"] == admin_keypair['user_id']
    assert state["signed_at"] == 200


def generic_state_delete(state_store: DataStore, space_id: str, admin_keypair: dict):
    """Generic test for state deletion"""
    data = {"test": "data"}

    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path="temp/data",
        contents=data,
        signer_private_key=admin_keypair['private'],
        signer_user_id=admin_keypair['user_id'],
        signed_at=100
    )

    # Verify it exists
    assert state_store.get_state(space_id, "temp/data") is not None

    # Delete it
    state_store.delete_state(space_id, "temp/data")

    # Verify it's gone
    assert state_store.get_state(space_id, "temp/data") is None


def generic_state_list_by_prefix(state_store: DataStore, space_id: str, admin_keypair: dict):
    """Generic test for listing state by prefix"""
    # Create multiple state entries
    for i in range(5):
        data = {"index": i}

        sign_and_store_state(
            state_store=state_store,
            space_id=space_id,
            path=f"members-count/user{i}",
            contents=data,
            signer_private_key=admin_keypair['private'],
            signer_user_id=admin_keypair['user_id'],
            signed_at=100 + i
        )

    # Add some entries with a different prefix
    for i in range(3):
        data = {"index": i}

        sign_and_store_state(
            state_store=state_store,
            space_id=space_id,
            path=f"config-count/setting{i}",
            contents=data,
            signer_private_key=admin_keypair['private'],
            signer_user_id=admin_keypair['user_id'],
            signed_at=200 + i
        )

    # List members
    members = state_store.list_state(space_id, "members-count/")
    assert len(members) == 5
    for member in members:
        assert member["path"].startswith("members-count/")

    # List config
    configs = state_store.list_state(space_id, "config-count/")
    assert len(configs) == 3
    for config in configs:
        assert config["path"].startswith("config-count/")


def generic_state_nonexistent(state_store: DataStore, space_id: str):
    """Generic test for getting nonexistent state"""
    state = state_store.get_state(space_id, "does/not/exist")
    assert state is None


def generic_state_multiple_spaces(state_store: DataStore, space_id: str, admin_keypair: dict):
    """Generic test for state isolation between spaces"""
    data = {"test": "data"}

    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path="config/setting",
        contents=data,
        signer_private_key=admin_keypair['private'],
        signer_user_id=admin_keypair['user_id'],
        signed_at=100
    )

    # Should not be visible in a different space
    other_space_id = f"{space_id}-other"
    assert state_store.get_state(other_space_id, "config/setting") is None


# ============================================================================
# SQLite-Specific Tests
# ============================================================================

def test_sqlite_state_set_and_get(sqlite_state_store, admin_keypair):
    space_id = admin_keypair['space_id']
    generic_state_set_and_get(sqlite_state_store, space_id, admin_keypair)

def test_sqlite_state_update(sqlite_state_store, admin_keypair, user_keypair):
    space_id = admin_keypair['space_id']
    generic_state_update(sqlite_state_store, space_id, admin_keypair, user_keypair)

def test_sqlite_state_delete(sqlite_state_store, admin_keypair):
    space_id = admin_keypair['space_id']
    generic_state_delete(sqlite_state_store, space_id, admin_keypair)

def test_sqlite_state_list_by_prefix(sqlite_state_store, admin_keypair):
    space_id = admin_keypair['space_id']
    generic_state_list_by_prefix(sqlite_state_store, space_id, admin_keypair)

def test_sqlite_state_nonexistent(sqlite_state_store, admin_keypair):
    space_id = admin_keypair['space_id']
    generic_state_nonexistent(sqlite_state_store, space_id)

def test_sqlite_state_multiple_spaces(sqlite_state_store, admin_keypair):
    space_id = admin_keypair['space_id']
    generic_state_multiple_spaces(sqlite_state_store, space_id, admin_keypair)

