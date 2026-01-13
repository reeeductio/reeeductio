"""
Generic tests for data storage backends

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
sign_data_entry = conftest.sign_data_entry
sign_and_store_data = conftest.sign_and_store_data

# ============================================================================
# Generic Test Functions
# ============================================================================

def generic_data_set_and_get(data_store: DataStore, space_id: str, admin_keypair: dict):
    """Generic test for basic data set and get operations"""
    data = {"public_key": "alice_key", "added_at": 12345}

    sign_and_store_data(
        data_store=data_store,
        space_id=space_id,
        path="members/alice",
        contents=data,
        signer_private_key=admin_keypair['private'],
        signer_user_id=admin_keypair['user_id'],
        signed_at=12345
    )

    data = data_store.get_data(space_id, "members/alice")
    assert data is not None
    decoded_data = json.loads(base64.b64decode(data["data"]))
    assert decoded_data["public_key"] == "alice_key"
    assert data["signed_by"] == admin_keypair['user_id']
    assert data["signed_at"] == 12345


def generic_data_update(data_store: DataStore, space_id: str, admin_keypair: dict, user_keypair: dict):
    """Generic test for updating existing data"""
    data1 = {"value": 1}
    sign_and_store_data(
        data_store=data_store,
        space_id=space_id,
        path="config/setting",
        contents=data1,
        signer_private_key=admin_keypair['private'],
        signer_user_id=admin_keypair["user_id"],
        signed_at=100
    )


    data2 = {"value": 2}
    sign_and_store_data(
        data_store=data_store,
        space_id=space_id,
        path="config/setting",
        contents=data2,
        signer_private_key=admin_keypair['private'],
        signer_user_id=admin_keypair["user_id"],
        signed_at=200
    )

    data = data_store.get_data(space_id, "config/setting")
    assert data is not None
    decoded_data = json.loads(base64.b64decode(data["data"]))
    assert decoded_data["value"] == 2
    assert data["signed_by"] == admin_keypair['user_id']
    assert data["signed_at"] == 200


def generic_data_delete(data_store: DataStore, space_id: str, admin_keypair: dict):
    """Generic test for data deletion"""
    data = {"test": "data"}

    sign_and_store_data(
        data_store=data_store,
        space_id=space_id,
        path="temp/data",
        contents=data,
        signer_private_key=admin_keypair['private'],
        signer_user_id=admin_keypair['user_id'],
        signed_at=100
    )

    # Verify it exists
    assert data_store.get_data(space_id, "temp/data") is not None

    # Delete it
    data_store.delete_data(space_id, "temp/data")

    # Verify it's gone
    assert data_store.get_data(space_id, "temp/data") is None


def generic_data_list_by_prefix(data_store: DataStore, space_id: str, admin_keypair: dict):
    """Generic test for listing data by prefix"""
    # Create multiple data entries
    for i in range(5):
        data = {"index": i}

        sign_and_store_data(
            data_store=data_store,
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

        sign_and_store_data(
            data_store=data_store,
            space_id=space_id,
            path=f"config-count/setting{i}",
            contents=data,
            signer_private_key=admin_keypair['private'],
            signer_user_id=admin_keypair['user_id'],
            signed_at=200 + i
        )

    # List members
    members = data_store.list_data(space_id, "members-count/")
    assert len(members) == 5
    for member in members:
        assert member["path"].startswith("members-count/")

    # List config
    configs = data_store.list_data(space_id, "config-count/")
    assert len(configs) == 3
    for config in configs:
        assert config["path"].startswith("config-count/")


def generic_data_nonexistent(data_store: DataStore, space_id: str):
    """Generic test for getting nonexistent data"""
    data = data_store.get_data(space_id, "does/not/exist")
    assert data is None


def generic_data_multiple_spaces(data_store: DataStore, space_id: str, admin_keypair: dict):
    """Generic test for data isolation between spaces"""
    data = {"test": "data"}

    sign_and_store_data(
        data_store=data_store,
        space_id=space_id,
        path="config/setting",
        contents=data,
        signer_private_key=admin_keypair['private'],
        signer_user_id=admin_keypair['user_id'],
        signed_at=100
    )

    # Should not be visible in a different space
    other_space_id = f"{space_id}-other"
    assert data_store.get_data(other_space_id, "config/setting") is None


# ============================================================================
# SQLite-Specific Tests
# ============================================================================

def test_sqlite_data_set_and_get(sqlite_data_store, admin_keypair):
    space_id = admin_keypair['space_id']
    generic_data_set_and_get(sqlite_data_store, space_id, admin_keypair)

def test_sqlite_data_update(sqlite_data_store, admin_keypair, user_keypair):
    space_id = admin_keypair['space_id']
    generic_data_update(sqlite_data_store, space_id, admin_keypair, user_keypair)

def test_sqlite_data_delete(sqlite_data_store, admin_keypair):
    space_id = admin_keypair['space_id']
    generic_data_delete(sqlite_data_store, space_id, admin_keypair)

def test_sqlite_data_list_by_prefix(sqlite_data_store, admin_keypair):
    space_id = admin_keypair['space_id']
    generic_data_list_by_prefix(sqlite_data_store, space_id, admin_keypair)

def test_sqlite_data_nonexistent(sqlite_data_store, admin_keypair):
    space_id = admin_keypair['space_id']
    generic_data_nonexistent(sqlite_data_store, space_id)

def test_sqlite_data_multiple_spaces(sqlite_data_store, admin_keypair):
    space_id = admin_keypair['space_id']
    generic_data_multiple_spaces(sqlite_data_store, space_id, admin_keypair)

