"""
Tests for state dual-write functionality

Verifies that state changes are written to both the state table and state topic,
enabling event sourcing and state replay capabilities.
"""

import base64
import json
import hashlib
import pytest
import sys
from pathlib import Path

from space import Space
from crypto import CryptoUtils

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

import conftest
sign_data_entry = conftest.sign_data_entry
sign_and_store_data = conftest.sign_and_store_data
set_space_state = conftest.set_space_state
authenticate_with_challenge = conftest.authenticate_with_challenge


def test_message_type_field(message_store, admin_keypair):
    """Test that messages now include the 'type' field"""
    space_id = admin_keypair['space_id']
    admin_id = admin_keypair['id']

    # Add a chat message
    message_store.add_message(
        space_id=space_id,
        topic_id="general",
        message_hash="hash123",
        msg_type="chat.text",  # Message type field
        prev_hash=None,
        data="encrypted_content",
        sender=admin_id,
        signature="sig123",
        server_timestamp=1234567890
    )

    # Retrieve the message
    messages = message_store.get_messages(space_id, "general")
    assert len(messages) == 1
    assert messages[0]["type"] == "chat.text"  # Type field present
    assert messages[0]["data"] == "encrypted_content"  # Renamed from data


def test_state_event_with_path_as_type(message_store, unique_admin_keypair):
    """Test that state events use the path as the message type"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['id']
    path = "/auth/users/U_alice/rights/cap_123"

    # Add a state event
    message_store.add_message(
        space_id=space_id,
        topic_id="state",
        message_hash="hash_state",
        msg_type=path,  # Path is the type!
        prev_hash=None,
        data="capability_data_base64",
        sender=admin_id,
        signature="sig_state",
        server_timestamp=1234567890
    )

    # Retrieve state events
    events = message_store.get_messages(space_id, "state")
    assert len(events) == 1
    assert events[0]["type"] == path  # Path stored in type field
    assert events[0]["data"] == "capability_data_base64"


def test_chain_conflict_detection(message_store, admin_keypair):
    """Test that concurrent writes are detected via chain conflict"""
    from exceptions import ChainConflictError

    space_id = admin_keypair['space_id']

    # Add first message
    message_store.add_message(
        space_id=space_id,
        topic_id="state",
        message_hash="hash_1",
        msg_type="/auth/users/U_alice",
        prev_hash=None,  # First message
        data="data_1",
        sender="U_admin",
        signature="sig_1",
        server_timestamp=1000
    )

    # Try to add another message claiming to be first (wrong prev_hash)
    with pytest.raises(ChainConflictError) as exc_info:
        message_store.add_message(
            space_id=space_id,
            topic_id="state",
            message_hash="hash_2",
            msg_type="/auth/users/U_bob",
            prev_hash=None,  # Wrong! Should be hash_1
            data="data_2",
            sender="U_admin",
            signature="sig_2",
            server_timestamp=2000
        )

    assert "Chain conflict" in str(exc_info.value)
    assert "expected prev_hash=hash_1" in str(exc_info.value)

    # Verify only first message was added
    events = message_store.get_messages(space_id, "state")
    assert len(events) == 1
    assert events[0]["message_hash"] == "hash_1"

    # Now add with correct prev_hash
    message_store.add_message(
        space_id=space_id,
        topic_id="state",
        message_hash="hash_2",
        msg_type="/auth/users/U_bob",
        prev_hash="hash_1",  # Correct!
        data="data_2",
        sender="U_admin",
        signature="sig_2",
        server_timestamp=2000
    )

    # Verify both messages are now present
    events = message_store.get_messages(space_id, "state")
    assert len(events) == 2
    assert events[0]["message_hash"] == "hash_1"
    assert events[1]["message_hash"] == "hash_2"


def test_post_message_updates_state(unique_space, message_store, state_store, unique_admin_keypair, user_keypair):
    """Test that post_message() to state topic updates the state store"""
    import asyncio

    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['id']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    path = f"auth/users/{user_id}"
    user_data = {"user_id": user_id, "name": "Test User"}
    user_data_b64 = CryptoUtils.base64_encode_object(user_data)

    set_space_state(
        unique_space,
        path,
        user_data,
        admin_token,
        unique_admin_keypair
    )

    # Verify message was written to state topic
    events = message_store.get_messages(space_id, "state")
    assert len(events) == 1
    assert events[0]["type"] == path
    assert events[0]["data"] == user_data_b64

    # Verify state was also updated in state store
    state = state_store.get_state(space_id, path)
    assert state is not None
    assert state["data"] == user_data_b64
    assert state["sender"] == unique_admin_keypair['id']


def test_post_message_unauthorized_state_modification(unique_space, message_store, state_store, unique_admin_keypair, user_keypair):
    """Test that unauthorized users cannot modify state via post_message"""
    import asyncio

    space_id = unique_admin_keypair['space_id']
    user_id = user_keypair['id']
    user_private = user_keypair['private']
    admin_id = unique_admin_keypair['id']
    admin_private = unique_admin_keypair['private']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Admin adds user to the space
    set_space_state(
        unique_space,
        f"auth/users/{user_id}",
        {"user_id": user_id},
        admin_token,
        unique_admin_keypair
    )

    # User tries to create a capability for themselves (unauthorized)
    path = f"auth/users/{user_id}/rights/cap_admin"
    capability_data = {"op": "write", "path": "{...}"}
    data_b64 = base64.b64encode(json.dumps(capability_data).encode()).decode()

    # Compute message hash
    message_hash = unique_space.compute_message_hash(
        topic_id="state",
        msg_type=path,
        prev_hash=None,
        data=data_b64,
        sender=user_id
    )

    # Sign the message
    from identifiers import decode_identifier
    msg_id = decode_identifier(message_hash)
    message_signature = user_keypair['private'].sign(msg_id.to_bytes())
    message_signature_b64 = base64.b64encode(message_signature).decode()

    # Create JWT token for the user
    user_token = authenticate_with_challenge(unique_space, user_id, user_private)

    # Should raise ValueError for no permission
    with pytest.raises(ValueError) as exc_info:
        set_space_state(
            unique_space,
            path,
            capability_data,
            user_token,
            user_keypair
        )
    # User is blocked from posting to state topic or from modifying that state path
    assert "capability grant" in str(exc_info.value).lower()

    # Verify no additional message was added
    events = message_store.get_messages(space_id, "state")
    # Should have only the 'create user' event
    assert len(events) == 1

    # Verify no additional state was created
    state = state_store.get_state(space_id, path)
    assert state is None


def test_post_message_privilege_escalation_blocked(unique_space, message_store, state_store, unique_admin_keypair, user_keypair):
    """Test that users cannot escalate privileges by writing to unauthorized state paths"""
    import asyncio

    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['id']
    user_id = user_keypair['id']
    admin_private = unique_admin_keypair['private']
    user_private = user_keypair['private']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Admin adds user to the space
    set_space_state(
        unique_space,
        f"auth/users/{user_id}",
        {"user_id": user_id},
        admin_token,
        unique_admin_keypair
    )

    # Grant the user permission to write to their own profile data
    # (simulating a user who has *some* permissions but not admin)

    # Admin creates a capability allowing user to write to their profile
    capability_data = {
        "op": "modify",
        "path": f"state/profiles/{user_keypair['id']}/{{...}}"  # User can modify their own profile
    }
    capability_path = f"auth/users/{user_keypair['id']}/rights/cap_profile_write"

    # Admin signs and stores the capability
    set_space_state(
        unique_space,
        capability_path,
        capability_data,
        admin_token,
        unique_admin_keypair
    )

    # Now user tries to grant themselves admin capability by posting to auth/ tree
    user_token = authenticate_with_challenge(unique_space, user_id, user_private)
    admin_cap_data = {
        "op": "modify",
        "path": "auth/{...}"  # Trying to grant themselves full auth access!
    }
    malicious_path = f"auth/users/{user_keypair['id']}/rights/cap_admin"

    # Should raise ValueError for no create permission on auth/ path
    with pytest.raises(ValueError) as exc_info:
        set_space_state(
            unique_space,
            malicious_path,
            admin_cap_data,
            user_token,
            user_keypair
        )

    # Verify the error is about lacking permission
    error_msg = str(exc_info.value)
    assert "capability grant" in error_msg

    # Verify no message was added to state after the 2 admin messages
    events = message_store.get_messages(space_id, "state")
    assert len(events) == 2  # No new messages should have been added

    # Verify no malicious capability was created
    malicious_state = state_store.get_state(space_id, malicious_path)
    assert malicious_state is None

    # Verify user still only has their original two capabilities (topic + profile)
    user_caps = state_store.list_state(space_id, f"auth/users/{user_keypair['id']}/rights/")
    assert len(user_caps) == 1
    cap_paths = {cap["type"] for cap in user_caps}
    assert capability_path in cap_paths
    assert malicious_path not in cap_paths
