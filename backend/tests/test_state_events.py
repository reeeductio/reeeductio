"""
Tests for state dual-write functionality

Verifies that state changes are written to both the state table and state topic,
enabling event sourcing and state replay capabilities.
"""

import base64
import json
import hashlib
import pytest

from space import Space
from tests.conftest import sign_state_entry, sign_and_store_state


@pytest.fixture
def space(temp_db_path, admin_keypair, message_store, state_store):
    """Create a Space instance for testing"""
    return Space(
        space_id=admin_keypair['space_id'],
        state_store=state_store,
        message_store=message_store,
        jwt_secret="test-secret"
    )


def test_state_set_dual_write(space, message_store, state_store, admin_keypair):
    """Test that setting state writes to both state table and state topic"""
    space_id = admin_keypair['space_id']
    path = "auth/users/U_test123"
    user_data = {"user_id": "U_test123", "name": "Test User"}
    data_b64 = base64.b64encode(json.dumps(user_data).encode()).decode()
    signed_at = 1234567890

    # Create signature
    signature_b64 = sign_state_entry(
        space_id, path, data_b64,
        admin_keypair['private'], admin_keypair['id'], signed_at
    )

    # Write to both stores (simulating what Space.set_state does)
    message_hash = hashlib.sha256(data_b64.encode('utf-8')).hexdigest()

    state_store.set_state(
        space_id=space_id,
        path=path,
        data=data_b64,
        signature=signature_b64,
        signed_by=admin_keypair['id'],
        signed_at=signed_at
    )

    message_store.add_message(
        space_id=space_id,
        topic_id="state",
        message_hash=message_hash,
        msg_type=path,  # Path is the message type!
        prev_hash=None,
        data=data_b64,  # Data goes directly
        sender=admin_keypair['id'],
        signature=signature_b64,
        server_timestamp=signed_at
    )

    # Verify in state table
    table_state = state_store.get_state(space_id, path)
    assert table_state is not None
    assert table_state["data"] == data_b64
    assert table_state["signed_by"] == admin_keypair['id']

    # Verify in state topic
    events = message_store.get_messages(space_id, "state")
    assert len(events) == 1
    assert events[0]["type"] == path  # Path is in type field
    assert events[0]["data"] == data_b64  # Data matches
    assert events[0]["sender"] == admin_keypair['id']


def test_state_delete_dual_write(space, message_store, state_store, admin_keypair):
    """Test that deleting state writes a deletion event to state topic"""
    space_id = admin_keypair['space_id']
    path = "auth/users/U_test456"
    user_data = {"user_id": "U_test456", "name": "Delete Me"}

    # First, create some state
    sign_and_store_state(
        state_store, space_id, path, user_data,
        admin_keypair['private'], admin_keypair['id'], 1234567890
    )

    # Add to state
    data_b64 = base64.b64encode(json.dumps(user_data).encode()).decode()
    signature_b64 = sign_state_entry(
        space_id, path, data_b64,
        admin_keypair['private'], admin_keypair['id'], 1234567890
    )
    message_hash = hashlib.sha256(data_b64.encode('utf-8')).hexdigest()

    message_store.add_message(
        space_id, "state", message_hash, path, None,
        data_b64, admin_keypair['id'], signature_b64, 1234567890
    )

    # Now delete it
    deleted = state_store.delete_state(space_id, path)
    assert deleted

    # Write deletion event (empty data)
    deletion_marker = f"delete:{path}:9999999"
    deletion_hash = hashlib.sha256(deletion_marker.encode()).hexdigest()
    head = message_store.get_chain_head(space_id, "state")

    message_store.add_message(
        space_id=space_id,
        topic_id="state",
        message_hash=deletion_hash,
        msg_type=path,
        prev_hash=head["message_hash"],
        data="",  # EMPTY DATA = DELETION!
        sender=admin_keypair['id'],
        signature=signature_b64,
        server_timestamp=9999999
    )

    # Verify deleted from table
    table_state = state_store.get_state(space_id, path)
    assert table_state is None

    # Verify deletion event in topic
    events = message_store.get_messages(space_id, "state")
    assert len(events) == 2

    # Find creation and deletion events (order may vary)
    creation_event = next(e for e in events if e["data"])
    deletion_event = next(e for e in events if not e["data"])

    assert creation_event["data"] == data_b64  # Creation event has data
    assert deletion_event["data"] == ""  # Deletion event is empty
    assert creation_event["type"] == path
    assert deletion_event["type"] == path


def test_replay_state_from_events(space, message_store, state_store, admin_keypair):
    """Test that state can be reconstructed by replaying events"""
    space_id = admin_keypair['space_id']

    # Create multiple state entries
    paths_data = [
        ("auth/users/U_alice", {"user_id": "U_alice", "name": "Alice"}),
        ("auth/users/U_bob", {"user_id": "U_bob", "name": "Bob"}),
        ("auth/roles/admin", {"role_id": "admin", "description": "Administrator"}),
    ]

    for path, state_data in paths_data:
        sign_and_store_state(
            state_store, space_id, path, state_data,
            admin_keypair['private'], admin_keypair['id'], 1234567890
        )

        data_b64 = base64.b64encode(json.dumps(state_data).encode()).decode()
        signature_b64 = sign_state_entry(
            space_id, path, data_b64,
            admin_keypair['private'], admin_keypair['id'], 1234567890
        )

        message_hash = hashlib.sha256(data_b64.encode('utf-8')).hexdigest()
        head = message_store.get_chain_head(space_id, "state")
        prev_hash = head["message_hash"] if head else None

        message_store.add_message(
            space_id, "state", message_hash, path, prev_hash,
            data_b64, admin_keypair['id'], signature_b64, 1234567890
        )

    # Replay state from events
    replayed_state = space.replay_state_from_events()

    # Verify all paths are present
    assert len(replayed_state) == 3
    for path, state_data in paths_data:
        assert path in replayed_state
        data_b64 = base64.b64encode(json.dumps(state_data).encode()).decode()
        assert replayed_state[path]["data"] == data_b64


def test_verify_state_consistency(space, message_store, state_store, admin_keypair):
    """Test that state table and replayed events are consistent"""
    space_id = admin_keypair['space_id']
    path = "auth/users/U_charlie"
    user_data = {"user_id": "U_charlie", "name": "Charlie"}

    # Create some state
    sign_and_store_state(
        state_store, space_id, path, user_data,
        admin_keypair['private'], admin_keypair['id'], 1234567890
    )

    data_b64 = base64.b64encode(json.dumps(user_data).encode()).decode()
    signature_b64 = sign_state_entry(
        space_id, path, data_b64,
        admin_keypair['private'], admin_keypair['id'], 1234567890
    )
    message_hash = hashlib.sha256(data_b64.encode('utf-8')).hexdigest()

    message_store.add_message(
        space_id, "state", message_hash, path, None,
        data_b64, admin_keypair['id'], signature_b64, 1234567890
    )

    # Check consistency
    consistency = space.verify_state_consistency()

    assert consistency["consistent"] is True
    assert len(consistency["missing_in_table"]) == 0
    assert len(consistency["missing_in_events"]) == 0
    assert len(consistency["mismatched"]) == 0


def test_message_type_field(message_store, admin_keypair):
    """Test that messages now include the 'type' field"""
    space_id = admin_keypair['space_id']

    # Add a chat message
    message_store.add_message(
        space_id=space_id,
        topic_id="general",
        message_hash="hash123",
        msg_type="chat.text",  # Message type field
        prev_hash=None,
        data="encrypted_content",
        sender="U_alice",
        signature="sig123",
        server_timestamp=1234567890
    )

    # Retrieve the message
    messages = message_store.get_messages(space_id, "general")
    assert len(messages) == 1
    assert messages[0]["type"] == "chat.text"  # Type field present
    assert messages[0]["data"] == "encrypted_content"  # Renamed from encrypted_payload


def test_state_event_with_path_as_type(message_store, admin_keypair):
    """Test that state events use the path as the message type"""
    space_id = admin_keypair['space_id']
    path = "/auth/users/U_alice/rights/cap_123"

    # Add a state event
    message_store.add_message(
        space_id=space_id,
        topic_id="state",
        message_hash="hash_state",
        msg_type=path,  # Path is the type!
        prev_hash=None,
        data="capability_data_base64",
        sender="U_admin",
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


def test_post_message_updates_state(space, message_store, state_store, admin_keypair):
    """Test that post_message() to state topic updates the state store"""
    import asyncio

    space_id = admin_keypair['space_id']
    path = "auth/users/U_test789"
    user_data = {"user_id": "U_test789", "name": "Test User"}
    data_b64 = base64.b64encode(json.dumps(user_data).encode()).decode()
    signed_at = 1234567890

    # Create signature
    signature_b64 = sign_state_entry(
        space_id, path, data_b64,
        admin_keypair['private'], admin_keypair['id'], signed_at
    )

    # Compute correct message hash using space's method
    message_hash = space.compute_message_hash(
        topic_id="state",
        prev_hash=None,
        encrypted_payload=data_b64,
        sender=admin_keypair['id']
    )

    # Create JWT token for authentication
    token_info = space.create_jwt(admin_keypair['id'])
    token = token_info['token']

    # Sign the message hash (sign the typed identifier bytes)
    from identifiers import decode_identifier
    msg_id = decode_identifier(message_hash)
    message_signature = admin_keypair['private'].sign(msg_id.to_bytes())
    message_signature_b64 = base64.b64encode(message_signature).decode()

    # Post message to state topic
    async def post():
        return await space.post_message(
            topic_id="state",
            message_hash=message_hash,
            msg_type=path,  # Path is the type
            prev_hash=None,
            data=data_b64,
            signature=message_signature_b64,  # Message signature (not state signature)
            token=token
        )

    # Run async function
    server_timestamp = asyncio.run(post())

    # Verify message was written to state topic
    events = message_store.get_messages(space_id, "state")
    assert len(events) == 1
    assert events[0]["type"] == path
    assert events[0]["data"] == data_b64

    # Verify state was also updated in state store
    state = state_store.get_state(space_id, path)
    assert state is not None
    assert state["data"] == data_b64
    assert state["signed_by"] == admin_keypair['id']


def test_post_message_unauthorized_state_modification(space, message_store, state_store, admin_keypair, user_keypair):
    """Test that unauthorized users cannot modify state via post_message"""
    import asyncio

    space_id = admin_keypair['space_id']

    # User tries to create a capability for themselves (unauthorized)
    path = f"auth/users/{user_keypair['id']}/rights/cap_admin"
    capability_data = {"capability_id": "cap_admin", "scope": "admin"}
    data_b64 = base64.b64encode(json.dumps(capability_data).encode()).decode()

    # Compute message hash
    message_hash = space.compute_message_hash(
        topic_id="state",
        prev_hash=None,
        encrypted_payload=data_b64,
        sender=user_keypair['id']
    )

    # Create JWT token for the user
    token_info = space.create_jwt(user_keypair['id'])
    token = token_info['token']

    # Sign the message
    from identifiers import decode_identifier
    msg_id = decode_identifier(message_hash)
    message_signature = user_keypair['private'].sign(msg_id.to_bytes())
    message_signature_b64 = base64.b64encode(message_signature).decode()

    # Try to post message - should fail authorization
    async def post():
        return await space.post_message(
            topic_id="state",
            message_hash=message_hash,
            msg_type=path,
            prev_hash=None,
            data=data_b64,
            signature=message_signature_b64,
            token=token
        )

    # Should raise ValueError for no permission
    with pytest.raises(ValueError) as exc_info:
        asyncio.run(post())

    # User is blocked from posting to state topic or from modifying that state path
    assert "No post permission" in str(exc_info.value) or "No permission" in str(exc_info.value)

    # Verify no message was added
    events = message_store.get_messages(space_id, "state")
    assert len(events) == 0

    # Verify no state was created
    state = state_store.get_state(space_id, path)
    assert state is None


def test_post_message_privilege_escalation_blocked(space, message_store, state_store, admin_keypair, user_keypair):
    """Test that users cannot escalate privileges by writing to unauthorized state paths"""
    import asyncio

    space_id = admin_keypair['space_id']

    # First, grant the user permission to write to their own profile data
    # (simulating a user who has *some* permissions but not admin)

    # Grant permission to post to state topic
    topic_cap_data = {
        "op": "create",
        "path": "topics/state/messages/{...}"
    }
    topic_cap_path = f"auth/users/{user_keypair['id']}/rights/cap_post_state_events"
    sign_and_store_state(
        state_store, space_id, topic_cap_path, topic_cap_data,
        admin_keypair['private'], admin_keypair['id'], 1234567890
    )

    # Admin creates a capability allowing user to write to their profile
    capability_data = {
        "op": "modify",
        "path": f"profiles/{user_keypair['id']}/{{...}}"  # User can modify their own profile
    }
    capability_path = f"auth/users/{user_keypair['id']}/rights/cap_profile_write"

    # Admin signs and stores the capability
    sign_and_store_state(
        state_store, space_id, capability_path, capability_data,
        admin_keypair['private'], admin_keypair['id'], 1234567890
    )

    # Now user tries to grant themselves admin capability by posting to auth/ tree
    admin_cap_data = {
        "op": "modify",
        "path": "auth/{...}"  # Trying to grant themselves full auth access!
    }
    malicious_path = f"auth/users/{user_keypair['id']}/rights/cap_admin"
    malicious_data_b64 = base64.b64encode(json.dumps(admin_cap_data).encode()).decode()

    # Compute message hash for the malicious state event
    message_hash = space.compute_message_hash(
        topic_id="state",
        prev_hash=None,  # First message to state
        encrypted_payload=malicious_data_b64,
        sender=user_keypair['id']
    )

    # Create JWT token for the user
    token_info = space.create_jwt(user_keypair['id'])
    token = token_info['token']

    # Sign the message
    from identifiers import decode_identifier
    msg_id = decode_identifier(message_hash)
    message_signature = user_keypair['private'].sign(msg_id.to_bytes())
    message_signature_b64 = base64.b64encode(message_signature).decode()

    # Try to post message - should fail because user doesn't have permission for auth/ paths
    async def post():
        return await space.post_message(
            topic_id="state",
            message_hash=message_hash,
            msg_type=malicious_path,  # Path in auth/ tree
            prev_hash=None,
            data=malicious_data_b64,
            signature=message_signature_b64,
            token=token
        )

    # Should raise ValueError for no create permission on auth/ path
    with pytest.raises(ValueError) as exc_info:
        asyncio.run(post())

    # Verify the error is about lacking permission for the specific state path
    error_msg = str(exc_info.value)
    assert "No create permission" in error_msg or "No permission" in error_msg

    # Verify no message was added to state
    events = message_store.get_messages(space_id, "state")
    assert len(events) == 0  # No messages should have been added

    # Verify no malicious capability was created
    malicious_state = state_store.get_state(space_id, malicious_path)
    assert malicious_state is None

    # Verify user still only has their original two capabilities (topic + profile)
    user_caps = state_store.list_state(space_id, f"auth/users/{user_keypair['id']}/rights/")
    assert len(user_caps) == 2
    cap_paths = {cap["path"] for cap in user_caps}
    assert topic_cap_path in cap_paths
    assert capability_path in cap_paths
    assert malicious_path not in cap_paths
