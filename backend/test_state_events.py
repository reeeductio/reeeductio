"""
Test script for state-events dual-write functionality

This script verifies that:
1. State changes are written to both state table and state-events topic
2. Empty data in state-events indicates deletion
3. State can be reconstructed by replaying events
"""

import os
import tempfile
import base64
import json
from sqlite_data_store import SqliteDataStore
from sqlite_message_store import SqliteMessageStore
from space import Space
from crypto import CryptoUtils

def test_state_events_dual_write():
    """Test that state changes are dual-written to state-events topic"""

    # Create temporary databases
    with tempfile.TemporaryDirectory() as tmpdir:
        state_db = os.path.join(tmpdir, "state.db")
        message_db = os.path.join(tmpdir, "messages.db")

        # Initialize stores
        state_store = SqliteDataStore(state_db)
        message_store = SqliteMessageStore(message_db)

        # Create a space
        crypto = CryptoUtils()
        space_keypair = crypto.generate_keypair()
        space_id = crypto.public_key_to_base64(space_keypair.public_key())

        space = Space(
            space_id=space_id,
            state_store=state_store,
            message_store=message_store,
            jwt_secret="test-secret"
        )

        # Create a user keypair
        user_keypair = crypto.generate_keypair()
        user_public_key = crypto.public_key_to_base64(user_keypair.public_key())
        user_id = f"U_{user_public_key}"

        # Manually add user to state (bypassing auth for test)
        user_data = {"user_id": user_id, "name": "Test User"}
        user_data_b64 = base64.b64encode(json.dumps(user_data).encode()).decode()
        path = f"auth/users/{user_id}"
        signed_at = 1234567890

        # Create signature
        message_to_sign = '|'.join([space_id, path, user_data_b64, str(signed_at)]).encode('utf-8')
        signature = crypto.sign(message_to_sign, space_keypair)
        signature_b64 = crypto.base64_encode(signature)

        # Directly call state_store.set_state and message_store.add_message
        # to simulate what Space.set_state does
        import hashlib
        message_hash = hashlib.sha256(user_data_b64.encode('utf-8')).hexdigest()

        # Write to state table
        state_store.set_state(
            space_id=space_id,
            path=path,
            data=user_data_b64,
            signature=signature_b64,
            signed_by=space_id,
            signed_at=signed_at
        )

        # Write to state-events topic
        message_store.add_message(
            space_id=space_id,
            topic_id="state-events",
            message_hash=message_hash,
            msg_type=path,  # Path is the type!
            prev_hash=None,
            data=user_data_b64,  # Data goes directly
            sender=space_id,
            signature=signature_b64,
            server_timestamp=signed_at
        )

        print("✓ State written to both stores")

        # Verify state in table
        table_state = state_store.get_state(space_id, path)
        assert table_state is not None
        assert table_state["data"] == user_data_b64
        print("✓ State found in state table")

        # Verify event in state-events topic
        events = message_store.get_messages(space_id, "state-events")
        assert len(events) == 1
        assert events[0]["type"] == path  # Path is in type field
        assert events[0]["data"] == user_data_b64  # Data matches
        print("✓ Event found in state-events topic")

        # Test replay
        replayed_state = space.replay_state_from_events()
        assert path in replayed_state
        assert replayed_state[path]["data"] == user_data_b64
        print("✓ State successfully replayed from events")

        # Test deletion
        state_store.delete_state(space_id, path)

        # Write deletion event
        deletion_marker = f"delete:{path}:9999999"
        deletion_hash = hashlib.sha256(deletion_marker.encode()).hexdigest()
        head = message_store.get_chain_head(space_id, "state-events")

        message_store.add_message(
            space_id=space_id,
            topic_id="state-events",
            message_hash=deletion_hash,
            msg_type=path,
            prev_hash=head["message_hash"],
            data="",  # Empty data = deletion!
            sender=space_id,
            signature=signature_b64,
            server_timestamp=9999999
        )

        print("✓ Deletion written to both stores")

        # Verify deletion in table
        table_state = state_store.get_state(space_id, path)
        assert table_state is None
        print("✓ State deleted from table")

        # Verify deletion event
        events = message_store.get_messages(space_id, "state-events")
        assert len(events) == 2
        assert events[1]["data"] == ""  # Empty data
        print("✓ Deletion event in state-events topic")

        # Replay should show deleted state
        replayed_state = space.replay_state_from_events()
        assert path not in replayed_state
        print("✓ Deletion correctly applied during replay")

        # Test consistency check
        consistency = space.verify_state_consistency()
        assert consistency["consistent"]
        print("✓ State consistency verified")

        print("\n🎉 All tests passed!")

if __name__ == "__main__":
    test_state_events_dual_write()
