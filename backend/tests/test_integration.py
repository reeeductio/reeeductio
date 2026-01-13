"""
End-to-end integration tests
"""
import pytest
import json
import base64
import sys
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

from identifiers import decode_identifier
from crypto import CryptoUtils
import conftest
set_space_state = conftest.set_space_state
authenticate_with_challenge = conftest.authenticate_with_challenge

def test_end_to_end_workflow(unique_space, unique_admin_keypair, user_keypair):
    """Test complete end-to-end workflow"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']
    user_private = user_keypair['private']

    # Admin authenticates
    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Admin adds user (should work)
    assert unique_space.authz.check_permission(space_id, admin_id, "create", f"members/{user_id}")

    user_member_data = {
        "user_id": user_id
    }
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents=user_member_data,
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Grant user post capability
    post_cap = {
        "op": "create",
        "path": "topics/{any}/messages/"
    }
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/post",
        contents=post_cap,
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # User posts message
    assert unique_space.authz.check_permission(space_id, user_id, "create", "topics/general-chat/messages/")

    # Compute message hash with sender
    crypto = CryptoUtils()
    msg_hash = crypto.compute_message_hash(
        space_id, "general-chat", None, "encrypted_content", user_id
    )

    # Sign the message hash (sign the full typed identifier bytes)
    msg_id = decode_identifier(msg_hash)
    msg_signature = user_private.sign(msg_id.to_bytes())

    unique_space.message_store.add_message(
        space_id=space_id,
        topic_id="general-chat",
        message_hash=msg_hash,
        msg_type="chat.text",
        prev_hash=None,
        data="encrypted_content",
        sender=user_id,
        signature=crypto.base64_encode(msg_signature),
        server_timestamp=12347000
    )

    # Verify user can't write to admin areas
    assert not unique_space.authz.check_permission(space_id, user_id, "write", "auth/users/someone_else/rights/")

    # Retrieve and verify message
    messages = unique_space.message_store.get_messages(space_id, "general-chat")
    assert len(messages) == 1
    assert messages[0]["message_hash"] == msg_hash
    assert messages[0]["sender"] == user_id
