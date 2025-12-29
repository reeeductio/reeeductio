"""
End-to-end integration tests
"""
import pytest

from identifiers import decode_identifier


def test_end_to_end_workflow(db, state_store, crypto, authz, admin_keypair, user_keypair):
    """Test complete end-to-end workflow"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']
    user_private = user_keypair['private']

    # Add admin as member
    state_store.set_state(
        channel_id,
        f"members/{admin_id}",
        {
            "public_key": admin_id,
            "added_at": 12345000,
            "added_by": admin_id
        },
        encrypted=False,
        updated_by=admin_id,
        updated_at=12345000
    )

    # Grant admin write capability
    admin_cap = {
        "op": "write",
        "path": "*",
        "granted_by": admin_id,
        "granted_at": 12345000
    }
    cap_msg = crypto.compute_capability_signature_message(
        channel_id, admin_id, "write", "*", 12345000
    )
    admin_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))

    state_store.set_state(
        channel_id,
        f"members/{admin_id}/rights/admin",
        admin_cap,
        encrypted=False,
        updated_by=admin_id,
        updated_at=12345000
    )

    # Admin adds user (should work)
    assert authz.check_permission(channel_id, admin_id, "create", f"members/{user_id}")

    state_store.set_state(
        channel_id,
        f"members/{user_id}",
        {
            "public_key": user_id,
            "added_at": 12346000,
            "added_by": admin_id
        },
        encrypted=False,
        updated_by=admin_id,
        updated_at=12346000
    )

    # Grant user post capability
    post_cap = {
        "op": "create",
        "path": "topics/*/messages/",
        "granted_by": admin_id,
        "granted_at": 12346000
    }
    cap_msg = crypto.compute_capability_signature_message(
        channel_id, user_id, "create", "topics/*/messages/", 12346000
    )
    post_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))

    state_store.set_state(
        channel_id,
        f"members/{user_id}/rights/post",
        post_cap,
        encrypted=False,
        updated_by=admin_id,
        updated_at=12346000
    )

    # User posts message
    assert authz.check_permission(channel_id, user_id, "create", "topics/general-chat/messages/")

    # Compute message hash with sender
    msg_hash = crypto.compute_message_hash(
        channel_id, "general-chat", None, "encrypted_content", user_id
    )

    # Sign the message hash (sign the full typed identifier bytes)
    msg_tid = decode_identifier(msg_hash)
    msg_signature = user_private.sign(msg_tid.to_bytes())

    db.add_message(
        channel_id=channel_id,
        topic_id="general-chat",
        message_hash=msg_hash,
        prev_hash=None,
        encrypted_payload="encrypted_content",
        sender=user_id,
        signature=crypto.base64_encode(msg_signature),
        server_timestamp=12347000
    )

    # Verify user can't write to admin areas
    assert not authz.check_permission(channel_id, user_id, "write", "members/someone_else/rights/")

    # Retrieve and verify message
    messages = db.get_messages(channel_id, "general-chat")
    assert len(messages) == 1
    assert messages[0]["message_hash"] == msg_hash
    assert messages[0]["sender"] == user_id
