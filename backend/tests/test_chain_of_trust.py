"""
Tests for chain-of-trust validation

These tests verify that the system properly validates the chain of trust
from any user or tool back to the space admin, preventing database tampering
attacks where an adversary inserts unauthorized keys directly into storage.
"""
import pytest
import json
import base64
import sys
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

import conftest
sign_data_entry = conftest.sign_data_entry
sign_and_store_data = conftest.sign_and_store_data
set_space_state = conftest.set_space_state
authenticate_with_challenge = conftest.authenticate_with_challenge

def test_space_admin_always_valid(authz, admin_keypair):
    """Test that space admin always has valid chain (root of trust)"""
    space_id = admin_keypair['space_id']
    admin_id = admin_keypair['user_id']

    # Admin is the root of trust - always valid
    assert authz.verify_chain_of_trust(space_id, admin_id)


def test_user_created_by_admin_valid(unique_space, unique_admin_keypair, user_keypair):
    """Test that a user created by admin has valid chain"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Admin creates a user
    user_info = {"user_id": user_id}
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents=user_info,
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # User has valid chain: user -> admin (root)
    assert unique_space.authz.verify_chain_of_trust(space_id, user_id)


def test_user_created_by_user_valid(unique_space, unique_admin_keypair, user_keypair):
    """Test that a user created by another user has valid chain"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']
    user_private = user_keypair['private']

    # Create second user keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_user_id
    user2_private = Ed25519PrivateKey.generate()
    user2_public = user2_private.public_key().public_bytes_raw()
    user2_id = encode_user_id(user2_public)

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Admin creates first user
    user_info = {"user_id": user_id}
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents=user_info,
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Admin grants first user permission to create other users
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}/rights/create_users",
        contents={
            "op": "create",
            "path": "state/auth/users/{...}"
        },
        token=admin_token,
        keypair=unique_admin_keypair
    )

    user_token = authenticate_with_challenge(unique_space, user_id, user_private)

    # First user creates second user
    user2_info = {"user_id": user2_id}
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user2_id}",
        contents=user2_info,
        token=user_token,
        keypair=user_keypair
    )

    # Second user has valid chain: user2 -> user1 -> admin (root)
    assert unique_space.authz.verify_chain_of_trust(space_id, user2_id)


def test_tool_created_by_admin_valid(unique_space, unique_admin_keypair):
    """Test that a tool created by admin has valid chain"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']

    # Create tool keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_tool_id
    tool_private = Ed25519PrivateKey.generate()
    tool_public = tool_private.public_key().public_bytes_raw()
    tool_id = encode_tool_id(tool_public)

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Admin creates tool
    tool_info = {"tool_id": tool_id, "use_limit": 100}
    set_space_state(
        space=unique_space,
        path=f"auth/tools/{tool_id}",
        contents=tool_info,
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Tool has valid chain: tool -> admin (root)
    assert unique_space.authz.verify_chain_of_trust(space_id, tool_id)


def test_unauthorized_user_insertion_rejected(unique_space, unique_admin_keypair):
    """
    Test that a user inserted directly into database (not signed by admin/user)
    is rejected by chain validation

    This simulates a database tampering attack by directly inserting a message
    """
    space_id = unique_admin_keypair['space_id']

    # Create attacker keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_user_id, decode_identifier
    from crypto import CryptoUtils
    import base64

    attacker_private = Ed25519PrivateKey.generate()
    attacker_public = attacker_private.public_key().public_bytes_raw()
    attacker_id = encode_user_id(attacker_public)

    crypto = CryptoUtils()

    # Attacker creates their own user entry
    attacker_info = {"user_id": attacker_id}
    data = crypto.base64_encode_object(attacker_info)
    path = f"auth/users/{attacker_id}"

    # Get current chain head
    head = unique_space.message_store.get_chain_head(space_id, "state")
    prev_hash = head["message_hash"] if head else None

    # Compute message hash (attacker is the sender)
    message_hash = crypto.compute_message_hash(
        space_id,
        "state",
        prev_hash,
        data,
        attacker_id  # Attacker signs their own message
    )

    # Sign with attacker's key
    message_tid = decode_identifier(message_hash)
    message_bytes = message_tid.to_bytes()
    signature_bytes = attacker_private.sign(message_bytes)
    signature = base64.b64encode(signature_bytes).decode('utf-8')

    # Directly insert into message store (bypassing authorization)
    unique_space.message_store.add_message(
        space_id=space_id,
        topic_id="state",
        message_hash=message_hash,
        msg_type=path,
        prev_hash=prev_hash,
        data=data,
        sender=attacker_id,
        signature=signature,
        server_timestamp=12345000
    )

    # Attacker's chain is invalid: attacker -> attacker (circular, not admin)
    assert not unique_space.authz.verify_chain_of_trust(space_id, attacker_id)


def test_capabilities_rejected_for_untrusted_user(unique_space, unique_admin_keypair):
    """
    Test that capabilities are not loaded for a user without valid chain

    This ensures the read path is protected against database tampering
    """
    space_id = unique_admin_keypair['space_id']

    # Create attacker keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_user_id, decode_identifier
    from crypto import CryptoUtils
    import base64

    attacker_private = Ed25519PrivateKey.generate()
    attacker_public = attacker_private.public_key().public_bytes_raw()
    attacker_id = encode_user_id(attacker_public)

    crypto = CryptoUtils()

    # Get current chain head
    head = unique_space.message_store.get_chain_head(space_id, "state")
    prev_hash = head["message_hash"] if head else None

    # Helper to insert attacker's message directly
    def insert_attacker_message(path, contents):
        nonlocal prev_hash
        data = crypto.base64_encode_object(contents)
        message_hash = crypto.compute_message_hash(space_id, "state", prev_hash, data, attacker_id)
        message_tid = decode_identifier(message_hash)
        signature_bytes = attacker_private.sign(message_tid.to_bytes())
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        unique_space.message_store.add_message(
            space_id=space_id,
            topic_id="state",
            message_hash=message_hash,
            msg_type=path,
            prev_hash=prev_hash,
            data=data,
            sender=attacker_id,
            signature=signature,
            server_timestamp=12345000
        )
        prev_hash = message_hash

    # Attacker inserts themselves into database
    insert_attacker_message(f"auth/users/{attacker_id}", {"user_id": attacker_id})

    # Attacker grants themselves god-mode capability
    insert_attacker_message(f"auth/users/{attacker_id}/rights/god_mode", {"op": "write", "path": "{...}"})

    # Capabilities should NOT be loaded (chain validation fails)
    capabilities = unique_space.authz._load_user_capabilities(space_id, attacker_id)
    assert len(capabilities) == 0

    # Permission check should fail
    assert not unique_space.authz.check_permission(space_id, attacker_id, "write", "anything")


def test_tool_capabilities_rejected_for_untrusted_tool(unique_space, unique_admin_keypair):
    """
    Test that tool capabilities are not loaded for a tool without valid chain
    """
    space_id = unique_admin_keypair['space_id']

    # Create attacker tool keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_tool_id, decode_identifier
    from crypto import CryptoUtils
    import base64

    attacker_tool_private = Ed25519PrivateKey.generate()
    attacker_tool_public = attacker_tool_private.public_key().public_bytes_raw()
    attacker_tool_id = encode_tool_id(attacker_tool_public)

    crypto = CryptoUtils()

    # Get current chain head
    head = unique_space.message_store.get_chain_head(space_id, "state")
    prev_hash = head["message_hash"] if head else None

    # Helper to insert attacker tool's message directly
    def insert_attacker_message(path, contents):
        nonlocal prev_hash
        data = crypto.base64_encode_object(contents)
        message_hash = crypto.compute_message_hash(space_id, "state", prev_hash, data, attacker_tool_id)
        message_tid = decode_identifier(message_hash)
        signature_bytes = attacker_tool_private.sign(message_tid.to_bytes())
        signature = base64.b64encode(signature_bytes).decode('utf-8')

        unique_space.message_store.add_message(
            space_id=space_id,
            topic_id="state",
            message_hash=message_hash,
            msg_type=path,
            prev_hash=prev_hash,
            data=data,
            sender=attacker_tool_id,
            signature=signature,
            server_timestamp=12345000
        )
        prev_hash = message_hash

    # Attacker inserts tool into database
    insert_attacker_message(f"auth/tools/{attacker_tool_id}", {"tool_id": attacker_tool_id})

    # Attacker grants tool a capability
    insert_attacker_message(f"auth/tools/{attacker_tool_id}/rights/evil", {"op": "write", "path": "{...}"})

    # Tool capabilities should NOT be loaded (chain validation fails)
    capabilities = unique_space.authz._load_tool_capabilities(space_id, attacker_tool_id)
    assert len(capabilities) == 0

    # Permission check should fail
    assert not unique_space.authz.check_permission(space_id, attacker_tool_id, "write", "anything")


def test_chain_cache_works(unique_space, unique_admin_keypair, user_keypair):
    """Test that chain validation cache improves performance"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Create user
    user_info = {"user_id": user_id}
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents=user_info,
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # First validation should populate cache
    assert unique_space.authz.verify_chain_of_trust(space_id, user_id, skip_cache=False)

    # Check cache is populated
    cache_key = (space_id, user_id)
    assert cache_key in unique_space.authz._chain_validation_cache
    assert unique_space.authz._chain_validation_cache[cache_key] == True

    # Second validation should use cache (we can't directly verify this,
    # but we can verify the result is correct)
    assert unique_space.authz.verify_chain_of_trust(space_id, user_id, skip_cache=False)


def test_chain_cache_invalidation(unique_space, unique_admin_keypair, user_keypair):
    """Test that chain cache is properly invalidated"""
    space_id = unique_admin_keypair['space_id']
    admin_id = unique_admin_keypair['user_id']
    admin_private = unique_admin_keypair['private']
    user_id = user_keypair['user_id']

    admin_token = authenticate_with_challenge(unique_space, admin_id, admin_private)

    # Create user
    user_info = {"user_id": user_id}
    set_space_state(
        space=unique_space,
        path=f"auth/users/{user_id}",
        contents=user_info,
        token=admin_token,
        keypair=unique_admin_keypair
    )

    # Populate cache
    assert unique_space.authz.verify_chain_of_trust(space_id, user_id)
    cache_key = (space_id, user_id)
    assert cache_key in unique_space.authz._chain_validation_cache

    # Invalidate cache for this user
    unique_space.authz.invalidate_chain_cache(space_id, user_id)
    assert cache_key not in unique_space.authz._chain_validation_cache

    # Can still verify (will repopulate cache)
    assert unique_space.authz.verify_chain_of_trust(space_id, user_id)
    assert cache_key in unique_space.authz._chain_validation_cache


@pytest.mark.skip(reason="Needs adaptation for event-sourced model - requires direct message store manipulation")
def test_invalid_signature_on_user_entry_rejected():
    """Test that a user entry with invalid signature is rejected"""
    # TODO: Adapt this test for event-sourced model
    # Need to directly insert an invalid message into the message store
    # to simulate database tampering with invalid signatures
    pass


def test_nonexistent_user_rejected(unique_space, unique_admin_keypair):
    """Test that a user with no database entry is rejected"""
    space_id = unique_admin_keypair['space_id']

    # Create user keypair but don't store in database
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_user_id
    user_private = Ed25519PrivateKey.generate()
    user_public = user_private.public_key().public_bytes_raw()
    user_id = encode_user_id(user_public)

    # User doesn't exist in database
    assert not unique_space.authz.verify_chain_of_trust(space_id, user_id)
