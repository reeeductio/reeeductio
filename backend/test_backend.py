#!/usr/bin/env python3
"""
Basic tests for the E2EE messaging system

Run these tests to verify core functionality.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from database import Database
from sqlite_state_manager import SqliteStateManager
from crypto import CryptoUtils
from authorization import AuthorizationEngine
from identifiers import encode_channel_id, encode_user_id, decode_identifier
from filesystem_blob_manager import FilesystemBlobManager
from database_blob_manager import DatabaseBlobManager
import tempfile
import base64
import shutil
from cryptography.hazmat.primitives.asymmetric import ed25519


def test_database():
    """Test database operations"""
    print("Testing database and state operations...")

    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name

    try:
        db = Database(db_path)
        state_manager = SqliteStateManager(db_path)

        # Test state operations
        print("  Testing state storage...")
        state_manager.set_state(
            "channel1",
            "members/alice",
            {"public_key": "alice_key", "added_at": 12345},
            encrypted=False,
            updated_by="admin",
            updated_at=12345
        )

        state = state_manager.get_state("channel1", "members/alice")
        assert state is not None
        assert state["data"]["public_key"] == "alice_key"
        print("✓ State storage works")
        
        # Test message operations
        print("  Testing message storage...")
        db.add_message(
            channel_id="channel1",
            topic_id="general",
            message_hash="hash1",
            prev_hash=None,
            encrypted_payload="encrypted_content",
            sender="alice_key",
            signature="dummy_signature",
            server_timestamp=12346000  # milliseconds
        )
        
        messages = db.get_messages("channel1", "general")
        assert len(messages) == 1
        assert messages[0]["message_hash"] == "hash1"
        print("✓ Message storage works")
        
        # Test chain head
        print("  Testing chain head tracking...")
        head = db.get_chain_head("channel1", "general")
        assert head["message_hash"] == "hash1"
        print("✓ Chain head tracking works")
        
        # Test message queries with time filters (milliseconds)
        print("  Testing time-based queries...")
        messages = db.get_messages("channel1", "general", from_ts=12340000, to_ts=12350000)
        assert len(messages) == 1
        print("✓ Time-based queries work")
        
        print("Database tests passed!\n")
        
    finally:
        os.unlink(db_path)


def test_crypto():
    """Test cryptographic operations"""
    print("Testing cryptographic operations...")
    
    crypto = CryptoUtils()
    
    # Generate keypair
    print("  Testing signature verification...")
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Get raw bytes
    public_key_bytes = public_key.public_bytes_raw()
    
    # Test signature
    message = b"Hello, world!"
    signature = private_key.sign(message)
    
    # Verify signature
    assert crypto.verify_signature(message, signature, public_key_bytes)
    print("✓ Signature verification works")
    
    # Test with wrong message
    print("  Testing invalid signature rejection...")
    assert not crypto.verify_signature(b"Wrong message", signature, public_key_bytes)
    print("✓ Invalid signature rejected")
    
    # Test base64 encoding/decoding
    print("  Testing base64 encoding...")
    data = b"test data"
    encoded = crypto.base64_encode(data)
    decoded = crypto.base64_decode(encoded)
    assert decoded == data
    print("✓ Base64 encoding works")
    
    # Test message hash computation (now includes sender and returns typed ID)
    print("  Testing message hashing...")
    sender_id = encode_user_id(public_key_bytes)
    msg_hash = crypto.compute_message_hash(
        "channel1",
        "general-chat",  # slug format
        None,
        "encrypted_payload",
        sender_id
    )
    assert len(msg_hash) == 44  # Typed message ID is 44 chars base64
    assert msg_hash.startswith('M')  # Message type indicator
    print("✓ Message hashing works")

    # Test message signature verification
    print("  Testing message signature verification...")
    # Sign the full typed identifier bytes
    msg_tid = decode_identifier(msg_hash)
    msg_signature = private_key.sign(msg_tid.to_bytes())
    assert crypto.verify_message_signature(msg_hash, msg_signature, public_key_bytes)
    print("✓ Message signature verification works")
    
    print("Crypto tests passed!\n")


def test_authorization():
    """Test authorization engine"""
    print("Testing authorization engine...")
    
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    
    try:
        db = Database(db_path)
        state_manager = SqliteStateManager(db_path)
        crypto = CryptoUtils()
        authz = AuthorizationEngine(state_manager, crypto)
        
        # Generate keypairs
        admin_private = ed25519.Ed25519PrivateKey.generate()
        admin_public = admin_private.public_key()
        admin_public_bytes = admin_public.public_bytes_raw()
        admin_id = encode_user_id(admin_public_bytes)

        user_private = ed25519.Ed25519PrivateKey.generate()
        user_public = user_private.public_key()
        user_public_bytes = user_public.public_bytes_raw()
        user_id = encode_user_id(user_public_bytes)

        channel_id = encode_channel_id(admin_public_bytes)  # Admin is channel creator

        # Test channel creator has god mode
        print("  Testing channel creator god mode...")
        assert authz.check_permission(channel_id, admin_id, "write", "anything")
        print("✓ Channel creator has god mode")

        # Create a capability for user
        print("  Testing granted capability...")
        capability = {
            "op": "read",
            "path": "*",
            "granted_by": admin_id,
            "granted_at": 12345000  # milliseconds
        }

        # Sign the capability
        cap_message = crypto.compute_capability_signature_message(
            channel_id,
            user_id,
            capability["op"],
            capability["path"],
            capability["granted_at"]
        )
        signature = admin_private.sign(cap_message)
        capability["signature"] = crypto.base64_encode(signature)

        # Store capability in state
        state_manager.set_state(
            channel_id,
            f"members/{user_id}/rights/read_all",
            capability,
            encrypted=False,
            updated_by=admin_id,
            updated_at=12345000
        )

        # Test user now has read permission
        assert authz.check_permission(channel_id, user_id, "read", "members/alice")
        print("✓ User has granted capability")

        # Test user doesn't have write permission
        print("  Testing ungranted capability rejection...")
        assert not authz.check_permission(channel_id, user_id, "write", "members/alice")
        print("✓ User doesn't have ungranted capability")
        
        # Test path matching
        print("  Testing path matching...")
        assert authz._path_matches("*", "members")
        assert authz._path_matches("members/", "members/alice")
        assert not authz._path_matches("members/alice", "members/bob")
        print("✓ Path matching works")

        # Test capability subset checking
        print("  Testing capability subset checking...")
        granter_caps = [
            {"op": "write", "path": "*"}
        ]
        requested_caps = [
            {"op": "create", "path": "members/"}
        ]
        assert authz._has_capability_superset(granter_caps, requested_caps)
        print("✓ Capability subset checking works")
        
        # Test privilege escalation prevention
        print("  Testing privilege escalation prevention...")
        requested_caps = [
            {"op": "write", "path": "*"}
        ]
        granter_caps = [
            {"op": "read", "path": "*"}
        ]
        assert not authz._has_capability_superset(granter_caps, requested_caps)
        print("✓ Privilege escalation prevented")
        
        print("Authorization tests passed!\n")
        
    finally:
        os.unlink(db_path)


def test_blob_storage():
    """Test blob storage with both filesystem and database backends"""
    print("Testing blob storage...")

    crypto = CryptoUtils()

    # Test data
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)

    # Test FilesystemBlobManager
    print("  Testing FilesystemBlobManager...")
    blob_dir = tempfile.mkdtemp()
    try:
        fs_manager = FilesystemBlobManager(blob_dir)

        # Test successful upload
        print("  Testing blob upload...")
        fs_manager.add_blob(blob_id, blob_data)
        print("  ✓ Blob upload works")

        # Test retrieval
        print("  Testing blob retrieval...")
        retrieved = fs_manager.get_blob(blob_id)
        assert retrieved == blob_data
        print("  ✓ Blob retrieval works")

        # Test duplicate upload (should raise FileExistsError)
        print("  Testing duplicate blob rejection...")
        try:
            fs_manager.add_blob(blob_id, blob_data)
            assert False, "Should have raised FileExistsError"
        except FileExistsError:
            print("  ✓ Duplicate blob rejected")

        # Test invalid blob_id (wrong type)
        print("  Testing invalid blob_id rejection...")
        try:
            invalid_id = encode_user_id(b"x" * 32)  # USER type instead of BLOB
            fs_manager.add_blob(invalid_id, blob_data)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "BLOB type" in str(e)
            print("  ✓ Invalid blob_id rejected")

        # Test retrieval of non-existent blob
        print("  Testing non-existent blob retrieval...")
        non_existent_id = crypto.compute_blob_id(b"different content")
        assert fs_manager.get_blob(non_existent_id) is None
        print("  ✓ Non-existent blob returns None")

        # Test deletion
        print("  Testing blob deletion...")
        assert fs_manager.delete_blob(blob_id) == True
        assert fs_manager.get_blob(blob_id) is None
        print("  ✓ Blob deletion works")

        # Test deleting non-existent blob
        print("  Testing non-existent blob deletion...")
        assert fs_manager.delete_blob(blob_id) == False
        print("  ✓ Deleting non-existent blob returns False")

    finally:
        shutil.rmtree(blob_dir)

    # Test DatabaseBlobManager
    print("  Testing DatabaseBlobManager...")
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name

    try:
        db = Database(db_path)
        db_manager = DatabaseBlobManager(db)

        # Test successful upload
        print("  Testing database blob upload...")
        db_manager.add_blob(blob_id, blob_data)
        print("  ✓ Database blob upload works")

        # Test retrieval
        print("  Testing database blob retrieval...")
        retrieved = db_manager.get_blob(blob_id)
        assert retrieved == blob_data
        print("  ✓ Database blob retrieval works")

        # Test deletion
        print("  Testing database blob deletion...")
        assert db_manager.delete_blob(blob_id) == True
        assert db_manager.get_blob(blob_id) is None
        print("  ✓ Database blob deletion works")

        # Test deleting non-existent blob
        print("  Testing database non-existent blob deletion...")
        assert db_manager.delete_blob(blob_id) == False
        print("  ✓ Database: Deleting non-existent blob returns False")

    finally:
        os.unlink(db_path)

    print("Blob storage tests passed!\n")


def test_integration():
    """Test end-to-end workflow"""
    print("Testing end-to-end workflow...")
    
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    
    try:
        db = Database(db_path)
        state_manager = SqliteStateManager(db_path)
        crypto = CryptoUtils()
        authz = AuthorizationEngine(state_manager, crypto)
        
        # Setup: Create channel and admin
        print("  Setting up channel and admin...")
        admin_private = ed25519.Ed25519PrivateKey.generate()
        admin_public = admin_private.public_key()
        admin_public_bytes = admin_public.public_bytes_raw()
        admin_id = encode_user_id(admin_public_bytes)
        channel_id = encode_channel_id(admin_public_bytes)

        # Add admin as member
        state_manager.set_state(
            channel_id,
            f"members/{admin_id}",
            {
                "public_key": admin_id,
                "added_at": 12345000,  # milliseconds
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
            "granted_at": 12345000  # milliseconds
        }
        cap_msg = crypto.compute_capability_signature_message(
            channel_id, admin_id, "write", "*", 12345000
        )
        admin_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))

        state_manager.set_state(
            channel_id,
            f"members/{admin_id}/rights/admin",
            admin_cap,
            encrypted=False,
            updated_by=admin_id,
            updated_at=12345000
        )

        # Create and add a new user
        print("  Testing admin adding new member...")
        user_private = ed25519.Ed25519PrivateKey.generate()
        user_public = user_private.public_key()
        user_public_bytes = user_public.public_bytes_raw()
        user_id = encode_user_id(user_public_bytes)

        # Admin adds user (should work)
        assert authz.check_permission(channel_id, admin_id, "create", f"members/{user_id}")

        state_manager.set_state(
            channel_id,
            f"members/{user_id}",
            {
                "public_key": user_id,
                "added_at": 12346000,  # milliseconds
                "added_by": admin_id
            },
            encrypted=False,
            updated_by=admin_id,
            updated_at=12346000
        )
        print("✓ Admin can add new member")

        # Grant user post capability
        print("  Testing user posting message...")
        post_cap = {
            "op": "create",
            "path": "topics/*/messages/",
            "granted_by": admin_id,
            "granted_at": 12346000  # milliseconds
        }
        cap_msg = crypto.compute_capability_signature_message(
            channel_id, user_id, "create", "topics/*/messages/", 12346000
        )
        post_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))

        state_manager.set_state(
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
            topic_id="general-chat",  # slug format
            message_hash=msg_hash,
            prev_hash=None,
            encrypted_payload="encrypted_content",
            sender=user_id,
            signature=crypto.base64_encode(msg_signature),
            server_timestamp=12347000  # milliseconds
        )
        print("✓ User can post message with granted capability")

        # Verify user can't write to admin areas
        print("  Testing unauthorized access prevention...")
        assert not authz.check_permission(channel_id, user_id, "write", "members/someone_else/rights/")
        print("✓ User can't access unauthorized areas")

        # Retrieve and verify message
        print("  Testing message retrieval...")
        messages = db.get_messages(channel_id, "general-chat")
        assert len(messages) == 1
        assert messages[0]["message_hash"] == msg_hash
        assert messages[0]["sender"] == user_id
        print("✓ Message retrieval works")
        
        print("Integration test passed!\n")
        
    finally:
        os.unlink(db_path)


if __name__ == "__main__":
    print("=" * 60)
    print("E2EE Messaging System - Test Suite")
    print("=" * 60)
    print()
    
    try:
        test_database()
        test_crypto()
        test_authorization()
        test_blob_storage()
        test_integration()

        print("=" * 60)
        print("ALL TESTS PASSED! ✓")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
