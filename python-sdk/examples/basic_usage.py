"""
Basic usage example for reeeductio SDK.

This example demonstrates:
- Generating keys
- Authenticating with a space
- Posting messages
- Reading state
- Uploading blobs
"""

import os

from reeeductio import Space, generate_keypair

# Generate a key pair for the user
keypair = generate_keypair()
user_id = keypair.to_user_id()
print(f"Generated user ID: {user_id}")

# In practice, you'd have a space_id from creating or joining a space
# For this example, we'll use a placeholder
SPACE_ID = "Cabc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
BASE_URL = "http://localhost:8000"

# Generate the symmetric root key (32 bytes)
# In practice, this would be derived from the space's shared secret or retrieved securely
symmetric_root = os.urandom(32)
print(f"Generated symmetric root key: {symmetric_root.hex()[:32]}...")

# Connect to the space
with Space(
    space_id=SPACE_ID,
    member_id=keypair.to_user_id(),
    private_key=keypair.private_key,
    symmetric_root=symmetric_root,
    base_url=BASE_URL,
    auto_authenticate=True,
) as space:
    print("Connected to space!")

    # ============================================================
    # Messages
    # ============================================================

    # Post a message to a topic
    print("\n=== Messages ===")
    try:
        result = space.post_message(
            topic_id="general",
            msg_type="chat",
            data=b"Hello from the new SDK!",  # Should be encrypted in production
        )
        print(f"Posted message: {result.message_hash}")
        print(f"Server timestamp: {result.server_timestamp}")
    except Exception as e:
        print(f"Failed to post message: {e}")

    # Get recent messages
    try:
        messages = space.get_messages("general", limit=5)
        print(f"\nFound {len(messages)} messages:")
        for msg in messages:
            print(f"  {msg.sender[:10]}...: {msg.type} (hash: {msg.message_hash[:10]}...)")
    except Exception as e:
        print(f"Failed to get messages: {e}")

    # ============================================================
    # State
    # ============================================================

    print("\n=== State ===")

    # Set a state value
    try:
        import json
        profile = {"name": "Alice", "status": "online"}
        profile_data = json.dumps(profile).encode()

        result = space.set_state(f"profiles/{user_id}", profile_data)
        print(f"Set state: {result.message_hash}")
    except Exception as e:
        print(f"Failed to set state: {e}")

    # Get a state value
    try:
        state_msg = space.get_state(f"profiles/{user_id}")
        print(f"Got state from message: {state_msg.message_hash}")
        print(f"State data (base64): {state_msg.data[:50] if state_msg.data else None}...")
    except Exception as e:
        print(f"Failed to get state: {e}")

    # Get state history
    try:
        history = space.get_state_history(limit=5)
        print(f"\nState history ({len(history)} entries):")
        for msg in history:
            print(f"  {msg.type}: {msg.message_hash[:10]}...")
    except Exception as e:
        print(f"Failed to get state history: {e}")

    # ============================================================
    # Key-Value Data
    # ============================================================

    print("\n=== Key-Value Data ===")

    # Set data
    try:
        timestamp = space.set_data("settings/theme", b"dark")
        print(f"Set data at timestamp: {timestamp}")
    except Exception as e:
        print(f"Failed to set data: {e}")

    # Get data
    try:
        data_entry = space.get_data("settings/theme")
        print(f"Got data: {data_entry.data}")
        print(f"Signed by: {data_entry.signed_by[:10]}...")
        print(f"Signed at: {data_entry.signed_at}")
    except Exception as e:
        print(f"Failed to get data: {e}")

    # ============================================================
    # Blobs
    # ============================================================

    print("\n=== Blobs ===")

    # Upload a blob
    try:
        blob_data = b"This is a test file"
        blob = space.upload_blob(blob_data)
        print(f"Uploaded blob: {blob.blob_id}")
        print(f"Blob size: {blob.size} bytes")

        # Download the blob
        downloaded = space.download_blob(blob.blob_id)
        print(f"Downloaded {len(downloaded)} bytes")
        print(f"Content matches: {downloaded == blob_data}")
    except Exception as e:
        print(f"Failed with blobs: {e}")

    print("\n=== Done! ===")
