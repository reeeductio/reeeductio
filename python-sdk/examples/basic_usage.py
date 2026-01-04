#!/usr/bin/env python3
"""
Basic usage example for the reeeductio high-level SDK.

This example demonstrates:
- Generating keypairs
- Connecting to a space
- Authentication
- State management
- Message retrieval
"""

from reeeductio import Space, generate_keypair
import json


def main():
    print("=== reeeductio SDK Example ===\n")

    # 1. Generate a keypair (or load from file in production)
    print("1. Generating keypair...")
    keypair = generate_keypair()
    user_id = keypair.to_typed_public_key()
    print(f"   User ID: {user_id}\n")

    # 2. Connect to a space
    # Note: In production, you would use a real space_id
    space_id = "AAAA" + "A" * 40  # Placeholder 44-char ID
    base_url = "http://localhost:8000"

    print(f"2. Connecting to space: {space_id[:10]}...")
    space = Space(
        space_id=space_id,
        keypair=keypair,
        base_url=base_url,
        auto_authenticate=True,  # Automatically handle authentication
    )
    print("   Connected!\n")

    # 3. Authenticate
    print("3. Authenticating...")
    try:
        token = space.authenticate()
        print(f"   Got JWT token: {token[:20]}...\n")
    except Exception as e:
        print(f"   Authentication failed: {e}")
        print("   (Make sure the server is running and the space exists)\n")
        return

    # 4. Work with state
    print("4. Setting user profile in state...")
    profile = {
        "name": "Alice",
        "bio": "Example user",
        "avatar_url": "https://example.com/avatar.png"
    }

    try:
        profile_data = json.dumps(profile).encode('utf-8')
        success = space.set_state(f"profiles/{user_id}", profile_data)
        if success:
            print(f"   Profile saved for {user_id}\n")
        else:
            print("   Failed to save profile\n")
    except Exception as e:
        print(f"   Error: {e}\n")

    # 5. Read state back
    print("5. Reading profile from state...")
    try:
        retrieved_profile = space.get_profile(user_id)
        if retrieved_profile:
            print(f"   Retrieved: {json.dumps(retrieved_profile, indent=2)}\n")
        else:
            print("   Profile not found\n")
    except Exception as e:
        print(f"   Error: {e}\n")

    # 6. Get messages from a topic
    print("6. Fetching messages from 'general' topic...")
    try:
        messages = space.get_messages(topic_id="general", limit=10)
        print(f"   Found {len(messages)} messages")

        for i, msg in enumerate(messages[:3], 1):
            print(f"   Message {i}:")
            print(f"     Sender: {msg.sender[:10]}...")
            print(f"     Hash: {msg.message_hash[:10]}...")
            print(f"     Timestamp: {msg.server_timestamp}")
    except Exception as e:
        print(f"   Error: {e}\n")

    # 7. Cleanup - delete profile
    print("\n7. Cleaning up...")
    try:
        success = space.delete_state(f"profiles/{user_id}")
        if success:
            print("   Profile deleted\n")
    except Exception as e:
        print(f"   Error: {e}\n")

    print("=== Example Complete ===")


if __name__ == "__main__":
    main()
