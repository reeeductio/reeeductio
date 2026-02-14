"""
Example of HKDF key derivation in reeeductio SDK.

Demonstrates how the Space client derives encryption keys
from the symmetric root key.
"""

import os

from reeeductio import Space, derive_key, generate_keypair

print("=== HKDF Key Derivation Example ===\n")

# Generate a symmetric root key
symmetric_root = os.urandom(32)
print(f"Symmetric root key: {symmetric_root.hex()}\n")

# Create a Space client (which derives keys automatically)
keypair = generate_keypair()
space_id = keypair.to_space_id()
print(f"Space ID: {space_id}\n")

# Derive keys manually using derive_key (with space_id scoping)
message_key = derive_key(symmetric_root, f"message key|{space_id}")
blob_key = derive_key(symmetric_root, f"blob key|{space_id}")
state_key = derive_key(symmetric_root, f"state key|{space_id}")
data_key = derive_key(symmetric_root, f"data key|{space_id}")

print("Manually derived keys (scoped to space_id):")
print(f"  message_key: {message_key.hex()[:32]}...")
print(f"  blob_key:    {blob_key.hex()[:32]}...")
print(f"  state_key:   {state_key.hex()[:32]}...")
print(f"  data_key:    {data_key.hex()[:32]}...\n")

space = Space(
    space_id=space_id,
    keypair=keypair,
    symmetric_root=symmetric_root,
    base_url="http://localhost:8000",
    auto_authenticate=False,
)

print("Space client derived keys:")
print(f"  message_key: {space.message_key.hex()[:32]}...")
print(f"  blob_key:    {space.blob_key.hex()[:32]}...")
print(f"  state_key:   {space.state_key.hex()[:32]}...")
print(f"  data_key:    {space.data_key.hex()[:32]}...\n")

# Verify they match
assert message_key == space.message_key
assert blob_key == space.blob_key
assert state_key == space.state_key
assert data_key == space.data_key

print("✓ Manual derivation matches Space client derivation\n")

# Show that keys are deterministic
space2 = Space(
    space_id=space_id,
    keypair=keypair,
    symmetric_root=symmetric_root,
    base_url="http://localhost:8000",
    auto_authenticate=False,
)

assert space.message_key == space2.message_key
assert space.blob_key == space2.blob_key
assert space.state_key == space2.state_key
assert space.data_key == space2.data_key

print("✓ Key derivation is deterministic (same root → same keys)\n")

# Show that different roots produce different keys
different_root = os.urandom(32)
space3 = Space(
    space_id=space_id,
    keypair=keypair,
    symmetric_root=different_root,
    base_url="http://localhost:8000",
    auto_authenticate=False,
)

assert space.message_key != space3.message_key
assert space.blob_key != space3.blob_key
assert space.state_key != space3.state_key
assert space.data_key != space3.data_key

print("✓ Different roots produce different keys\n")

# Show domain separation: same root, different space_id
different_space_id = keypair.to_user_id()  # Different ID type
space4 = Space(
    space_id=different_space_id,
    keypair=keypair,
    symmetric_root=symmetric_root,  # Same root!
    base_url="http://localhost:8000",
    auto_authenticate=False,
)

print(f"Space 1 ID: {space_id[:20]}...")
print(f"Space 1 message_key: {space.message_key.hex()[:32]}...\n")

print(f"Space 4 ID: {different_space_id[:20]}... (different)")
print(f"Space 4 message_key: {space4.message_key.hex()[:32]}... (different!)\n")

assert space.message_key != space4.message_key
assert space.blob_key != space4.blob_key
assert space.state_key != space4.state_key
assert space.data_key != space4.data_key

print("✓ Domain separation: Same root + different space_id = different keys")
print("  This prevents accidental key reuse across spaces!\n")

# Custom key derivation
custom_key = derive_key(symmetric_root, "custom context", length=16)
print(f"Custom derived key (16 bytes): {custom_key.hex()}")
print(f"Length: {len(custom_key)} bytes\n")

print("=== All key derivation tests passed! ===")
