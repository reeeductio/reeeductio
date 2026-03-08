# Python Quick Start

This guide walks you through sending your first encrypted message with the Python SDK.
It assumes you have a server running locally — see [Running the Server](running-the-server.md) if you haven't done that yet.

## Install the SDK

```bash
pip install reeeductio
```

## Create a space and send a message

A **space** is a self-contained encrypted environment. To create one you generate
a keypair — the private key is the space's root credential. The holder of that key
is the space's first (and initially only) member.

Save the following as `quickstart.py` and run it:

```python
import json
import os
from reeeductio import Space, generate_keypair

# --- Step 1: Generate credentials ---
# The space keypair is the root identity for this space.
# The symmetric_root is the shared secret used to derive all encryption keys.
# Save both somewhere safe — you need them to reconnect to this space.
space_keypair = generate_keypair()
symmetric_root = os.urandom(32)

space_id  = space_keypair.to_space_id()   # starts with 'S'
member_id = space_keypair.to_user_id()    # starts with 'U'

print(f"Space ID:  {space_id}")
print(f"Member ID: {member_id}")

# Save credentials so you can reconnect later
creds = {
    "space_id": space_id,
    "member_id": member_id,
    "private_key_hex": space_keypair.private_key.hex(),
    "symmetric_root_hex": symmetric_root.hex(),
}
with open("space_creds.json", "w") as f:
    json.dump(creds, f, indent=2)
print("Credentials saved to space_creds.json")

# --- Step 2: Connect ---
# With auto_create_spaces enabled on the server, the space is created automatically
# the first time you connect to it.
with Space(
    space_id=space_id,
    member_id=member_id,
    private_key=space_keypair.private_key,
    symmetric_root=symmetric_root,
    base_url="http://localhost:8000",
) as space:

    # --- Step 3: Post an encrypted message ---
    # Messages are encrypted client-side before leaving your machine.
    # The server never sees plaintext.
    result = space.post_encrypted_message(
        topic_id="general",
        msg_type="chat.text",
        data=b"Hello, encrypted world!",
    )
    print(f"\nPosted message: {result.message_hash}")

    # --- Step 4: Read it back ---
    messages = space.get_messages("general")
    print(f"\nMessages in 'general' ({len(messages)} total):")
    for msg in messages:
        plaintext = space.decrypt_message_data(msg, "general")
        print(f"  [{msg.message_hash[:12]}...] {plaintext.decode()}")
```

Run it:

```bash
python quickstart.py
```

You should see output like:

```
Space ID:  S...
Member ID: U...
Credentials saved to space_creds.json

Posted message: M...

Messages in 'general' (1 total):
  [Mxyz123abc456...] Hello, encrypted world!
```

## Reconnecting to an existing space

Your credentials are in `space_creds.json`. Load them to reconnect:

```python
import json
from reeeductio import Space

with open("space_creds.json") as f:
    creds = json.load(f)

with Space(
    space_id=creds["space_id"],
    member_id=creds["member_id"],
    private_key=bytes.fromhex(creds["private_key_hex"]),
    symmetric_root=bytes.fromhex(creds["symmetric_root_hex"]),
    base_url="http://localhost:8000",
) as space:
    messages = space.get_messages("general")
    for msg in messages:
        plaintext = space.decrypt_message_data(msg, "general")
        print(plaintext.decode())
```

!!! warning "Keep your credentials safe"
    The `private_key` and `symmetric_root` are the keys to your space.
    Anyone who has them can read and write everything in it.
    Never commit them to source control.

## What just happened?

- **Key generation**: `generate_keypair()` created an Ed25519 keypair. The private key
  authenticates you to the server; the public key becomes your space ID (`S...`) and
  user ID (`U...`).
- **Key derivation**: The `symmetric_root` is used with HKDF to derive separate
  encryption keys for messages, state, blobs, and data — without you managing any of that.
- **Client-side encryption**: `post_encrypted_message()` encrypted your message with
  AES-GCM before sending it. The server stored only ciphertext.
- **Chain integrity**: Each message records the hash of the previous one, so tampering
  or reordering is detectable.

## Next steps

- [Add more users to your space](../how-to/add-users.md)
- [Store encrypted files](../how-to/store-files.md)
- [Explore the full Python SDK reference](../reference/python-sdk.md)
