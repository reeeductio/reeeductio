# Add Users

This guide covers how to add other users to an existing space, assign them roles, and remove them when needed.

## Prerequisites

- You are the space creator (or have `write` capability on `auth/users/{any}`).
- You have the new user's user ID (`U...`). They generate this from their own Ed25519 keypair.

## How users get their user ID

Each user generates their own keypair independently. Their user ID is the public key encoded with a `U` prefix:

=== "Python"

    ```python
    import os
    from reeeductio.crypto import generate_keypair, to_user_id, to_space_id

    private_key, public_key = generate_keypair()
    symmetric_root = os.urandom(32)   # will be shared with them by the space creator

    user_id  = to_user_id(public_key)   # share this with the space creator
    space_id = to_space_id(public_key)  # their own space ID (for their private space)
    print('My user ID:', user_id)
    ```

=== "TypeScript"

    ```typescript
    import { generateKeyPair, toUserId } from 'reeeductio';

    const keyPair = await generateKeyPair();
    const userId = toUserId(keyPair.publicKey);
    console.log('My user ID:', userId);  // share this with the space creator
    ```

## Adding a user (space creator / admin)

### Step 1 — Register the user in the space

=== "Python"

    ```python
    from reeeductio import Space

    space = Space(
        space_id='S...',
        member_id='U...',   # your own user ID
        private_key=...,
        symmetric_root=...,
        base_url='http://localhost:8000',
    )

    # Add the new user
    space.add_user('U...')   # their user ID
    ```

=== "CLI"

    ```bash
    reeeductio-admin user add U... \
        --space-key <your-private-key-hex> \
        --symmetric-root <symmetric-root-hex>
    ```

### Step 2 — Share the symmetric root

The `symmetric_root` is the shared secret that unlocks encryption for the space. Send it to the new user over a secure channel (e.g. Signal, an encrypted email, or in-person).

!!! warning "Share the symmetric root securely"
    Anyone who has the `symmetric_root` can decrypt all content in the space. Never send it in plaintext over an untrusted channel.

### Step 3 — Assign a role (optional but recommended)

Without a role, a newly added user has no capabilities and can't read or write anything. Assign them a role:

=== "Python"

    ```python
    # First create the role if it doesn't exist yet
    space.create_role('member')
    space.grant_capability_to_role('member', 'read-topics', {'op': 'read', 'path': 'topics/{any}'})
    space.grant_capability_to_role('member', 'post-topics', {'op': 'create', 'path': 'topics/{any}/messages/{any}'})

    # Then assign it
    space.assign_role_to_user('U...', 'member')
    ```

=== "CLI"

    ```bash
    # Create role and grant capabilities
    reeeductio-admin role create member
    reeeductio-admin role grant member --cap-id read-topics --op read --path "topics/{any}"
    reeeductio-admin role grant member --cap-id post-topics --op create --path "topics/{any}/messages/{any}"

    # Assign to user
    reeeductio-admin user assign-role U... --role member
    ```

## The new user connects

Once added, the new user connects using the space ID and the shared `symmetric_root`, plus their own keypair:

=== "Python"

    ```python
    from reeeductio import Space

    space = Space(
        space_id='S...',          # provided by the space creator
        member_id='U...',         # their own user ID
        private_key=...,          # their own private key
        symmetric_root=...,       # shared by the space creator
        base_url='http://localhost:8000',
    )
    msgs = space.get_messages('general')
    ```

=== "TypeScript"

    ```typescript
    import { Space } from 'reeeductio';

    const space = new Space({
      spaceId: 'S...',          // provided by the space creator
      keyPair,                  // their own key pair
      symmetricRoot,            // shared by the space creator
      baseUrl: 'http://localhost:8000',
    });
    const { messages } = await space.getMessages('general');
    ```

## Removing a user

Removing a user revokes their authorization state. They will no longer be able to authenticate with the server.

=== "Python"

    ```python
    # Set their auth entry to empty (marks as removed)
    space.set_plaintext_state(f'auth/users/{user_id}', '')
    ```

=== "CLI"

    ```bash
    reeeductio-admin user remove U...
    ```

!!! note "Encryption keys"
    Removing a user does not rotate the `symmetric_root`. They still have the copy you gave them. If you need to ensure a removed user cannot decrypt future messages, rotate the space's encryption keys by creating a new space and migrating members.

## Granting direct capabilities (without a role)

For one-off permissions, you can grant a capability directly to a user:

=== "Python"

    ```python
    space.grant_capability_to_user(
        user_id='U...',
        cap_id='read-audit-log',
        capability={'op': 'read', 'path': 'topics/audit-log'},
    )
    ```

=== "CLI"

    ```bash
    reeeductio-admin user grant U... \
        --cap-id read-audit-log \
        --op read \
        --path "topics/audit-log"
    ```

## Related

- [Manage Permissions](manage-permissions.md) — in-depth roles and capabilities
- [Tool Accounts](tool-accounts.md) — add bots and service accounts
- [Access Control](../concepts/access-control.md) — concept overview
