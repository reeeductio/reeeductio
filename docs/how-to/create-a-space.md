# Create a Space

This guide walks through generating credentials, connecting to a space for the first time, and saving credentials so you can reconnect later.

## Prerequisites

- The rEEEductio server is running locally. See [Running the Server](../getting-started/running-the-server.md) if you haven't done that.
- The server is configured with `auto_create_spaces: true` (the default dev config). This lets the space be created automatically on first connect.

## 1. Generate credentials

A space is identified by an Ed25519 keypair and a 32-byte symmetric root. Generate both:

=== "Python"

    ```python
    import os
    import json
    from reeeductio.crypto import generate_keypair, to_space_id, to_user_id

    private_key, public_key = generate_keypair()
    symmetric_root = os.urandom(32)

    space_id = to_space_id(public_key)
    user_id  = to_user_id(public_key)

    print('Space ID:       ', space_id)
    print('User ID:        ', user_id)
    print('Private key:    ', private_key.hex())
    print('Symmetric root: ', symmetric_root.hex())

    # Save to a file for later
    creds = {
        'space_id': space_id,
        'user_id': user_id,
        'private_key_hex': private_key.hex(),
        'symmetric_root_hex': symmetric_root.hex(),
    }
    with open('space_creds.json', 'w') as f:
        json.dump(creds, f, indent=2)
    print('Saved to space_creds.json')
    ```

=== "TypeScript"

    ```typescript
    import { writeFileSync } from 'node:fs';
    import { generateKeyPair, toSpaceId, toUserId } from 'reeeductio';

    const keyPair = await generateKeyPair();
    const symmetricRoot = crypto.getRandomValues(new Uint8Array(32));

    const spaceId = toSpaceId(keyPair.publicKey);
    const userId  = toUserId(keyPair.publicKey);

    console.log('Space ID:       ', spaceId);
    console.log('User ID:        ', userId);
    console.log('Private key:    ', Buffer.from(keyPair.privateKey).toString('hex'));
    console.log('Symmetric root: ', Buffer.from(symmetricRoot).toString('hex'));

    const creds = {
      spaceId,
      userId,
      privateKeyHex:     Buffer.from(keyPair.privateKey).toString('hex'),
      publicKeyHex:      Buffer.from(keyPair.publicKey).toString('hex'),
      symmetricRootHex:  Buffer.from(symmetricRoot).toString('hex'),
    };
    writeFileSync('space_creds.json', JSON.stringify(creds, null, 2));
    console.log('Saved to space_creds.json');
    ```

!!! warning "Keep your credentials safe"
    Anyone with your `private_key` and `symmetric_root` has full access to your space.
    Never commit `space_creds.json` to source control.

## 2. Connect (first time)

With `auto_create_spaces: true`, the server creates the space automatically when you first authenticate:

=== "Python"

    ```python
    from reeeductio import Space

    space = Space(
        space_id=space_id,
        member_id=user_id,
        private_key=private_key,
        symmetric_root=symmetric_root,
        base_url='http://localhost:8000',
    )
    # Authentication happens automatically on first API call
    msgs = space.get_messages('general')
    print(f'Space ready. Messages in general: {len(msgs)}')
    ```

=== "TypeScript"

    ```typescript
    import { Space } from 'reeeductio';

    const space = new Space({ spaceId, keyPair, symmetricRoot, baseUrl: 'http://localhost:8000' });
    const { messages } = await space.getMessages('general');
    console.log(`Space ready. Messages in general: ${messages.length}`);
    ```

## 3. Reconnect from saved credentials

=== "Python"

    ```python
    import json
    from reeeductio import Space

    with open('space_creds.json') as f:
        creds = json.load(f)

    space = Space(
        space_id=creds['space_id'],
        member_id=creds['user_id'],
        private_key=bytes.fromhex(creds['private_key_hex']),
        symmetric_root=bytes.fromhex(creds['symmetric_root_hex']),
        base_url='http://localhost:8000',
    )
    ```

=== "TypeScript"

    ```typescript
    import { readFileSync } from 'node:fs';
    import { Space } from 'reeeductio';

    const creds = JSON.parse(readFileSync('space_creds.json', 'utf8'));

    const keyPair = {
      privateKey: Uint8Array.from(Buffer.from(creds.privateKeyHex, 'hex')),
      publicKey:  Uint8Array.from(Buffer.from(creds.publicKeyHex,  'hex')),
    };
    const symmetricRoot = Uint8Array.from(Buffer.from(creds.symmetricRootHex, 'hex'));

    const space = new Space({
      spaceId: creds.spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: 'http://localhost:8000',
    });
    ```

## Without auto_create_spaces

If the server does not have `auto_create_spaces: true`, an admin must register the space first using the admin CLI. See [Self-Hosting](self-hosting.md) for production setup details.

## Next steps

- [Add Users](add-users.md) — invite other people to your space
- [Send Messages](send-messages.md) — post encrypted messages to topics
- [Manage Permissions](manage-permissions.md) — set up roles and capabilities
