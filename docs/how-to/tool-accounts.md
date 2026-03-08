# Tool Accounts

**Tools** are bot or service accounts that authenticate with the server just like users, but without the ability to have roles — every permission must be explicitly granted. Use them for:

- Automated posting bots (alerts, notifications, CI/CD updates)
- Background workers that read or process messages
- Third-party integrations
- Webhook receivers

## Creating a tool account

### Step 1 — Generate a keypair for the tool

Each tool has its own Ed25519 keypair. Generate one and save both keys:

=== "Python"

    ```python
    import os
    from reeeductio.crypto import generate_keypair, to_tool_id

    private_key, public_key = generate_keypair()
    tool_id = to_tool_id(public_key)   # starts with 'T'

    print('Tool ID:      ', tool_id)
    print('Private key:  ', private_key.hex())
    print('Public key:   ', public_key.hex())
    # Store both keys — you need the public key to reconstruct the tool ID later
    ```

=== "TypeScript"

    ```typescript
    import { generateKeyPair, toToolId } from 'reeeductio';

    const keyPair = await generateKeyPair();
    const toolId = toToolId(keyPair.publicKey);  // starts with 'T'

    console.log('Tool ID:     ', toolId);
    console.log('Private key: ', Buffer.from(keyPair.privateKey).toString('hex'));
    console.log('Public key:  ', Buffer.from(keyPair.publicKey).toString('hex'));
    ```

### Step 2 — Register the tool in the space (as admin)

=== "Python"

    ```python
    from reeeductio import Space

    space = Space(
        space_id='S...',
        member_id='U...',   # your user ID (admin)
        private_key=...,
        symmetric_root=...,
        base_url='http://localhost:8000',
    )

    space.create_tool('T...')   # the tool's T-prefixed ID
    ```

=== "CLI"

    ```bash
    reeeductio-admin tool add T... \
        --space-key <your-private-key-hex> \
        --symmetric-root <symmetric-root-hex>
    ```

### Step 3 — Grant capabilities to the tool

Tools have no permissions by default. Grant exactly what they need:

=== "Python"

    ```python
    # Allow the tool to post to the alerts topic
    space.grant_capability_to_tool(
        tool_id='T...',
        cap_id='post-alerts',
        capability={'op': 'create', 'path': 'topics/alerts/messages/{any}'},
    )

    # Allow the tool to read all topics (e.g. for a read-only bot)
    space.grant_capability_to_tool(
        tool_id='T...',
        cap_id='read-all',
        capability={'op': 'read', 'path': 'topics/{any}'},
    )
    ```

=== "CLI"

    ```bash
    reeeductio-admin tool grant T... \
        --cap-id post-alerts \
        --op create \
        --path "topics/alerts/messages/{any}"
    ```

## Using a tool account in code

Tools authenticate and make API calls exactly like users. Pass the tool's private key, its public key, and the `symmetric_root` to your bot process:

=== "Python"

    ```python
    import os
    from reeeductio import Space
    from reeeductio.crypto import to_tool_id

    # Load credentials from environment
    tool_private_key  = bytes.fromhex(os.environ['TOOL_PRIVATE_KEY'])
    tool_public_key   = bytes.fromhex(os.environ['TOOL_PUBLIC_KEY'])
    symmetric_root    = bytes.fromhex(os.environ['SYMMETRIC_ROOT'])
    space_id          = os.environ['SPACE_ID']

    tool_id = to_tool_id(tool_public_key)

    space = Space(
        space_id=space_id,
        member_id=tool_id,
        private_key=tool_private_key,
        symmetric_root=symmetric_root,
        base_url='https://your-server.example.com',
    )

    # Post an alert
    space.post_encrypted_message('alerts', 'alert.info', b'Build succeeded!')
    ```

=== "TypeScript"

    ```typescript
    import { Space, toToolId, stringToBytes } from 'reeeductio';

    const privateKey    = Uint8Array.from(Buffer.from(process.env.TOOL_PRIVATE_KEY!, 'hex'));
    const publicKey     = Uint8Array.from(Buffer.from(process.env.TOOL_PUBLIC_KEY!, 'hex'));
    const symmetricRoot = Uint8Array.from(Buffer.from(process.env.SYMMETRIC_ROOT!, 'hex'));
    const spaceId       = process.env.SPACE_ID!;

    const keyPair = { privateKey, publicKey };
    const toolId  = toToolId(publicKey);

    const space = new Space({ spaceId, keyPair, symmetricRoot, baseUrl: 'https://your-server.example.com' });

    await space.postEncryptedMessage('alerts', 'alert.info', stringToBytes('Build succeeded!'));
    ```

## Storing tool credentials safely

Never hardcode credentials. Use your platform's secrets manager:

| Platform | Recommended approach |
|----------|---------------------|
| Docker / Compose | `secrets:` block or `.env` file |
| Kubernetes | `Secret` objects, mounted as env vars |
| GitHub Actions | Encrypted Actions secrets |
| AWS | Secrets Manager or Parameter Store |
| Cloud Run | Secret Manager |

The bot needs four values: `TOOL_PRIVATE_KEY`, `TOOL_PUBLIC_KEY`, `SYMMETRIC_ROOT`, `SPACE_ID`.

## Removing a tool

=== "Python"

    ```python
    space.set_plaintext_state(f'auth/tools/{tool_id}', '')
    ```

=== "CLI"

    ```bash
    reeeductio-admin tool remove T...
    ```

After removal, the tool's authentication attempts will be rejected by the server.

## Example: CI/CD notification bot (GitHub Actions)

```yaml
- name: Notify rEEEductio
  env:
    TOOL_PRIVATE_KEY: ${{ secrets.REEEDUCTIO_TOOL_PRIVATE_KEY }}
    TOOL_PUBLIC_KEY:  ${{ secrets.REEEDUCTIO_TOOL_PUBLIC_KEY }}
    SYMMETRIC_ROOT:   ${{ secrets.REEEDUCTIO_SYMMETRIC_ROOT }}
    SPACE_ID:         ${{ secrets.REEEDUCTIO_SPACE_ID }}
  run: |
    pip install reeeductio
    python - <<'EOF'
    import os
    from reeeductio import Space
    from reeeductio.crypto import to_tool_id

    tool_id = to_tool_id(bytes.fromhex(os.environ['TOOL_PUBLIC_KEY']))
    space = Space(
        space_id=os.environ['SPACE_ID'],
        member_id=tool_id,
        private_key=bytes.fromhex(os.environ['TOOL_PRIVATE_KEY']),
        symmetric_root=bytes.fromhex(os.environ['SYMMETRIC_ROOT']),
        base_url='https://your-server.example.com',
    )
    space.post_encrypted_message('alerts', 'ci.deploy', b'Deployed to production!')
    EOF
```

## Related

- [Add Users](add-users.md) — adding human members
- [Manage Permissions](manage-permissions.md) — roles and capabilities in depth
- [Access Control](../concepts/access-control.md) — concept overview
