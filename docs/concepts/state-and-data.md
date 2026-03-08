# State & Data

Beyond messages, rEEEductio provides two lighter-weight storage primitives: **State** and **Data**. Both live inside a space, both are encrypted, and both are designed for structured metadata rather than conversation streams.

## State — event-sourced paths

State is a key-value store where each path has a **history**. Every write creates a new entry in an append-only event log, so you can always look back at what a value was at any point in time.

Think of it like a Git repository for your configuration: you see the current value at HEAD, but the full history is always there.

### What state is good for

- User profiles and preferences
- Access control lists (who has what role)
- Application configuration
- Audit logs of setting changes

### State paths

Paths use a slash-separated hierarchy (e.g. `profiles/alice`, `config/feature-flags`). The current value at a path is the most recent write to that path.

!!! note
    State paths are different from topic IDs. They can contain slashes and are not subject to the same character restrictions as topic names.

### Reading and writing state

=== "Python"

    ```python
    # Store a user profile (plaintext)
    space.set_plaintext_state('profiles/alice', '{"name": "Alice", "role": "admin"}')

    # Read it back
    profile_json = space.get_plaintext_state('profiles/alice')
    print(profile_json)  # {"name": "Alice", "role": "admin"}
    ```

=== "TypeScript"

    ```typescript
    import { stringToBytes, bytesToString } from 'reeeductio';

    // Store a user profile (plaintext)
    await space.setPlaintextState('profiles/alice', stringToBytes('{"name": "Alice", "role": "admin"}'));

    // Read it back
    const profileBytes = await space.getPlaintextState('profiles/alice');
    console.log(bytesToString(profileBytes));
    ```

### Encrypted state

For sensitive values (tokens, private settings), use the encrypted variants. The SDK uses `stateKey` (derived from `symmetricRoot`) to encrypt client-side before sending:

=== "Python"

    ```python
    # Store encrypted
    space.set_encrypted_state('secrets/api-key', b'my-secret-value')

    # Read and decrypt
    value = space.get_encrypted_state('secrets/api-key')
    ```

=== "TypeScript"

    ```typescript
    // Store encrypted
    await space.setEncryptedState('secrets/api-key', stringToBytes('my-secret-value'));

    // Read and decrypt
    const value = await space.getEncryptedState('secrets/api-key');
    ```

### State history

Since state is event-sourced, you can retrieve the full change history:

=== "Python"

    ```python
    history = space.get_state_history()
    for entry in history.messages:
        print(entry.path, entry.server_timestamp)
    ```

=== "TypeScript"

    ```typescript
    const history = await space.getStateHistory();
    for (const entry of history.messages) {
      console.log(entry.path, entry.server_timestamp);
    }
    ```

---

## Data — lightweight key-value pairs

Data is a simpler, flat key-value store. Each entry is a single value at a path, with no history. It's optimized for values that change frequently and where you only ever care about the latest value.

Each data entry is **signed** by the writer, so you can verify authenticity, but it is not chained — there's no `prev_hash`.

### What data is good for

- Presence and availability status
- Ephemeral metadata (e.g. "user is typing")
- Counters and cursors
- Short-lived configuration flags

### Reading and writing data

=== "Python"

    ```python
    # Set a value
    space.set_data('presence/alice', b'online')

    # Read it back
    entry = space.get_data('presence/alice')
    print(entry.value)
    ```

=== "TypeScript"

    ```typescript
    import { stringToBytes } from 'reeeductio';

    // Set a value
    await space.setData('presence/alice', stringToBytes('online'));

    // Read it back
    const entry = await space.getData('presence/alice');
    ```

---

## State vs. Data — which to use?

| | State | Data |
|---|---|---|
| History | Full history preserved | Latest value only |
| Integrity | Hash-chained, tamper-evident | Signed, no chain |
| Encryption | Optional (plaintext or encrypted) | Signed; encryption optional |
| Best for | Config, profiles, audit logs | Presence, ephemeral metadata |

When in doubt: if you might ever want to know what the value *was* at some point in the past, use **State**. If you only care about the current value, use **Data**.

## Related concepts

- [Spaces](spaces.md) — State and Data both live inside a space
- [Topics & Messages](topics-and-messages.md) — for ordered event streams and chat
- [Blobs](blobs.md) — for large binary payloads
