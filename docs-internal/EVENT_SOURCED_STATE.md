# Event-Sourced State Architecture

## Overview

This document describes the event-sourced state management architecture implemented in the Reeeductio backend. In this design, **messages are the source of truth**, and the state store serves as a materialized view (cache) for performance.

## Core Principles

### 1. Messages as Source of Truth

State changes are represented as messages in the `state` topic. The message chain provides:
- **Immutable audit log** - Every state change is recorded
- **Causal ordering** - Changes are sequenced via prev_hash references
- **Conflict detection** - Concurrent writes are detected via chain validation
- **Replay capability** - State can be reconstructed by replaying events

### 2. State Store as Cache

The state store (`StateStore` implementations) provides:
- **Fast lookups** - O(1) access to current state by path
- **Query capabilities** - List states by prefix, range queries
- **Eventual consistency** - Synchronized with message chain

The state store can be rebuilt at any time by replaying the state topic.

### 3. Dual Authorization

State modifications via the state topic require two levels of authorization:

1. **Topic-level**: Can the user post to the `state` topic?
2. **State-level**: Can the user create/modify/delete that specific state path?

This prevents privilege escalation where a user with limited state access tries to modify unauthorized paths.

## Architecture

### Message Structure for State Events

State changes are posted as messages to the `state` topic with this structure:

```python
{
    "message_hash": "M_...",      # Unique message identifier
    "type": "/auth/users/U_alice", # State path (stored in type field)
    "data": "base64_encoded_data", # State content (empty string for deletion)
    "sender": "U_admin",           # Who made the change
    "signature": "base64_sig",     # Message signature
    "prev_hash": "M_...",          # Previous message hash (for chain)
    "server_timestamp": 1234567890 # When change was committed
}
```

**Key design decisions:**
- State path is stored in the `type` field
- Empty `data` ("") indicates deletion
- Non-empty `data` indicates set/create operation

### State Store Schema

The state store maintains the current state with metadata:

```python
{
    "path": "/auth/users/U_alice",
    "data": "base64_encoded_data",
    "signature": "base64_sig",
    "signed_by": "U_admin",
    "signed_at": 1234567890
}
```

## Implementation Details

### Writing State Changes

There are two paths for writing state:

#### Path 1: Direct State API (`set_state()`, `delete_state()`)

Used by server initialization and legacy code:

```python
space.set_state(path, data, token, signature, signed_by, signed_at)
```

This performs **dual write**:
1. Writes to state topic (source of truth)
2. Writes to state store (cache)

Implementation in [space.py:442-523](backend/space.py#L442-L523):

```python
def set_state(self, path: str, data: str, token: str,
              signature: str, signed_by: str, signed_at: int) -> None:
    # 1. Verify signature
    self.crypto.verify_state_signature(...)

    # 2. Check authorization
    if not self.check_permission(signed_by, operation, path):
        raise ValueError(f"No {operation} permission for path: {path}")

    # 3. Write to message store (source of truth)
    message_hash = self.compute_message_hash(...)
    self.message_store.add_message(
        space_id=self.space_id,
        topic_id="state",
        message_hash=message_hash,
        msg_type=path,  # Path goes in type field
        ...
    )

    # 4. Write to state store (cache)
    self.state_store.set_state(...)
```

#### Path 2: Message API (`post_message()`)

Used by clients to modify state:

```python
await space.post_message(
    topic_id="state",
    message_hash=computed_hash,
    msg_type=state_path,
    data=base64_data,
    ...
)
```

This performs **single write** to the message chain, then updates cache.

Implementation in [space.py:677-766](backend/space.py#L677-L766):

```python
async def post_message(self, topic_id: str, message_hash: str,
                       msg_type: str, prev_hash: str, data: str,
                       signature: str, token: str) -> int:
    # 1. Authenticate user
    user = self._verify_jwt(token)
    sender = user["id"]

    # 2. Verify message signature
    self.crypto.verify_message_signature(...)

    # 3. Check topic-level permission
    if not self.check_permission(sender, "create", topic_path):
        raise ValueError("No post permission")

    # 4. For state, also check state-level permission
    if topic_id == "state":
        path = msg_type  # Path is in type field

        # Determine operation: create, modify, or delete
        if data:
            existing = self.state_store.get_state(self.space_id, path)
            operation = "modify" if existing else "create"
        else:
            operation = "delete"

        # Check permission for specific state path
        if not self.check_permission(sender, operation, path):
            raise ValueError(f"No {operation} permission for state path: {path}")

    # 5. Write to message chain (source of truth)
    self.message_store.add_message(...)

    # 6. Update state cache if this is a state event
    if topic_id == "state":
        self._apply_state_event({
            "type": msg_type,
            "data": data,
            "sender": sender,
            "signature": signature,
            "server_timestamp": server_timestamp
        })
```

### Applying State Events

The `_apply_state_event()` helper updates the state cache without re-authorizing:

Implementation in [space.py:569-600](backend/space.py#L569-L600):

```python
def _apply_state_event(self, message: Dict[str, Any]) -> None:
    """
    Apply a state event to the state store (internal use only).

    Does NOT perform authorization checks since the message
    has already been validated and committed to the chain.
    """
    path = message["type"]
    data = message["data"]

    if data:
        # Set operation (non-empty data)
        self.state_store.set_state(
            space_id=self.space_id,
            path=path,
            data=data,
            signature=message["signature"],
            signed_by=message["sender"],
            signed_at=message["server_timestamp"]
        )
    else:
        # Delete operation (empty data)
        self.state_store.delete_state(self.space_id, path)
```

**Important**: This method does NOT check authorization because:
- The message has already passed authorization checks in `post_message()`
- The message is committed to the immutable chain
- We're just synchronizing the cache

### State Reconstruction

The state store can be rebuilt by replaying the state topic:

```python
def rebuild_state_from_events(space_id: str, message_store, state_store):
    """Rebuild state store by replaying state topic"""
    # Get all state events in order
    events = message_store.get_messages(space_id, "state")

    # Apply each event in sequence
    for event in events:
        path = event["type"]
        data = event["data"]

        if data:
            # Set operation
            state_store.set_state(
                space_id=space_id,
                path=path,
                data=data,
                signature=event["signature"],
                signed_by=event["sender"],
                signed_at=event["server_timestamp"]
            )
        else:
            # Delete operation
            state_store.delete_state(space_id, path)
```

See test in [test_state_events.py:144-175](backend/tests/test_state_events.py#L144-L175).

## Security Model

### Operation Types

State authorization uses three operation types:

- **`create`**: Creating new state that doesn't exist
- **`modify`**: Updating existing state
- **`delete`**: Removing existing state

The operation is determined in [space.py:739-748](backend/space.py#L739-L748):

```python
if data:
    existing = self.state_store.get_state(self.space_id, path)
    operation = "modify" if existing else "create"
else:
    operation = "delete"
```

### Capability Format

Capabilities grant permissions for operations on path patterns:

```python
{
    "op": "modify",                    # Operation: create, modify, delete
    "path": "profiles/U_alice/{...}"  # Path pattern ({...} is wildcard)
}
```

Stored at: `auth/users/{user_id}/rights/{capability_id}`

### Privilege Escalation Prevention

The dual authorization prevents privilege escalation attacks:

**Attack scenario**: User with `profiles/{user_id}/*` permission tries to grant themselves `auth/*` permission.

**Prevention**:
1. User can post to `state` topic (has topic-level capability)
2. User tries to create state at `auth/users/{user_id}/rights/cap_admin`
3. State-level check fails: user lacks `create` permission for `auth/` paths
4. Message is rejected before being committed to chain

See test in [test_state_events.py:443-536](backend/tests/test_state_events.py#L443-L536).

## Conflict Detection

### Chain Validation

The message store enforces chain integrity via compare-and-swap:

```python
def add_message(self, space_id, topic_id, message_hash,
                msg_type, prev_hash, ...):
    # Get current chain head
    current_head = self.get_chain_head(space_id, topic_id)

    # Verify prev_hash matches current head
    if current_head and prev_hash != current_head["message_hash"]:
        raise ChainConflictError(
            f"Chain conflict: prev_hash={prev_hash} but "
            f"expected prev_hash={current_head['message_hash']}"
        )

    # Atomic write with chain validation
    # (Implementation varies by backend)
```

### Handling Conflicts

When a client encounters a conflict:

1. Get the new chain head
2. Re-validate the operation against current state
3. Retry with updated `prev_hash`

This ensures serializability of state modifications.

## Testing

### Test Coverage

The event-sourced state implementation is verified by:

1. **Dual write tests** ([test_state_events.py:25-142](backend/tests/test_state_events.py#L25-L142))
   - Verify `set_state()` writes to both topic and store
   - Verify `delete_state()` writes deletion events

2. **Replay tests** ([test_state_events.py:144-175](backend/tests/test_state_events.py#L144-L175))
   - Reconstruct state from events
   - Verify consistency with direct state API

3. **Integration tests** ([test_state_events.py:324-384](backend/tests/test_state_events.py#L324-L384))
   - Verify `post_message()` updates state cache
   - End-to-end message → state flow

4. **Security tests** ([test_state_events.py:386-536](backend/tests/test_state_events.py#L386-L536))
   - Block unauthorized state modifications
   - Prevent privilege escalation attacks

5. **Conflict detection tests** ([test_state_events.py:263-321](backend/tests/test_state_events.py#L263-L321))
   - Verify ChainConflictError on wrong prev_hash
   - Ensure chain integrity

### Running Tests

```bash
# All state events tests
uv run pytest backend/tests/test_state_events.py -v

# Specific security test
uv run pytest backend/tests/test_state_events.py::test_post_message_privilege_escalation_blocked -v

# Chain conflict test
uv run pytest backend/tests/test_state_events.py::test_chain_conflict_detection -v
```

## Benefits

### 1. Auditability
Every state change is recorded with:
- Who made the change (`sender`)
- When it was made (`server_timestamp`)
- What changed (`data`)
- Why it was allowed (implicit from authorization checks)

### 2. Consistency
- Chain validation prevents race conditions
- CAS operations ensure atomic updates
- No lost updates even with concurrent clients

### 3. Flexibility
- State store can be rebuilt from events
- Multiple materialized views possible (cache, search index, analytics)
- Event replay enables time-travel debugging

### 4. Security
- Dual authorization prevents privilege escalation
- Immutable audit log detects tampering
- Cryptographic signatures verify authenticity

### 5. Performance
- State cache provides fast reads
- Write-through cache keeps cache synchronized
- No need to scan message history for current state

## Migration Path

### For Existing Code

Existing code using the state API continues to work:

```python
# This still works
space.set_state(path, data, token, signature, signed_by, signed_at)
space.delete_state(path, token)
```

These methods perform dual writes to maintain consistency.

### For New Code

New client code should use the message API:

```python
# Compute message hash
message_hash = compute_message_hash(
    space_id=space_id,
    topic_id="state",
    prev_hash=chain_head,
    encrypted_payload=data,
    sender=user_id
)

# Sign message
signature = sign_message(message_hash, private_key)

# Post to state topic
await space.post_message(
    topic_id="state",
    message_hash=message_hash,
    msg_type=state_path,
    prev_hash=chain_head,
    data=data,
    signature=signature,
    token=jwt_token
)
```

This provides:
- Better concurrency handling (explicit prev_hash)
- Client-side conflict detection
- Integration with message streaming

## Future Enhancements

### 1. State Snapshots

Periodically create state snapshots to speed up reconstruction:

```python
# Instead of replaying all events from beginning:
snapshot = load_snapshot(space_id, snapshot_id)
events_since = get_messages_since(snapshot.last_message_hash)
replay(events_since)
```

### 2. Event Compaction

Compact old events while preserving audit trail:

```python
# Keep: Latest state + last N changes + snapshots
# Archive: Older events to cold storage
# Delete: Never (audit requirement)
```

### 3. Read Replicas

Create read-only replicas for scaling:

```python
# Primary: Handles writes, updates state cache
# Replicas: Subscribe to state, maintain read-only cache
# Benefit: Horizontal read scaling
```

### 4. Change Notifications

Notify clients of state changes via WebSocket:

```python
# Client subscribes to state path pattern
subscribe("auth/users/{user_id}/*")

# Server pushes state matching pattern
on_state_event(event => {
    update_local_cache(event)
    trigger_ui_update()
})
```

## Related Files

- [backend/space.py](backend/space.py) - Space class with state methods
- [backend/tests/test_state_events.py](backend/tests/test_state_events.py) - Test suite
- [backend/message_store.py](backend/message_store.py) - MessageStore interface
- [backend/state_store.py](backend/state_store.py) - StateStore interface
- [backend/exceptions.py](backend/exceptions.py) - ChainConflictError definition
- [backend/sqlite_message_store.py](backend/sqlite_message_store.py) - SQLite implementation
- [backend/firestore_message_store.py](backend/firestore_message_store.py) - Firestore implementation

## References

- [Event Sourcing Pattern](https://martinfowler.com/eaaDev/EventSourcing.html)
- [CQRS Pattern](https://martinfowler.com/bliki/CQRS.html)
- [Capability-Based Security](https://en.wikipedia.org/wiki/Capability-based_security)
