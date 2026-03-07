# Chain Validation with Compare-and-Swap

## Overview

This document describes the compare-and-swap (CAS) implementation for message chain validation in the Reeeductio backend. This mechanism prevents race conditions and ensures message chain integrity when multiple clients or server instances attempt to add messages concurrently.

## Problem Statement

### Race Condition Without CAS

Without chain validation, a race condition can occur:

```
Time    Client A                    Client B
----    --------                    --------
t1      Get chain head: hash_1
t2                                  Get chain head: hash_1
t3      Post message_A
        (prev_hash=hash_1)
t4                                  Post message_B
                                    (prev_hash=hash_1)  ← CONFLICT!
```

Both clients see `hash_1` as the chain head and try to append to it. Without validation:
- Both messages get written
- Both claim `prev_hash=hash_1`
- Chain forks (broken invariant)

### Impact

A forked chain breaks critical assumptions:
- **Ordering ambiguity**: Which message came first?
- **State inconsistency**: If these are state events, which state is current?
- **Audit integrity**: The immutable log is corrupted

## Solution: Compare-and-Swap (CAS)

### Principle

Compare-and-swap is an atomic operation that:
1. **Reads** the current chain head
2. **Compares** it to the expected value (prev_hash)
3. **Swaps** (writes new message) only if they match
4. **Fails** if they don't match

This is done atomically within a transaction.

### Implementation

#### SQLite Implementation

File: [backend/sql_message_store.py](backend/sql_message_store.py)

```python
def add_message(self, space_id, topic_id, message_hash, prev_hash, ...):
    """Add message with atomic chain validation"""
    from exceptions import ChainConflictError

    with self.get_connection() as conn:
        cursor = conn.cursor()

        # 1. Read current chain head (within transaction)
        cursor.execute("""
            SELECT message_hash
            FROM messages
            WHERE space_id = ? AND topic_id = ?
            ORDER BY server_timestamp DESC
            LIMIT 1
        """, (space_id, topic_id))

        row = cursor.fetchone()
        current_head = row["message_hash"] if row else None

        # 2. Compare: Does prev_hash match current head?
        if current_head != prev_hash:
            raise ChainConflictError(
                f"Chain conflict: expected prev_hash={current_head}, "
                f"got {prev_hash}"
            )

        # 3. Swap: Write new message (we own the chain head)
        cursor.execute("""
            INSERT INTO messages (...)
            VALUES (...)
        """, (...))

        # Transaction commits on context exit
```

**Key points:**
- The transaction provides atomicity (all-or-nothing)
- Read and write happen in same transaction (no gap)
- SQLite's transaction isolation prevents concurrent modifications

#### Firestore Implementation

File: [backend/firestore_message_store.py](backend/firestore_message_store.py)

```python
def add_message(self, space_id, topic_id, message_hash, prev_hash, ...):
    """Add message with atomic chain validation"""
    from exceptions import ChainConflictError

    @firestore.transactional
    def add_message_transaction(transaction):
        # 1. Read current chain head (within transaction)
        topic_ref = db.collection('spaces').document(space_id) \
                     .collection('topics').document(topic_id)

        topic_doc = topic_ref.get(transaction=transaction)

        if topic_doc.exists:
            current_head = topic_doc.to_dict().get('chain_head')
        else:
            current_head = None

        # 2. Compare: Does prev_hash match current head?
        if current_head != prev_hash:
            raise ChainConflictError(
                f"Chain conflict: expected prev_hash={current_head}, "
                f"got {prev_hash}"
            )

        # 3. Swap: Write new message and update chain head
        msg_ref = ...
        transaction.set(msg_ref, {...})
        transaction.set(topic_ref, {'chain_head': message_hash}, merge=True)

    # Execute transaction with automatic retry on conflict
    transaction = self.db.transaction()
    add_message_transaction(transaction)
```

**Key points:**
- Firestore's `@firestore.transactional` provides atomicity
- Transaction reads and writes are isolated
- Firestore automatically retries on transient conflicts

## Conflict Detection

### ChainConflictError Exception

Defined in [backend/exceptions.py](backend/exceptions.py):

```python
class ChainConflictError(Exception):
    """
    Raised when a message's prev_hash doesn't match the current chain head.

    This indicates a concurrent write conflict - another message was added
    to the topic between when the client got the chain head and when they
    tried to add their message.

    Client should:
    1. Get the new chain head
    2. Re-validate their operation against current state
    3. Retry with the new prev_hash
    """
    pass
```

### Error Message Format

```
Chain conflict in topic 'general': expected prev_hash=M_abc123...,
got M_xyz789.... Another message was added concurrently.
```

The error includes:
- Topic where conflict occurred
- Expected prev_hash (current chain head)
- Received prev_hash (from client's request)
- Truncated hashes for readability (first 16 chars + "...")

## Client Handling

### Retry Pattern

When a client encounters a `ChainConflictError`:

```python
def post_message_with_retry(space, topic_id, payload, max_retries=3):
    """Post message with automatic retry on conflict"""

    for attempt in range(max_retries):
        try:
            # 1. Get current chain head
            head = space.get_chain_head(topic_id)
            prev_hash = head["message_hash"] if head else None

            # 2. Compute message hash with current prev_hash
            message_hash = compute_message_hash(
                space_id=space.space_id,
                topic_id=topic_id,
                prev_hash=prev_hash,
                encrypted_payload=payload,
                sender=user_id
            )

            # 3. Sign message
            signature = sign_message(message_hash, private_key)

            # 4. Attempt to post
            await space.post_message(
                topic_id=topic_id,
                message_hash=message_hash,
                prev_hash=prev_hash,
                data=payload,
                signature=signature,
                token=jwt_token
            )

            # Success!
            return message_hash

        except ChainConflictError:
            # Another client posted first - retry with new head
            if attempt == max_retries - 1:
                raise  # Final attempt failed
            continue

    raise RuntimeError("Failed to post message after retries")
```

### Important: Re-validate State

For state-modifying operations, the client MUST re-validate against current state:

```python
for attempt in range(max_retries):
    try:
        # Get current state
        current_state = space.get_state(path)

        # Re-validate operation is still valid
        if current_state and not can_modify(current_state):
            raise ValueError("State changed - operation no longer valid")

        # ... post message ...

    except ChainConflictError:
        continue  # Retry with updated state
```

**Why this matters:**
- Client A reads state at time t1
- Client B modifies state at time t2
- Client A's planned modification may no longer be valid
- Must re-check current state before retrying

## Benefits

### 1. Consistency

CAS ensures **serializability** of message additions:
- Messages form a single, linear chain
- No forks or branches
- Total ordering of all messages in a topic

### 2. Conflict Detection

Immediate detection of concurrent writes:
- Client knows instantly if another client posted first
- No silent data loss
- No "last write wins" semantics (which lose data)

### 3. Correctness

Preserves critical invariants:
- Each message (except first) has exactly one predecessor
- Each message (except last) has exactly one successor
- Chain can be traversed from any point

### 4. Atomicity

Transaction guarantees:
- Either message is added successfully, or nothing changes
- No partial writes
- No inconsistent state between message store and chain head

## Performance Considerations

### Throughput Impact

CAS adds a read before each write:
- **SQLite**: Minimal impact (local database, fast reads)
- **Firestore**: One additional document read per transaction

### Contention

High write contention on a single topic:
- Multiple clients trying to append simultaneously
- More conflicts → more retries
- Effective throughput decreases

**Mitigation strategies:**
1. **Partition topics**: Use separate topics for independent conversations
2. **Batching**: Accumulate multiple messages before posting (where appropriate)
3. **Exponential backoff**: Add jitter to retry delays to reduce thundering herd

### Scalability

- **Vertical**: CAS scales with database transaction throughput
- **Horizontal**: Each topic is an independent chain (no cross-topic contention)
- **Firestore advantage**: Distributed transactions scale better than single SQLite file

## Testing

### Test Coverage

File: [backend/tests/test_chain_conflict.py](backend/tests/test_chain_conflict.py)

1. **Basic conflict detection**:
   - Add first message
   - Try to add second message with `prev_hash=None`
   - Verify `ChainConflictError` raised
   - Verify first message remains, second rejected

2. **Multi-message chain**:
   - Build chain of 3 messages
   - Try to add message with old `prev_hash`
   - Verify conflict detected

3. **Chain head after conflict**:
   - Add message successfully
   - Attempt conflicting message (rejected)
   - Verify chain head unchanged
   - Add valid message
   - Verify chain head updated

### Running Tests

```bash
# Chain conflict tests
uv run pytest backend/tests/test_chain_conflict.py -v

# All message storage tests (includes chain tests)
uv run pytest backend/tests/test_message_storage.py -v

# Firestore tests (requires emulator)
docker-compose up -d firestore-emulator
uv run pytest backend/tests/test_firestore_stores.py -v
```

## Comparison with Other Approaches

### Alternative 1: Last Write Wins (LWW)

```python
# No validation - just write
INSERT INTO messages (...) VALUES (...)
```

**Problems:**
- Silent conflicts (no error)
- Data loss (earlier write disappears)
- Chain can fork
- No consistency guarantee

### Alternative 2: Lock-Based

```python
# Acquire lock
with topic_lock:
    current_head = get_chain_head()
    if current_head != prev_hash:
        raise ConflictError
    add_message(...)
```

**Problems:**
- Requires distributed lock manager (complex)
- Lock contention reduces throughput
- Deadlock risk
- Lock timeouts are hard to tune

### Why CAS is Better

- **No distributed coordination**: Database provides atomicity
- **No locks**: No deadlock risk, no timeout tuning
- **Optimistic**: No blocking on read, only on write
- **Simple**: Leverages existing database transaction semantics

## Future Enhancements

### 1. Batch Append

Allow appending multiple messages in one transaction:

```python
def add_messages_batch(
    space_id: str,
    topic_id: str,
    messages: List[Message]
) -> None:
    """Add multiple messages atomically"""

    # All messages must form a valid chain segment
    # First message's prev_hash must match current head
    # Each subsequent message's prev_hash must match previous message's hash
```

Benefits:
- Reduced transaction overhead
- Higher throughput for bulk operations
- Fewer conflicts (one CAS check instead of N)

### 2. Conditional Writes

Allow writes with custom predicates:

```python
def add_message_if(
    ...,
    condition: Callable[[Message], bool]
) -> None:
    """Add message only if condition(current_head) is True"""
```

Use cases:
- "Only append if topic has < 1000 messages"
- "Only append if last message is from different sender"
- Advanced state validation

### 3. Conflict Metrics

Track conflict rates for monitoring:

```python
class MessageStore:
    def get_conflict_stats(self, space_id, topic_id):
        """Return conflict statistics for a topic"""
        return {
            "total_attempts": 1000,
            "conflicts": 50,
            "conflict_rate": 0.05,
            "avg_retries": 1.2
        }
```

Use for:
- Identifying hot topics (high contention)
- Tuning retry strategies
- Capacity planning

## Related Files

- [backend/exceptions.py](backend/exceptions.py) - `ChainConflictError` definition
- [backend/sql_message_store.py](backend/sql_message_store.py) - SQLite CAS implementation
- [backend/firestore_message_store.py](backend/firestore_message_store.py) - Firestore CAS implementation
- [backend/tests/test_chain_conflict.py](backend/tests/test_chain_conflict.py) - CAS test suite

## References

- [Compare-and-swap (Wikipedia)](https://en.wikipedia.org/wiki/Compare-and-swap)
- [Optimistic Concurrency Control](https://en.wikipedia.org/wiki/Optimistic_concurrency_control)
- [Firestore Transactions](https://cloud.google.com/firestore/docs/manage-data/transactions)
- [SQLite Transaction Isolation](https://www.sqlite.org/isolation.html)
