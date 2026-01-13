# Unified Namespace for Authorization

## Overview

The authorization system now uses a unified namespace with resource type prefixes for all capability paths. This provides a consistent, extensible way to control access to different types of resources in the system.

## Resource Types

All capability paths MUST start with one of these prefixes:

- `state/{path}` - State paths (auth/users/..., profiles/..., etc.)
- `data/{path}` - Data storage paths (key-value store)
- `topics/{topic}` - Message topic access
- `blobs/{blob_id}` - Blob storage access

## Examples

### State Access

```python
# Grant read access to a user's own profile state
{
    "op": "read",
    "path": "state/profiles/{self}/{...}"
}

# Grant write access to auth system (admin capability)
{
    "op": "write",
    "path": "state/auth/{...}"
}

# Grant capability to grant other capabilities
{
    "op": "create",
    "path": "state/auth/users/{any}/rights/{...}"
}
```

### Data Access

```python
# Grant read access to user's own data
{
    "op": "read",
    "path": "data/user-data/{self}/{...}",
    "must_be_owner": true
}

# Grant write access to shared data
{
    "op": "write",
    "path": "data/shared/{...}"
}
```

### Message Access

```python
# Grant read access to a specific topic
{
    "op": "read",
    "path": "topics/general"
}

# Grant write access to any topic
{
    "op": "write",
    "path": "topics/{any}"
}

# Grant read access to all topics
{
    "op": "read",
    "path": "topics/{...}"
}
```

### Blob Access

```python
# Grant read access to all blobs
{
    "op": "read",
    "path": "blobs/{...}"
}

# Grant ability to upload blobs
{
    "op": "create",
    "path": "blobs/{...}"
}

# Grant ability to delete own blobs
{
    "op": "delete",
    "path": "blobs/{...}",
    "must_be_owner": true
}
```

## Ownership Verification

The `must_be_owner` flag works differently for each resource type:

### State Resources
Ownership is verified by checking the `sender` field in the state entry (message).

### Data Resources
Ownership is verified by checking the `signed_by` field in the data entry.

### Blob Resources
Ownership is verified by checking if the user has a reference to the blob in the blob metadata. Blobs can have multiple owners (references), and "deleting" a blob only removes your reference to it.

### Message Resources
Messages don't support ownership verification (they're immutable). Using `must_be_owner: true` with messages will always fail.

## Wildcards

The same wildcard rules apply across all resource types:

- `{self}` - Matches the user's own ID
- `{any}` - Matches exactly one path segment
- `{other}` - Matches any ID except the user's own ID
- `{...}` - Matches any remaining path segments (rest wildcard)

## Migration Guide

### Old Format (State Only)
```python
# Old: implicit state prefix
{
    "op": "read",
    "path": "profiles/{self}/{...}"
}
```

### New Format (Unified Namespace)
```python
# New: explicit resource type prefix
{
    "op": "read",
    "path": "state/profiles/{self}/{...}"
}
```

### Migration Steps

1. **Update capability definitions**: Add `state/` prefix to all existing capability paths
2. **Update permission checks**: Ensure all `check_permission()` calls use prefixed paths
3. **Update tests**: Add resource type prefixes to all test capabilities

## Implementation Notes

### Important: When to Use Prefixes

**Resource type prefixes are used in:**
1. **Capability patterns** - When defining what a capability grants access to
2. **Permission checks** - When checking if a user has permission for a resource

**Resource type prefixes are NOT used in:**
1. **Actual data/state paths** - The paths stored in state_store, data_store, etc.
2. **User-created paths** - Paths provided by users when creating/modifying data

### Example: State Operations

```python
# User creates a state entry at path "profiles/alice"
# (no prefix - this is the actual path within the state namespace)
space.set_state(path="profiles/alice", data=..., token=...)

# Internally, permission is checked with the prefix
authz.check_permission(space_id, user_id, "create", "state/profiles/alice")

# The capability that grants this permission uses the prefix
capability = {
    "op": "create",
    "path": "state/profiles/{self}"
}
```

### check_permission() Changes

The `check_permission()` method now accepts prefixed resource paths:

```python
# Old
authz.check_permission(space_id, user_id, "read", "profiles/alice")

# New
authz.check_permission(space_id, user_id, "read", "state/profiles/alice")
```

**Note:** The actual state path is still `profiles/alice` - the `state/` prefix is only added when checking permissions.

### Resource-Specific Ownership

The authorization engine now dispatches ownership verification based on resource type:

- `_verify_state_ownership()` - Checks state entry `sender` field
- `_verify_data_ownership()` - Checks data entry `signed_by` field
- `_verify_blob_ownership()` - Checks blob metadata references
- Messages - Ownership not supported

### Path Validation

The `validate_capability_path()` function now requires and validates resource type prefixes:

```python
# Valid
validate_capability_path("state/auth/users/{self}/rights/{...}")  # ✅

# Invalid - missing prefix
validate_capability_path("auth/users/{self}/rights/{...}")  # ❌

# Invalid - unknown resource type
validate_capability_path("files/{...}")  # ❌
```

## Future Extensions

The unified namespace makes it easy to add new resource types:

```python
# Potential future resource types
RESOURCE_TYPES = {
    'state',     # Current: State storage
    'data',      # Current: Key-value storage
    'messages',  # Current: Message topics
    'blobs',     # Current: Blob storage
    'files',     # Future: Filesystem-like storage
    'indexes',   # Future: Search indexes
    'streams',   # Future: Event streams
}
```

## Benefits

1. **Clarity**: Resource type is explicit in every capability path
2. **Consistency**: Same authorization model works across all resource types
3. **Extensibility**: Easy to add new resource types
4. **Type Safety**: Resource type is validated at capability creation time
5. **Flexibility**: Different ownership models for different resource types
