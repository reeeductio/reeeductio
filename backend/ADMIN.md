# Server Admin Interface

The server provides an API under /admin for managing server-level users (above the level of individual spaces) and for administrative operations that require server-side orchestration.

Top-level users of the server can create spaces directly through the admin space's normal API. Server admins can also perform administrative operations like deleting spaces and blobs.

Like users within individual spaces, users at the server level are identified only by their public key. The admin interface stores all of its data in a special-purpose space (the "admin space"), which uses the normal space API for most operations.

## Admin Space Overview

The admin space is a special space managed by the `AdminSpace` class, which extends the regular `Space` class with additional validation rules for space registration.

### Key Differences from Regular Spaces

1. **Space registration validation**: Writes to `spaces/{space_id}` require:
   - A valid `space_signature` proving ownership of the space's private key
   - The `created_by` field must match the authenticated user

2. **Direct user writes**: Server users write directly to the admin space state using the normal space API, rather than going through a server-mediated `/admin` endpoint.

3. **Role-based permissions**: Users are granted the `space-creator` role, which gives them permission to register spaces.

## Admin Space Membership Model

The admin space has two tiers of membership:

### Server Users (Space Creators)
- **Purpose**: Create and register spaces
- **Admin space membership**: YES (under `auth/users/{user_id}`)
- **Role**: `space-creator` (granted at `auth/users/{user_id}/roles/space-creator`)
- **What they CAN do**:
  - Authenticate to get JWT tokens
  - Create space registry entries at `spaces/{space_id}` via normal space API
  - Create entries in their own space index at `users/{user_id}/spaces/{space_id}`
- **What they CAN'T do**:
  - Modify or delete existing space entries
  - Write to other users' space indexes
  - Access admin-only operations

### Server Admins
- **Purpose**: Full server management
- **Admin space membership**: YES (under `auth/users/{user_id}`)
- **Role**: `server-admin` with full capabilities
- **What they CAN do**: Manage all admin space state via normal space API or `/admin` endpoints
- **Admin API powers**: All admin operations including user management, space deletion, blob deletion

## Space Registration Flow

When user U1 wants to create a new space:

1. **Generate space keypair**: Client generates an Ed25519 keypair for the new space
2. **Create registration data**: Client prepares:
   ```json
   {
       "space_id": "C_abc123...",
       "created_by": "U_xyz789...",
       "created_at": 1234567890,
       "space_signature": "base64_signature_proving_ownership"
   }
   ```
3. **Sign with space key**: The `space_signature` is the space's private key signing over `{space_id}|{created_by}|{created_at}`
4. **Write to admin space**: User writes to `spaces/{space_id}` via the normal state API
5. **Index the space**: User writes to `users/{user_id}/spaces/{space_id}` for their own index

### Space Signature Verification

The `AdminSpace` class validates space registrations by:
1. Extracting the public key from `space_id`
2. Verifying `space_signature` over the canonical message `"{space_id}|{created_by}|{created_at}"`
3. Ensuring `created_by` matches the authenticated user

This proves the user has control of the space's private key.

## The space-creator Role

Server users are granted the `space-creator` role, which provides:

```json
// Role definition at auth/roles/space-creator
{
  "role_id": "space-creator",
  "description": "Can register new spaces in the admin space"
}

// Capability 1: Create space registry entries
// at auth/roles/space-creator/rights/cap_000
{
  "op": "create",
  "path": "state/spaces/{any}"
}

// Capability 2: Create entries in own user space index
// at auth/roles/space-creator/rights/cap_001
{
  "op": "create",
  "path": "state/users/{self}/spaces/{any}"
}
```

The `{self}` wildcard ensures users can only write to their own space index.

## Admin Space State Structure

### Space Registry
The canonical registry of all spaces is stored at `spaces/{space_id}`:
```json
{
  "space_id": "C_abc123...",
  "created_by": "U_xyz789...",
  "created_at": 1234567890,
  "space_signature": "base64_signature"
}
```

### User Space Index
For each user, their spaces are indexed at `users/{user_id}/spaces/{space_id}`:
```json
{
  "space_id": "C_abc123..."
}
```

This enables efficient "list spaces created by user" queries.

## Authentication

The admin API's authentication scheme is the same as for regular spaces. Any member of the admin space can authenticate using Ed25519 keys and JWT tokens.

The admin API exposes convenience endpoints so clients don't need to know the admin space ID:
- `GET /admin/auth/challenge` - Get authentication challenge
- `POST /admin/auth/verify` - Verify signature and get JWT

## The /admin API Endpoints

The `/admin` API is now primarily for operations that require server-side orchestration:

### Still Required

| Endpoint | Purpose |
|----------|---------|
| `GET /admin/auth/challenge` | Convenience endpoint for auth (don't need to know admin space ID) |
| `POST /admin/auth/verify` | Convenience endpoint for auth |
| `DELETE /admin/spaces/{space_id}` | Delete space with cascade cleanup |
| `DELETE /admin/blobs/{blob_id}` | Delete blob from storage |
| `PUT/DELETE /admin/auth/users/{user_id}` | Server admin user management |

### No Longer Required (Use Normal Space API)

| Old Endpoint | New Approach |
|--------------|--------------|
| `PUT /admin/spaces/{space_id}` | Write directly to admin space at `spaces/{space_id}` |
| `GET /admin/spaces/{space_id}` | Read from admin space at `spaces/{space_id}` |
| `GET /admin/auth/users/{user_id}` | Read from admin space at `auth/users/{user_id}` |

## Roles and Permissions

### Server Users (space-creator role)
Capabilities:
- `{ op: "create", path: "state/spaces/{any}" }` - Register new spaces
- `{ op: "create", path: "state/users/{self}/spaces/{any}" }` - Index own spaces

### Server Admins (server-admin role)
Capabilities:
- `{ op: "write", path: "state/auth/{...}" }` - Manage admin space membership and roles
- `{ op: "write", path: "state/spaces/{...}" }` - Manage space registry
- `{ op: "write", path: "state/users/{...}" }` - Manage user metadata
- `{ op: "delete", path: "state/spaces/{...}" }` - Delete space entries

## Bootstrap Procedure

On first server startup:

1. **Create admin space**: Initialize using admin space ID and creator private key from config
2. **Create space-creator role**: Write role definition to `auth/roles/space-creator`
3. **Add role capabilities**: Write capabilities to `auth/roles/space-creator/rights/`
4. **Create server-admin role**: Write role definition with full capabilities
5. **Bootstrap first admin**: Create admin user entry and grant `server-admin` role

The `AdminSpace.get_bootstrap_state_entries()` method provides the entries needed for steps 2-3.

## Security Considerations

### Simplified Trust Model
- Users write directly to the admin space - no server-side tool key needed for space creation
- The admin private key is only needed for bootstrap and admin operations
- If a user's key is compromised, only their spaces are at risk (they can't modify others)

### Validation Guarantees
- `space_signature` proves ownership of the space's private key
- `created_by` enforcement prevents users from registering spaces on behalf of others
- The `create` capability prevents modification or deletion of existing entries

### What's NOT Enforced
- **Quotas**: The current design does not enforce space creation quotas. This could be added later via:
  - Soft enforcement (periodic audit and disable over-quota users)
  - Pre-write hooks in `AdminSpace._check_state_operation()`
  - A separate quota service

## Implementation Notes

### AdminSpace Class

The `AdminSpace` class (`admin_space.py`) extends `Space` with:

1. **`_check_state_operation()` override**: Adds validation for space registration paths
2. **`_validate_space_registration()`**: Enforces space_signature and created_by rules
3. **`_verify_space_signature()`**: Cryptographic verification of space ownership
4. **`get_bootstrap_state_entries()`**: Returns entries needed to set up space-creator role

### SpaceManager Integration

The `SpaceManager` accepts an `admin_space_id` parameter and returns an `AdminSpace` instance when that space is requested:

```python
space_manager = SpaceManager(
    admin_space_id="C_admin_space_id_here",
    # ... other config
)

# Returns AdminSpace for admin space, regular Space for others
space = space_manager.get_space(space_id)
```

## Extension Ideas

### Managing S3 Buckets
We could have different S3 buckets for different server-level users. When user U1 creates a space, that space's blobs could be stored in user U1's bucket.

Bucket information could be stored under `buckets/{bucket_id}` or `users/{user_id}/buckets/{bucket_id}`.

This would let server admins allow users to bring their own buckets (BYOB) and pay for their own storage.

### Quota Enforcement
If quotas become necessary:
1. Store quota info at `users/{user_id}` with `max_spaces` field
2. Add quota checking in `AdminSpace._check_state_operation()` before allowing space creation
3. Query existing spaces count with `list_state("users/{user_id}/spaces/")`
