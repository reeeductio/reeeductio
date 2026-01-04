# Server Admin Interface
The server provides an API under /admin for managing server-level users (above the level of individual channels) and for creating channels.

Top-level users of the server can create and delete channels, and server admins can also delete blobs (and maybe messages).

Like users within individual channels, users at the server level are identified only by their public key.  In fact, the admin interface stores all of its data in a special-purpose channel, which can also be used through the normal channel API to manage the server state.

## Admin Channel Membership Model

The admin channel has two tiers of membership:

### Server Users (Channel Creators)
- **Purpose**: Authentication only
- **Admin channel membership**: YES (under `auth/users/{user_id}`)
- **Capabilities in admin channel**: None - they exist for authentication but have no roles or capabilities
- **What they CAN do**: Authenticate to get JWT tokens, then use `/admin` endpoints
- **What they CAN'T do via normal channel API**: Cannot read/write any state in the admin channel, cannot send messages
- **Admin API powers**: Create channels (via `PUT /admin/channels/{channel_id}`)

### Server Admins
- **Purpose**: Full server management
- **Admin channel membership**: YES (under `auth/users/{user_id}`)
- **Capabilities in admin channel**: Full access via `server-admin` role
- **What they CAN do**: Manage all admin channel state via normal channel API or `/admin` endpoints
- **Admin API powers**: All admin operations including user management

## Example admin functions

### Creating channels and top-level users
* `PUT /admin/auth/users/{user_id}`
* `PUT /admin/channels/{channel_id}`

### Getting information
* `GET /admin/auth/users/{user_id}`
* `GET /admin/channels/{channel_id}`
* `GET /admin/blobs/{blob_id}`

### Deleting channels, users, and blobs (and messages?)
* `DELETE /admin/auth/users/{user_id}`
* `DELETE /admin/channels/{channel_id}`
* `DELETE /admin/blobs/{blob_id}`
* `DELETE /admin/channels/{channel_id}/messages/{message_id}`

## The Admin Channel
The server uses a channel to store its top-level admin data.

The admin private key for this special channel must be included in the server's configuration.

If the server owner also keeps a local copy of the admin private key, then they can manage the server remotely via the channel's regular API interface.

### Admin Channel State Structure

The admin channel uses the following state hierarchy:

#### Server Users
Information on each server-level user is stored at `users/{user_id}`:
```json
{
  "user_id": "U_abc123...",
  "can_create_channels": true,
  "max_channels": 10,
  "created_at": 1234567890
}
```

This is application-level metadata used by the `/admin` API for quota enforcement. Note that this is separate from the user's authentication entry at `auth/users/{user_id}`, which may have no roles or capabilities.

#### Channel Registry
The canonical registry of all channels is stored at `channels/{channel_id}`:
```json
{
  "channel_id": "C_abc123...",
  "created_by": "U_xyz789...",
  "created_at": 1234567890,
  "signature": "user_signature",
  "channel_signature": "channel_signature"
}
```

This registry serves as the single source of truth for channel existence and prevents duplicate channel creation.

#### User Channel Index
For each user, their channels are indexed at `users/{user_id}/channels/{channel_id}`:
```json
{
  "channel_id": "C_abc123..."
}
```

This enables efficient "list channels created by user" queries for quota enforcement.

## Authentication
The admin API's authentication and authorization scheme are exactly the same as for the admin channel.  Any member of the admin channel can authenticate to the admin API using the same Ed25519 keys and JWT tokens that they use with the admin channel.

The admin API exposes the `GET /admin/auth/challenge` and `POST /admin/auth/verify` endpoints for convenience, so clients do not need to know or remember the admin channel id.

## Authorization

Admin API calls are authorized based on the authenticated user's permissions and server-level metadata.

### Channel Creation Flow

When user U1 calls `PUT /admin/channels/{channel_id}`, the following validation occurs:

1. **JWT Authentication**: User must have a valid JWT token for the admin channel
2. **User Permissions**: User's entry at `users/{user_id}` must have `can_create_channels: true`
3. **Quota Check**: If `max_channels` is set, count channels where `created_by == user_id` and ensure limit not exceeded
4. **Duplicate Prevention**: Verify no entry exists at `channels/{channel_id}`
5. **Channel Ownership Proof**: Verify the `channel_signature` in the request body

The request body must contain:
```json
{
    "channel_id": "C_abc123...",
    "created_by": "U_xyz789...",
    "created_at": 1234567890,
    "signature": "user_signature_over_this_object",
    "channel_signature": "channel_key_signature_proving_ownership"
}
```

**Two signatures are required:**
- **User signature**: The user signs the entire JSON object to prove they intend to create this channel
- **Channel signature**: The channel private key signs `{channel_id, created_by, created_at}` to prove ownership and consent

### Server Writes State on User's Behalf

Importantly, the `/admin` API endpoints do **not** write to the admin channel state as the authenticated user. Instead, the server validates the user's request and then writes the state entries using the **admin channel creator private key** (from server configuration).

This means:
- Server users do not need any write capabilities in the admin channel
- All admin channel state modifications are signed by the server (admin channel creator)
- The user's signed data is embedded in the state entry's data payload for audit purposes

When the server processes `PUT /admin/channels/{channel_id}`, it:
1. Validates the user's request (authentication, permissions, signatures, quota)
2. Writes to `channels/{channel_id}` **as the admin channel creator**
3. Writes to `users/{user_id}/channels/{channel_id}` **as the admin channel creator**
4. Initializes the actual channel in the channel manager

### Roles and Permissions

The admin channel defines two conceptual roles, but they work differently:

#### Server Users (Channel Creators)
Server users are members of the admin channel but have **no capabilities** assigned. Their permissions are defined purely by application-level metadata at `users/{user_id}`:
- `can_create_channels`: Whether user can create channels via `/admin/channels`
- `max_channels`: Optional quota limit

Server users authenticate to the admin channel to get JWT tokens, but cannot read or write any admin channel state via the normal channel API. They can only operate through the `/admin` endpoints, which validate their permissions and write state on their behalf.

#### Server Admins
Server admins have the `server-admin` role with full capabilities:

**Role: `auth/roles/server-admin`**
- `{ op: "write", path: "auth/{...}" }` - Manage admin channel membership and roles
- `{ op: "write", path: "channels/{...}" }` - Manage channel registry
- `{ op: "write", path: "users/{...}" }` - Manage user metadata and quotas
- `{ op: "delete", path: "channels/{...}" }` - Delete channels

Server admins can manage the server either through `/admin` endpoints or by directly interacting with the admin channel's state using the normal channel API.

## Implementation Notes

### Channel Creation Validation

The `/admin/channels/{channel_id}` endpoint must validate:

1. **Channel signature verification**: Extract the public key from `channel_id`, verify the signature over `{channel_id, created_by, created_at}` matches
2. **User signature verification**: Verify the user's signature over the entire request body
3. **Consistency checks**:
   - `channel_id` in body matches URL parameter
   - `created_by` in body matches authenticated user from JWT
4. **Duplicate check**: Query admin channel state for `channels/{channel_id}` - return 409 Conflict if exists
5. **Quota enforcement**: If user has `max_channels` set, count existing channels and reject if quota exceeded

### Error Responses

| Status Code | Condition |
|-------------|-----------|
| 400 Bad Request | Invalid channel_id format, missing required fields, signature verification failed |
| 401 Unauthorized | Missing or invalid JWT token |
| 403 Forbidden | User's `can_create_channels` is false, or quota exceeded |
| 409 Conflict | Channel already exists in registry |
| 500 Internal Server Error | Failed to write to admin channel state or initialize channel |

### Channel Deletion

When deleting a channel via `DELETE /admin/channels/{channel_id}`:
1. Remove entry from `channels/{channel_id}`
2. Find and remove entry from `users/{created_by}/channels/{channel_id}`
3. Delete the actual channel data (state store, message store)
4. Optionally delete associated blobs (if not shared with other channels)

### Bootstrap Procedure

On first server startup:
1. Check if admin channel exists; if not, create it using the admin channel ID and creator private key from config
2. Initialize admin channel with the `server-admin` role definition
3. Create the first server admin user entry (bootstrap admin from config)
4. Grant bootstrap admin the `server-admin` role

### Security Considerations

- The admin channel creator private key is highly sensitive - compromise allows full server control
- Consider encrypting the admin private key in config with a passphrase required at server startup
- Server users cannot bypass `/admin` validation by writing directly to admin channel (they have no capabilities)
- All channel creations are non-repudiable (both user and channel signatures preserved in state)

# Extension ideas

## Managing S3 Buckets
We could have different S3 buckets for different server-level users.  Then when user U1 creates a channel, that channel's blobs are stored in user U1's bucket.

Bucket information could be stored under `server/buckets/{bucket_id}` or under `server/users/{user_id}/buckets/{bucket_id}`.

This might be nice because then the server admin can let their friends bring their own buckets (heh BYOB) and pay for their own storage.