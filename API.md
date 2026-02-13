## API Endpoints

### Authentication

```
POST /spaces/{space_id}/auth/challenge
POST /spaces/{space_id}/auth/verify
POST /spaces/{space_id}/auth/refresh
```

Authentication uses challenge-response with Ed25519 signatures:
1. Client requests challenge with their public key
2. Client signs the challenge with their private key
3. Server verifies signature and issues JWT token

### State Management

```
GET    /spaces/{space_id}/state/{path}
PUT    /spaces/{space_id}/state/{path}
DELETE /spaces/{space_id}/state/{path}
```

All space data is stored as signed state entries:
- `/state/auth/users/{user_id}` - User identity
- `/state/auth/users/{user_id}/rights/{capability_id}` - User capabilities
- `/state/auth/users/{user_id}/roles/{role_id}` - Role grants to users
- `/state/auth/roles/{role_id}` - Role definitions
- `/state/auth/roles/{role_id}/rights/{capability_id}` - Role capabilities
- `/state/auth/tools/{tool_id}` - Tool definitions (with optional use_limit)
- `/state/auth/tools/{tool_id}/rights/{capability_id}` - Tool capabilities
- `/state/topics/{topic_id}/metadata` - Topic information
- `/state/user/{user_id}/*` - User-specific encrypted data

Each state entry includes:
- `data` - Base64-encoded content
- `signature` - Ed25519 signature over `space_id|path|data|signed_at`
- `signed_by` - User ID who created the entry
- `signed_at` - Unix timestamp in milliseconds

### Messages

```
GET  /spaces/{space_id}/topics/{topic_id}/messages?from=&to=&limit=
POST /spaces/{space_id}/topics/{topic_id}/messages
GET  /spaces/{space_id}/messages/{message_hash}
```

Messages form a blockchain-style chain:
- Each message includes `prev_hash` pointing to the previous message
- Server validates chain integrity
- Queries are time-based (using server timestamps) for efficiency

### Blobs

```
POST   /blobs
GET    /blobs/{blob_id}
DELETE /blobs/{blob_id}
```

Content-addressed storage for encrypted files/attachments.
