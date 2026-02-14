# Security

rEEEductio has been designed from the ground up to be secure against a variety of threats,
including a compromised server (or database) that tries to read, modify, or forge the
space's contents.

At the same time, this is a hobby project that has not been independently reviewed for security.
Use it at your own peril.

## Integrity

The space public key is the root of trust for everything in the space.

### Message Integrity
Every message must be signed by its sender, who must be a member of the space.

Messages are identified by the SHA-256 hash of their content.

Each message includes the hash of the previous message in the given topic.

### State Integrity
Each update to the Space state is transmitted and stored as a message in the special "state" topic in the space.  

The validity of the state can be verified by replaying the sequence of updates, verifying that each update is authorized under the previous state.

### Blob Integrity
Blobs are identified by the SHA-256 hash of their content. The hash is checked whenever a blob is uploaded or downloaded.

### KV Store Integrity
Each entry the the Space's key-value store is signed by the user who uploaded it.  The signature covers both the state path (ie the key) and the data stored at that path (ie the value).

## Accounts

### Users
Each user is identified by their user id, a 44-byte base64 string beginning with the letter "U" that encodes the user's 32-byte Ed25519 public key.  

A user is made a member of the space by writing their user id to the space state at `auth/users/{user_id}`.

So the first non-root user must be added by the root user.  Then additional users can be added by any member of the space who has the right to create new state entries under `auth/users/`.

### Tools
Tools are like limited user accounts for use by bots or for providing special powers to human users.  Unlike user accounts, tools cannot have roles
- Tools are Ed25519 keypairs identified by `T_` prefix
- Stored at `/state/auth/tools/{tool_id}`
- Can only perform actions explicitly granted via capabilities
- Optional `use_limit` restricts total number of state writes
- Tool usage is tracked separately from regular users

## Authorization

### Capabilities
Granular, signed permissions that control access:
- Each capability specifies an operation (`read`, `create`, `update`, `write`, `delete`) and a path pattern
- Path patterns support wildcards: `{self}`, `{any}`, `{other}`, `{...}` (recursive)

Capabilities can be granted directly to users or to roles
- User capabilities: `/state/auth/users/{user_id}/rights/{capability_id}`
- Role capabilities: `/state/auth/roles/{role_id}/rights/{capability_id}`
- Tool capabilities: `/state/auth/tools/{tool_id}/rights/{capability_id}`

### Role-Based Access Control
Roles provide reusable permission sets for users
- Roles are defined at `/state/auth/roles/{role_id}` with associated capabilities
- Users are granted roles at `/state/auth/users/{user_id}/roles/{role_id}`
- Users inherit all capabilities from their assigned roles
- Role grants can have optional expiration times


## Authentication

### Cryptographic Authentication
A user authenticates to the space by signing a challenge from the server.

### Password-based Login with OPAQUE
Spaces and users within those spaces can optionally enroll themselves to enable a more traditional username and password via the OPAQUE protocol.  This makes Space accounts more convenient for normal users and more compatible with existing infrastructure like password managers.

Note that successful completion of the OPAQUE protocol does not authenticate the user to the Space.  Instead it provides the user with an encrypted copy of their keys for the Space, and a decryption key that can be used to unwrap them.  The user can then use the decrypted private key to authenticate to the space via the normal cryptographic auth mechanism.