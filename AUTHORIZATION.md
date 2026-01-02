# Authorization in Reeeductio

Reeeductio's authorization could be called a "half capability" system.  It uses capability objects to store user's rights in the system, but it is not a strict capability system.  It does have ambient authority because clients are not required to present a capability along with each request.  So it does not prevent confused deputies, but the usability improvement seems to be worth it.

The basic idea is to use some sub-tree of the channel's state space to store authentication and authorization data.  In general the channel state is very flexible and can be used by the application in almost any way, because the server does not need to understand it.  But the /auth subtree is special because the server does use it to decide how to authorize requests.

## The Basic Scheme

In the most basic version of this scheme, we store user keys under /auth/users/{user_public_key} with the user's capabilities in /auth/users/{u_p_k}/rights/{cap_id}.  Each capability (like every state entry) must be signed by a valid public key that is authorized to write there.

Each capability contains
* The public key for the subject (ie the user)
* The operation
* The state prefix for the object
* The timestamp when this access was granted
* The timestamp (if any) when this access shall expire (TODO)
* The grantor's signature over the above
* The public key that granted the capability

A new capability may be written to the state IFF
1. The grantor public key is also a user in the channel, or the channel creator
2. The grantor public key has at least as much power as is being granted (ie, a more powerful operation on a prefix of the granted prefix)
3. The grantor public key is authorized to write or create under the prefix /auth/users/{u_p_k}/rights/

The channel creator key is the super-admin and is always implicitly authorized to perform any action in the channel.

## Role-Based Access Control

It would be convenient to have RBAC.  Otherwise the application must be careful to grant each new user the rights that they need for every subtree of the state that is used in the application.  It would be much more pleasant and less error-prone if we could simply give the new user a role like "user" or "default" and have all of the default permissions granted to them.

We could put roles under /auth/roles/{role_id} and their rights under /auth/roles{r_id}/rights/.  Here role_id can be human readable, like "admin" or "user" or "default", this is much nicer than requiring it to be a hash, as it's just an identifier.

Then the role grants for a user would go under /auth/users/{user_public_key}/roles/{role_id}.  Contents would be similar to the contents of a capability entry:
* User's public key
* Role being granted
* Timestamp when granted
* Timestamp for expiry
* Signature over the above
* Signer's public key

In order to grant a role to a user, the grantor must
* Have power that dominates the role's power
* Have write or create access to /auth/users/{u_p_k}/roles/

## Limited Use Tools

It would be nice if we could give out limited "API key" style keys.

One motivating example is moderation.  When a user gets banned it is often better if the ban comes from a generic "mod" account rather than from an individual moderator.  This can reduce drama because it reduces the temptation for the banned user to lash out at the individual moderator.

Another example is for "bot" accounts where I want to give limited access to some computer, not a human.  Maybe the bot sends notifications from some other service, eg Github.  Or maybe one day I will finally build my encrypted security camera; then the camera needs to upload photos and videos, but it doesn't need to do anything else in the channel.

The big motivating example is letting users join the channel from a text message.  This is *almost* like joining from a QR code.  In either case, we want to create some special key that can create new users in the room.  But we *do not* want the key itself to be usable as a user key.  We don't want it posting messages, and we definitely don't want it downloading and decrypting everything that's already in the room.  The naive version would be to include the symmetric root key in the invite / QR code.  But then if we are not careful, if the join key is a full user key, then anyone who learns the invite can connect to the channel as the join key, download all of our messages (and our state) and decrypt everything, all without ever being detected.  So we definitely don't want that.  It seems the solution is to make the join key *not* a full regular user in the channel.  So then a new user (either legitimate or a bad guy who saw the invite) must create a new user key in the channel WHERE WE CAN SEE THEM, and only then can they download our data and use the symmetric root to decrypt it.  An incremental improvement above and beyond that would be to encrypt the symmetric root with a key-wrap key (KWK) and save it somewhere in the state.  We include the KWK in the invite instead of the root key.  Then the new users can connect, download the wrapped key, and unwrap with the KWK to recover the root secret.  It doesn't prevent a malicious chat platform from stealing all of our stuff, but it does prevent them from doing it without our notice.

I think the critical factor for tools must be that a tool has different authorization requirements from those of a user.
* A tool can create users and tools, and can grant rights.  Unlike a user, it is not required to have all of the powers that it itself is granting.  So for example we can have a tool that can create new users, and can grant them the "user" role even though it does not have that role itself.  It can only create users (and grant the role if we want to make it explicit).
* A tool does not inherit any rights other than those it is explicitly granted in the state

As an extra step, it would be cool if each tool could have a limited number of uses.  (Like in Minecraft, ha!) This requires the channel to keep track of the use count for each tool, but oh well that's not *too* much extra work.  All we need is one more table in the database.

Tools are stored in the channel state just like users, but under a different prefix:
* Tool metadata: `auth/tools/{tool_public_key}`
* Tool capabilities: `auth/tools/{tool_public_key}/rights/{cap_id}`

This is parallel to user storage:
* User metadata: `auth/users/{user_public_key}`
* User capabilities: `auth/users/{user_public_key}/rights/{cap_id}`

The key differences between tools and users are:
1. **No ambient authority** - Tools ONLY have the capabilities explicitly granted in `auth/tools/{id}/rights/`. They cannot read messages, access user data, or perform any actions without explicit capabilities. However, tools CAN authenticate via challenge/verify to obtain JWT tokens for making API requests (e.g., security camera uploading photos).
2. **Use-count limiting** - Tools can have a `use_limit` field that decrements with each use
3. **Expiration** - Tools can have an `expires_at` timestamp for auto-revocation

### Tool Permission Model

Tools use the same path-based capability system as regular users. Their capabilities are stored in the state at `auth/tools/{tool_public_key}/rights/{cap_id}` just like user capabilities are stored at `auth/users/{user_public_key}/rights/{cap_id}`.

**Why tools grant roles, not arbitrary capabilities:**

Role names are human-readable and predictable ("user", "admin", "moderator"), so we can give a tool the capability `{"op": "create", "path": "auth/users/{any}/roles/user"}` and it can ONLY grant the "user" role. This path-based limiting works perfectly for roles.

Arbitrary capability grants don't work as well because:
* Capability IDs are unpredictable hashes
* Many equivalent ways to express the same permission
* Cannot meaningfully embed capability constraints in paths

**Best practice:** If you need a tool to grant specific permissions, create a role with those permissions, then give the tool `create` access to that role's path.

**Example: Camera provisioning tool**

```
// Role definition
auth/roles/camera → {"role_id": "camera", "description": "Upload photos only"}
auth/roles/camera/rights/cap_001 → {"op": "create", "path": "photos/{...}", ...}

// Tool definition
auth/tools/T_camera_tool → {"tool_id": "T_camera_tool", "use_limit": 50, ...}

// Tool's capabilities
auth/tools/T_camera_tool/rights/cap_001 → {"op": "create", "path": "auth/users/{any}"}
auth/tools/T_camera_tool/rights/cap_002 → {"op": "create", "path": "auth/users/{any}/roles/camera"}
```

This tool can create new users and grant them the "camera" role, but cannot grant any other role.

### Path-Content Consistency Enforcement

To prevent privilege escalation attacks, the server enforces that data content matches the path for authorization-critical writes:

**For role grants at `auth/users/{user_id}/roles/{role_id}`:**
* Data MUST contain `"role_id": "{role_id}"` matching the path
* Data MUST contain `"user_id": "{user_id}"` matching the path

**For role definitions at `auth/roles/{role_id}`:**
* Data MUST contain `"role_id": "{role_id}"` matching the path

**For tool definitions at `auth/tools/{tool_id}`:**
* Data MUST contain `"tool_id": "{tool_id}"` matching the path

This prevents attacks where a tool with permission to write `auth/users/U123/roles/user` tries to write `{"role_id": "admin"}` to that path. Even though the tool has authorization for the path, the write is rejected because the data doesn't match.

### Tool Creation Requirements

A tool can only be created if:

1. Creator has `create` or `write` permission on `auth/tools/{tool_id}`
2. **Creator has superset permission for each capability being granted to the tool**
3. Tool definition is properly signed by creator
4. Path-content consistency rules are satisfied (tool_id in data matches path)

The critical security property is #2: you cannot create a tool more powerful than yourself. For example, if you only have the "user" role, you cannot create a tool with the capability `{"op": "create", "path": "auth/users/*/roles/admin"}` because you lack that capability yourself.

This prevents privilege escalation through tool creation.

### Path Syntax

**User-created paths** (for state writes, message topics, etc.) must use slug format:
- Segments separated by `/`
- Each segment contains only: `[a-zA-Z0-9._-]`
- No leading or trailing slashes (normalized by server)
- Examples: `profiles/alice`, `topics/general/messages`, `files/photo.jpg`

**Capability path patterns** (for permission grants) can additionally use wildcards:
- `{self}` - Resolves to the acting user's public key
- `{any}` - Matches exactly one path segment at that position
- `{other}` - Matches any segment except the acting user's public key
- `{...}` - Matches any remaining segments at any depth (rest wildcard)

**Exact Depth vs Prefix Matching:**

Without `{...}`, patterns require exact depth matching:
- `auth/users/{any}` matches `auth/users/U_alice` ✅
- `auth/users/{any}` DOES NOT match `auth/users/U_alice/roles/admin` ❌ (too many segments)
- `topics/{any}/messages` matches `topics/general/messages` ✅
- `topics/{any}/messages` DOES NOT match `topics/general/messages/msg1` ❌

With `{...}`, patterns match any depth from that point forward:
- `{...}` matches ANY path at ANY depth (global wildcard)
- `auth/users/{...}` matches `auth/users/U_alice` ✅
- `auth/users/{...}` matches `auth/users/U_alice/roles/admin` ✅
- `topics/{any}/messages/{...}` matches `topics/general/messages/msg1` ✅
- `topics/{any}/messages/{...}` matches `topics/general/messages/msg1/replies/reply2` ✅

**Examples:**
- `profiles/{self}` - Can ONLY access your own profile entry (exact depth)
- `profiles/{self}/{...}` - Can access everything under your profile at any depth
- `topics/{any}/messages/{...}` - Can access messages in any topic at any depth
- `auth/users/{other}/banned` - Can write to other users' banned flag (exact depth)
- `auth/roles/{any}/rights/{...}` - Can manage all rights for any role at any depth

**Forbidden in user paths:**
- Reserved wildcards: `{self}`, `{any}`, `{other}`, `{...}`
- Any braced expressions: `{foo}`, `{id}`, etc.
- Special characters: spaces, quotes, backslashes, etc.

The server rejects any state write with a path containing reserved wildcards or invalid characters.
