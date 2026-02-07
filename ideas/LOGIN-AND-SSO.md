# Design Ideas for Login and SSO

## Problem

Reeeductio spaces authenticate via Ed25519 challenge-response and encrypt with
a shared 32-byte symmetric root. There are no passwords in the protocol. Users
currently must manually enter a private key and symmetric root to log in.

We want password-based login. This requires bridging two worlds:
- **What users have**: a username and password
- **What reeeductio needs**: a 32-byte Ed25519 private key + 32-byte symmetric root

## Approach: OPAQUE in the Core Space API

We add [OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/)
(an asymmetric PAKE protocol) as an optional feature of the reeeductio space
API. Any space can enable it. OPAQUE serves one purpose: **recovering the
user's private key from a password**. It does not replace Ed25519 auth.

### Why OPAQUE over Raw Argon2 + Salt

With a naive approach (derive keys from `Argon2(password, salt)`), we need the
salt to be accessible before the user authenticates. This creates a bootstrap
problem and exposes the salt to offline brute-force. OPAQUE eliminates both:

- **No salt distribution problem.** The client sends a blinded element; the
  server evaluates an OPRF with its secret key. No pre-auth fetch needed.
- **Offline brute-force requires the server's OPRF key.** Stealing the salt
  is no longer sufficient. An attacker needs to compromise the server AND
  grind through the password space.
- **The server never sees the password or derived keys.** The OPRF is
  oblivious; the server contributes to key derivation without learning the
  result.

### Key Design Decisions

**1. OPAQUE is for key recovery only, not authentication.**

After OPAQUE, the client holds its private key and authenticates to the space
via the existing Ed25519 challenge-response. The space has a single auth
mechanism. It doesn't know or care that OPAQUE was involved.

This requires more round trips (OPAQUE then challenge-response) but keeps the
auth model simple and avoids having two ways to get a session token.

**2. Keypairs are random and stable across password changes.**

The Ed25519 keypair is generated randomly at registration time, not derived
from the password. This is important because the current OPAQUE spec derives
its own internal AKE keypair deterministically from the password -- meaning
that keypair changes whenever the password changes. We do not use the OPAQUE
AKE keypair as the reeeductio identity. Instead, the reeeductio keypair is
independent, wrapped with a key derived from OPAQUE's `export_key`, and stored
alongside the OPAQUE record on the server.

If the keypair were derived from the password, changing the password would
change the public key, requiring RBAC updates across the space. With wrapping,
password changes just re-wrap the same private key. The public key never
changes.

**3. Credentials are wrapped with the OPAQUE `export_key`, not stored in the
OPAQUE envelope.**

The current OPAQUE spec's envelope is minimal: just a nonce + auth tag (~64
bytes). It does not store the client's private key -- instead, the OPAQUE AKE
keypair is derived deterministically from the password. There is no slot in the
envelope for application-level key material.

Instead, we use OPAQUE's `export_key` (a value the spec produces specifically
for application use) to derive a wrapping key:

```
wrap_key = HKDF-SHA256(export_key, info="reeeductio-credential-wrap")
encrypted_credentials = AES-256-GCM(wrap_key, nonce, privateKey || symmetricRoot)
```

The `encrypted_credentials` blob is stored on the server alongside the OPAQUE
record and returned to the client after a successful OPAQUE login. This keeps
the OPAQUE protocol itself completely unmodified and standards-compliant.

**4. OPAQUE is opt-in per space, enabled by admin.**

A space admin enables OPAQUE by uploading a server setup to the data store at
`opaque/server/setup`. The presence of this setup determines whether OPAQUE
endpoints are functional. Spaces without a setup remain keypair-only.

**5. OPAQUE registration requires authentication.**

Only authenticated space members can register OPAQUE usernames. This ensures
proper authorization and allows the data store to maintain valid signatures.
The registering user must prove ownership of the keypair being registered by
signing the registration data.

## Per-Space Auth Flow

### API Surface

Four new endpoints per space (only active if OPAQUE is enabled):

```
POST /spaces/{id}/opaque/register/init    (requires auth)
POST /spaces/{id}/opaque/register/finish  (requires auth)
POST /spaces/{id}/opaque/login/init       (no auth required)
POST /spaces/{id}/opaque/login/finish     (no auth required)
```

The register endpoints require JWT authentication. The login endpoints do not
(that's the whole point -- recovering keys from a password).

These are pure OPAQUE protocol endpoints. They don't issue tokens or modify
RBAC. The existing `/auth/challenge` and `/auth/verify` endpoints remain the
only way to get an access token.

### Enabling OPAQUE for a Space

An admin must upload the OPAQUE server setup before the endpoints will work:

```
Admin                                      Space
-----                                      -----
// Generate OPAQUE server setup (once per space)
server = OpaqueServer()
setup_bytes = server.export_setup()

// Upload to data store (signed by admin)
PUT /spaces/{id}/data/opaque/server/setup
  data: base64(setup_bytes)
  signature: admin_signature
  signed_by: admin_public_key
  signed_at: timestamp
                                           OPAQUE is now enabled
```

### Storage Layout

OPAQUE data is stored in the space's data store:

| Path | Content | Signed By |
|------|---------|-----------|
| `opaque/server/setup` | Server OPRF keys (base64) | Admin |
| `opaque/users/{username}` | JSON with `password_file`, `encrypted_credentials`, and `public_key` | Registering keypair |

The user's OPAQUE record is a single atomic entry containing:
```json
{
  "password_file": "<base64 OPAQUE PasswordFile>",
  "encrypted_credentials": "<base64 AES-GCM wrapped keys>",
  "public_key": "<44-char base64 Ed25519 pubkey>"
}
```

### Registration (Authenticated)

Registration requires the user to already be authenticated to the space. This
happens in two scenarios:
1. Admin registering a tool account for onboarding
2. User registering their own credentials after being added to the space

```
Client (authenticated)                     Server
----------------------                     ------
keypair = ed25519_generate()               // random, NOT derived from password

// --- OPAQUE registration step 1 ---
POST /opaque/register/init
  Authorization: Bearer {jwt_token}
  { username, registration_request }
              ========================>
              <========================
  { registration_response }

// --- OPAQUE registration step 2 ---
// Client computes registration record and wraps credentials
export_key = OPAQUE_registration_output()
wrap_key = HKDF(export_key, "reeeductio-credential-wrap")
encrypted_creds = AES-GCM(wrap_key, nonce, privateKey || symmetricRoot)

POST /opaque/register/finish
  Authorization: Bearer {jwt_token}
  { username, registration_record }
              ========================>
                                           verify JWT (same user as init)
                                           compute password_file from registration_record
              <========================
  { password_file }

// --- Client stores via /data API ---
// Assemble the complete OPAQUE record
record = {
  "password_file": password_file,
  "encrypted_credentials": encrypted_creds,
  "public_key": public_key
}

// Sign the record for storage
message = space_id|"opaque/users/"+username|base64(json(record))|signed_at
signature = ed25519_sign(keypair.privateKey, message)

PUT /data/opaque/users/{username}
  Authorization: Bearer {jwt_token}
  { data: base64(json(record)),
    signature, signed_by: public_key, signed_at }
              ========================>
                                           verify JWT, verify signature
                                           store record atomically
              <========================
  { path, signed_at }
```

### Login (Unauthenticated)

Login does not require authentication -- it's the key recovery mechanism:

```
Client                                     Server
------                                     ------

// --- OPAQUE login step 1 ---
POST /opaque/login/init
  { username, credential_request }
              ========================>
                                           load password_file for username
              <========================
  { credential_response }

// --- OPAQUE login step 2 ---
POST /opaque/login/finish
  { username, credential_finalization }
              ========================>
                                           verify OPAQUE protocol
              <========================
  { encrypted_credentials, public_key }

// --- credential recovery (client-side) ---
export_key = OPAQUE_login_output()
wrap_key = HKDF(export_key, "reeeductio-credential-wrap")
{ privateKey, symmetricRoot }
    = AES-GCM-Decrypt(wrap_key, encrypted_credentials)

// --- standard reeeductio auth (unchanged) ---
POST /auth/challenge
  { public_key }
              ========================>
              <========================
  { challenge }

signature = ed25519_sign(privateKey, challenge)

POST /auth/verify
  { public_key, challenge, signature }
              ========================>
              <========================
  { token }
// authenticated session established
```

### Password Change

```
1. OPAQUE login with old password --> export_key --> unwrap credentials
2. Authenticate with recovered keypair
3. OPAQUE register with new password --> new export_key
4. Re-wrap same (privateKey, symmetricRoot) with new export_key
5. Server replaces OPAQUE record + encrypted_creds blob
6. Keypair unchanged, RBAC untouched, no downstream effects
```

## User Onboarding via Tool Accounts

The cleanest way to onboard new users is via a **tool account** -- a keypair
with limited RBAC permissions that can add new users and register them with
OPAQUE.

### Flow

```
1. Admin creates a "tool" keypair with rights limited to:
   - Adding new user public keys to the space
   - Granting them the "user" role
   - Reading the symmetric root

2. Admin registers the tool keypair with OPAQUE
   (Admin is authenticated, signs with tool's keypair)

3. Admin shares the tool's OPAQUE username + password with friend
   (e.g., via text message, email, or verbal)

4. Friend logs in as the tool via OPAQUE
   -> Recovers tool's private key and symmetric root

5. Friend authenticates to the space as the tool
   -> Gets JWT with tool's limited capabilities

6. Friend generates their own user keypair
   Uses tool's auth to:
   - Add their public key to the space
   - Grant themselves the "user" role

7. Friend authenticates to the space as themselves
   -> Gets JWT with full user capabilities

8. Friend registers their own keypair with OPAQUE
   (Friend is now authenticated as themselves)
   -> Can now log in with their own username/password
```

### Detailed Protocol

```
Admin (one-time setup)                     Space
---------------------                      -----
tool_keypair = ed25519_generate()

// Add tool to space with limited role
PUT /state/auth/tools/{tool_id}
  { public_key, created_by, capabilities: [...] }

// Enable OPAQUE (if not already done)
PUT /data/opaque/server/setup
  { setup_bytes }

// Register tool with OPAQUE (admin is authenticated)
POST /opaque/register/init
  Authorization: Bearer {admin_jwt}
  { username: "onboarding-tool", registration_request }

POST /opaque/register/finish
  Authorization: Bearer {admin_jwt}
  { username: "onboarding-tool", registration_record }
  -> { password_file }

// Store OPAQUE record via /data API
PUT /data/opaque/users/onboarding-tool
  Authorization: Bearer {admin_jwt}
  { data: base64(json({
      password_file,
      encrypted_credentials: wrap(tool_privateKey, symmetric_root),
      public_key: tool_publicKey
    })),
    signature: sign_with_tool_key(...),
    signed_by: tool_publicKey,
    signed_at }

// Share with friend: "onboarding-tool" / "friend-password-123"


Friend                                     Space
------                                     -----
// Log in as tool (no auth required)
POST /opaque/login/init
  { username: "onboarding-tool", credential_request }
POST /opaque/login/finish
  { username: "onboarding-tool", credential_finalization }
  -> { encrypted_credentials, public_key: tool_publicKey }

// Recover tool credentials
tool_privateKey, symmetric_root = unwrap(encrypted_credentials)

// Authenticate as tool
POST /auth/challenge + /auth/verify
  -> tool_jwt

// Create own user account
friend_keypair = ed25519_generate()
PUT /state/auth/users/{friend_id}
  Authorization: Bearer {tool_jwt}
  { public_key: friend_publicKey, ... }

// Authenticate as self
POST /auth/challenge + /auth/verify (with friend_keypair)
  -> friend_jwt

// Register own OPAQUE credentials
POST /opaque/register/init
  Authorization: Bearer {friend_jwt}
  { username: "alice", registration_request }

POST /opaque/register/finish
  Authorization: Bearer {friend_jwt}
  { username: "alice", registration_record }
  -> { password_file }

// Store OPAQUE record via /data API
PUT /data/opaque/users/alice
  Authorization: Bearer {friend_jwt}
  { data: base64(json({
      password_file,
      encrypted_credentials: wrap(friend_privateKey, symmetric_root),
      public_key: friend_publicKey
    })),
    signature: sign_with_friend_key(...),
    signed_by: friend_publicKey,
    signed_at }

// Done! Alice can now log in with "alice" / her_password
```

### Tool Account Capabilities

The tool role should be carefully scoped:

```json
{
  "role": "onboarding-tool",
  "capabilities": [
    { "op": "read", "path": "data/symmetric_root" },
    { "op": "create", "path": "state/auth/users/{any}" },
    { "op": "create", "path": "state/auth/users/{any}/roles/user" }
  ]
}
```

The tool MUST NOT have:
- Read access to content (messages, blobs)
- Access to existing user records
- Admin capabilities

This ensures that even if the tool password is compromised, the attacker can
only create new accounts -- they cannot access any existing content.

### Single Tool vs. Per-Invitation Tools

**Single shared tool account:**
- Simpler to manage -- one password shared with all invitees
- Cannot revoke individual invitations
- Password may leak over time

**Per-invitation tool accounts:**
- Admin creates a new tool for each invitation (e.g., "invite-alice")
- Can revoke unused invitations by deleting the tool
- More administrative overhead

A middle ground: generate tool accounts on demand with random passwords,
deliver via a short-lived invitation link, and auto-expire unused invitations.

## SSO via a Login Space

For deployments with many spaces, per-space passwords become unwieldy. A
centralized **login space** provides SSO: one password, access to all spaces.

### Architecture

The login space is a regular reeeductio space with OPAQUE enabled. It stores
encrypted credential bundles for other spaces. A **login app** provides the
web UI and mediates the SSO flow.

The login space uses the same per-space OPAQUE mechanism described above. The
user authenticates to the login space with OPAQUE + Ed25519, then retrieves
credential bundles for other spaces.

**Data layout in the login space:**

```
/data/credentials/{spaceId}    -- per-user credential bundle (encrypted by
                                  the space's own encryption, plus optionally
                                  application-layer encryption)
```

Each credential bundle contains `{ privateKey, symmetricRoot, baseUrl }` for a
target space.

### SSO Flow (Popup + postMessage)

```
Music App                Login App (client)       Login App Backend    Login Space
---------                ------------------       ----------------    -----------
    |                          |                        |                  |
 1. | -- open popup ---------->|                        |                  |
    |    origin, space_id      |                        |                  |
    |                          |                        |                  |
 2. |                          |<- user: name + pass    |                  |
    |                          |                        |                  |
 3. |                          |== OPAQUE login =======>|                  |
    |                          |<== export_key =========|                  |
    |                          |<-- encrypted_creds ----|                  |
    |                          |                        |                  |
    |                          |-- unwrap creds with    |                  |
    |                          |   export_key           |                  |
    |                          |   -> login privateKey  |                  |
    |                          |      + login symRoot   |                  |
    |                          |                        |                  |
 4. |                          |-- challenge-response auth --------------->|
    |                          |<-- token ---------------------------------|
    |                          |                        |                  |
 5. |                          |-- fetch credential bundle for space_id -->|
    |                          |<-- encrypted bundle ----------------------|
    |                          |                        |                  |
 6. |                          |-- decrypt bundle       |                  |
    |                          |   -> music privateKey  |                  |
    |                          |      + music symRoot   |                  |
    |                          |                        |                  |
 7. |<-- postMessage ----------|                        |                  |
    |    { privateKey,         |                        |                  |
    |      symmetricRoot }     |                        |                  |
    |                          |                        |                  |
 8. |-- challenge-response auth to music space          |                  |
    |-- authenticated          |                        |                  |
```

The `postMessage` in step 7 is scoped to the music app's origin. Credentials
exist in plaintext only in browser memory, never in URLs or browser history.

An alternative to the popup approach is a redirect flow with an ephemeral
X25519 key exchange: the music app generates an ephemeral keypair, passes the
public key in the redirect URL, and the login app encrypts the credentials to
it before redirecting back. This avoids popups but puts encrypted data in URLs.

### Credential Bundle Management

When a user is granted access to a new space, the credential bundle for that
space must be stored in the login space. The invitation flow:

1. Admin (or inviter) has the symmetric root for the target space
2. Admin generates a new Ed25519 keypair for the invitee
3. Admin registers the invitee's public key in the target space's RBAC
4. Admin stores `{ privateKey, symmetricRoot, baseUrl }` as a credential
   bundle in the login space, at the invitee's data path
5. If the target space also has OPAQUE enabled, admin can optionally register
   the invitee there for direct (non-SSO) login as well

## Trust Model Implications

Adding OPAQUE to the core space API changes the server's security posture:

- **Before**: The server holds no authentication secrets. Compromise yields
  encrypted blobs and public keys -- useless without client-side keys.
- **After**: The server holds per-space OPRF keys. Compromise enables offline
  brute-force against passwords (attacker still needs to grind the password
  space, but can do so without further server interaction).

This is a deliberate trade-off: real-world usability (password login) in
exchange for a weaker server-compromise story. OPAQUE makes this trade-off
about as well as it can be made -- significantly stronger than password hashing
or raw Argon2 + salt.

OPAQUE should be an **optional, per-space feature**. Spaces that don't need
password auth can remain keypair-only with no OPRF state on the server.

## Implementation Notes

### Backend (Python)

The backend uses the `opaque_snake` package (Python bindings for OPAQUE):

```python
from opaque_snake import OpaqueServer, OpaqueClient, PasswordFile

# Server setup (done once by admin)
server = OpaqueServer()
setup_bytes = server.export_setup()  # Store at opaque/server/setup

# Registration (server computes password_file, returns it for client to store)
response = server.create_registration_response(request, username)
password_file = server.finish_registration(upload)  # Return to client

# Login (server reads user record from opaque/users/{username})
response, server_state = server.create_credential_response(request, username, password_file)
session_keys = server.finish_login(finalization, server_state)
```

### Credential Wrapping

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Derive wrapping key from OPAQUE export_key
hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"reeeductio-credential-wrap")
wrap_key = hkdf.derive(export_key)

# Encrypt credentials
nonce = os.urandom(12)
aesgcm = AESGCM(wrap_key)
plaintext = private_key + symmetric_root  # 64 bytes
ciphertext = aesgcm.encrypt(nonce, plaintext, None)
encrypted_credentials = nonce + ciphertext  # 12 + 64 + 16 = 92 bytes
```

## Open Questions

1. ~~**Invitation and symmetric root delivery.**~~ Solved via tool accounts.

2. **Rate limiting and lockout.** Password auth requires brute-force
   protection. The server needs rate limiting on the OPAQUE login endpoints,
   and possibly account lockout after repeated failures.

3. ~~**OPAQUE library selection.**~~ Using `opaque_snake` (Python).

4. **SSO credential transfer security.** The popup + `postMessage` approach
   keeps credentials out of URLs but requires careful origin validation. The
   redirect + ephemeral ECDH approach is more robust against origin confusion
   but more complex. Need to pick one.

5. ~~**Encrypted credentials blob storage.**~~ Stored at
   `opaque/users/{username}/envelope` in JSON format.

6. **Password reset / recovery.** In an E2EE system, forgetting your password
   means losing your keys. Options: no recovery (accept the risk), admin-
   assisted re-invitation (new keypair, lose history association), or a
   social/threshold recovery scheme. No easy answer here.

7. **Multiple devices.** After OPAQUE login on a new device, the user has
   their keys. But cached data (IndexedDB) is per-device. Is there a need
   for cross-device session management, or is per-device OPAQUE login
   sufficient?

## Next Steps

1. ~~Prototype the OPAQUE endpoints in the reeeductio backend~~ Done (Python)
2. Build a minimal client-side OPAQUE flow in TypeScript
3. Test the full round-trip: OPAQUE registration, login, key recovery,
   then Ed25519 challenge-response auth
4. ~~Design the invitation/registration UX for delivering the symmetric root~~
   Solved via tool accounts
5. Evaluate whether the login space SSO layer is needed for the music app's
   initial use case, or if per-space OPAQUE auth is sufficient
