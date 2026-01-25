# Login API
For convenience, the server can offer an oldschool "login" API with traditional username and password for backwards compatibility with legacy infrastructure like password managers.

The goal of the login API is to let a client use the oldschool username and password to safely derive a keypair.  Then the keypair can be used to authenticate to spaces using modern cryptographic methods.

NOTE that the login API does not need to be running on the same server where the user will eventually use their keypair to authenticate.

---

# Claude Design

## Overview

This design uses **OPAQUE** (RFC 9497) with **key wrapping** to enable password-based authentication while maintaining stable user identity across password changes. The core principle is separating password-derived keys (which change on rotation) from long-term identity keys (which remain stable).

### Architecture: Separate Login Service

The login functionality is implemented as a **separate HTTP backend service** (distinct from the space server) that uses the space API as its storage layer. This means:

- **Login Service**: New FastAPI application that handles `/api/v1/login/*` endpoints
  - Implements OPAQUE protocol flows (registration, login, password change)
  - Makes HTTP calls to the space server's REST API to store/retrieve state
  - Owns a dedicated "login space" for storing user records
  - No direct database - delegates all persistence to space server

- **Space Server**: Existing reeeductio backend
  - Provides storage via `/api/v1/spaces/{space_id}/state/{path}` endpoints
  - Unaware that login service is using it for storage
  - Handles authentication via Ed25519 challenge-response as usual

This separation provides defense in depth, independent scaling, and cleaner architecture.

## Architecture Goals

1. **Server never learns password** - OPAQUE ensures password privacy
2. **Stable user identity** - Password changes don't affect `user_id` or space memberships
3. **Key recovery** - Encrypted space keys survive password rotation
4. **Brute-force resistance** - Client-side Argon2 + server-side rate limiting
5. **Forward secrecy** - Old passwords cannot decrypt new wrappings
6. **Federated design** - Login server can be separate from space server

## Key Hierarchy

```
Password + Username
        │
        ├─> Argon2id(password, SHA256(username))
        │           │
        │           ├─> OPAQUE Protocol
        │                       │
        │                       ├─> export_key (32 bytes) ← CHANGES on password rotation
        │                                   │
        │                                   ├─> HKDF-SHA256
        │                                           │
        ├───────────────────────────────────────────┼─> key_wrapping_key (32 bytes)
        │                                           │       │
        │                                           │       └─> Wrap/Unwrap master_secret
        │                                                               │
        │                                                               ├─> Long-term auth_seed (32 bytes) → STABLE Ed25519 keypair
        │                                                               ├─> Long-term recovery_key (32 bytes) → Decrypt space keys
        │                                                               └─> Long-term backup_key (32 bytes) → Future use
```

### Critical Insight: Key Wrapping

The **master_secret** (96 random bytes) is generated ONCE during registration and contains:
- `long_term_auth_seed` (32 bytes) → Derives STABLE Ed25519 signing keypair → STABLE `user_id`
- `long_term_recovery_key` (32 bytes) → Encrypts/decrypts space private keys
- `long_term_backup_key` (32 bytes) → Reserved for encrypted cloud backups

The master_secret is **wrapped** (encrypted) with a password-derived `key_wrapping_key`. When the password changes:
1. Derive NEW `key_wrapping_key` from new password
2. **Re-wrap the SAME master_secret** with new key
3. Update server storage (only `opaque_record` and `wrapped_master_secret` change)
4. `user_id`, `auth_public_key`, and `encrypted_space_keys` remain UNCHANGED

**Result:** Password rotation does NOT affect user identity or space memberships.

## Protocol Flows

### Registration

**Client:**
1. Harden password: `Argon2id(password, SHA256(username))` (3 iterations, 64MB memory)
2. OPAQUE registration: Generate `registration_request`
3. Server responds with `registration_response`
4. Finalize OPAQUE: Get `export_key` and `registration_record`
5. Derive `key_wrapping_key` from `export_key` using HKDF-SHA256
6. Generate random `master_secret` (96 bytes, cryptographically secure)
7. Derive STABLE Ed25519 keypair from `master_secret[0:32]`
8. Encode `user_id` from Ed25519 public key (typed identifier: `U_...`)
9. Wrap `master_secret` with `key_wrapping_key` using AES-256-GCM
10. Encrypt space private keys with `long_term_recovery_key` using AES-256-GCM
11. Send to server: `username`, `user_id`, `auth_public_key`, `opaque_record`, `wrapped_master_secret`, `encrypted_space_keys`

**Server:**
Store in database:
- `username` (unique, primary key)
- `user_id` (STABLE, never changes)
- `auth_public_key` (STABLE, Ed25519 public key)
- `opaque_record` (OPAQUE server state)
- `wrapped_master_secret` (nonce + ciphertext, re-wrapped on password change)
- `encrypted_space_keys` (JSON: `{space_id: {nonce, ciphertext}}`)
- Timestamps, rate limiting metadata

### Login

**Client:**
1. Harden password: `Argon2id(password, SHA256(username))`
2. OPAQUE login: Generate `login_request`
3. Server responds with `login_response` + `wrapped_master_secret` + `encrypted_space_keys`
4. Finalize OPAQUE: Verify server, get `export_key`
5. Derive `key_wrapping_key` from `export_key` using HKDF-SHA256
6. Unwrap `master_secret` using `key_wrapping_key` + AES-256-GCM
7. Extract `long_term_auth_seed`, `long_term_recovery_key`, `long_term_backup_key`
8. Derive STABLE Ed25519 keypair from `long_term_auth_seed`
9. Verify `user_id` matches derived public key (integrity check)
10. Decrypt space keys using `long_term_recovery_key` + AES-256-GCM

**Server:**
1. Lookup user by `username`
2. Rate limiting check (exponential backoff after 3/5/10 failures)
3. OPAQUE verification using stored `opaque_record`
4. Return `login_response`, `wrapped_master_secret`, `encrypted_space_keys`
5. Log audit event

### Password Change

**Client:**
1. Login with old password to obtain `master_secret`
2. Start OPAQUE registration with NEW password
3. Derive NEW `key_wrapping_key` from new password's `export_key`
4. **Re-wrap SAME `master_secret`** with NEW `key_wrapping_key`
5. Send to server: `new_opaque_record`, `new_wrapped_master_secret`

**Server:**
1. Verify old password (via JWT token from login)
2. Atomic update: Replace `opaque_record` and `wrapped_master_secret`
3. **Do NOT change:** `user_id`, `auth_public_key`, `encrypted_space_keys`
4. Update `password_changed_at` timestamp
5. Invalidate all existing sessions (force re-login)

**Result:** User keeps same `user_id`, all space memberships preserved, all encrypted data remains accessible.

## Complete Authentication Flow

```
Client                    Login Service             Space Server
  │                             │                          │
  │  1. OPAQUE Login            │                          │
  ├────────────────────────────>│                          │
  │                             │  1a. Fetch user record   │
  │                             ├─────────────────────────>│
  │                             │      (GET /state/...)    │
  │                             │<─────────────────────────┤
  │  2. Login response          │                          │
  │<────────────────────────────┤                          │
  │  3. Unwrap master_secret    │                          │
  │     Derive Ed25519 keypair  │                          │
  │                             │                          │
  │  4. Request challenge       │                          │
  ├──────────────────────────────────────────────────────> │
  │  5. Challenge (nonce)       │                          │
  │<────────────────────────────────────────────────────── │
  │  6. Sign challenge          │                          │
  │  7. Submit signature        │                          │
  ├──────────────────────────────────────────────────────> │
  │  8. Verify signature        │                          │
  │     (using user_id pubkey)  │                          │
  │  9. Issue JWT token         │                          │
  │<────────────────────────────────────────────────────── │
  │  10. Decrypt space keys   │                          │
  │      using recovery_key     │                          │
```

**Deployment Options:**
- **Separate services** (recommended): Login service + Space service as independent deployments
- **Same process**: Both services running in one FastAPI app (simpler for development)
- **Federated**: Multiple organizations run separate login services, all storing to shared space infrastructure

## Cryptographic Primitives

### OPAQUE
- **Protocol:** OPAQUE-3DH (aligned with RFC 9497/draft-18)
- **Group:** ristretto255 (recommended) or P-256
- **Hash:** SHA-512 for OPAQUE internal operations
- **Backend Library:** [opaque-ke](https://github.com/facebook/opaque-ke) (Rust, maintained by Facebook/Meta)
- **Web Client Library:** [serenitykit/opaque](https://github.com/serenitykit/opaque) (TypeScript, compatible implementation)

### Password Hardening (Client-Side)
- **Algorithm:** Argon2id
- **Parameters:** time_cost=3, memory_cost=65536 (64 MB), parallelism=4
- **Salt:** `SHA256(username)` (deterministic, unique per user)
- **Output:** 32 bytes

### Key Derivation
- **Algorithm:** HKDF-SHA256
- **Salt:** `b"reeeductio-kwk-v1"` (versioned for crypto agility)
- **Info:** `username.encode()` (user-specific context)

### Key Wrapping
- **Algorithm:** AES-256-GCM
- **Key:** 32-byte `key_wrapping_key`
- **Nonce:** 12 random bytes (unique per wrap operation, cryptographically random)
- **AAD:** `f"master_secret|{username}|{user_id}"` (prevents ciphertext substitution)
- **Plaintext:** 96-byte `master_secret`
- **Ciphertext:** 112 bytes (96 + 16-byte auth tag)

### Space Key Encryption
- **Algorithm:** AES-256-GCM
- **Key:** 32-byte `long_term_recovery_key`
- **Nonce:** 12 random bytes per space key (cryptographically random)
- **AAD:** `space_id.encode()` (binds ciphertext to space)

### Ed25519 Signatures
- **Seed:** `long_term_auth_seed` (32 bytes from master_secret)
- **Derivation:** `Ed25519PrivateKey.from_private_bytes(seed)`
- **User ID:** Typed identifier from public key (`U_` prefix + 43-char base64)

## Storage: Space-Based (No Separate Database)

Instead of maintaining a separate database, the login server stores all user records as **signed state entries** in a dedicated reeeductio space. This provides:

- **No database dependency** - Reuses existing space state storage (SQLite/Firestore)
- **Built-in replication** - Space state is already persistent and replicated
- **Cryptographic audit trail** - All operations are signed by login server's private key
- **Federation-ready** - Multiple login servers can read/write to same space
- **Capability-based access** - Login server acts as admin of the login space

### Space Structure

The login server maintains a **Login Space** with ID derived from the server's Ed25519 public key:

```python
# Server configuration
LOGIN_SERVER_PRIVATE_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(
    config["login_server_seed"]  # 32-byte seed from config file
)
LOGIN_SERVER_PUBLIC_KEY = LOGIN_SERVER_PRIVATE_KEY.public_key()
LOGIN_SPACE_ID = encode_space_id(LOGIN_SERVER_PUBLIC_KEY.public_bytes_raw())
```

### State Entry Paths

All user data is stored under the `login/` path prefix in the space state:

```
/login/users/{username}                     # User account record
/login/users/{username}/wrapped_secret      # Wrapped master secret
/login/users/{username}/space_keys        # Encrypted space keys
/login/rate_limit/{username}                # Rate limiting state (ephemeral)
/login/audit/{timestamp}/{username}         # Audit log entries
```

### User Record Format

**Path:** `/login/users/{username}`

**Data (JSON):**
```json
{
  "user_id": "U_abc123...",
  "auth_public_key": "base64-ed25519-pubkey",
  "opaque_record": "base64-opaque-record",
  "created_at": 1704412800000,
  "password_changed_at": 1704412800000,
  "last_login_at": 1704412850000
}
```

**Signature:** Signed by login server's private key
**Signed by:** Login server tool ID or space creator ID

### Wrapped Master Secret

**Path:** `/login/users/{username}/wrapped_secret`

**Data (JSON):**
```json
{
  "nonce": "base64-nonce",
  "ciphertext": "base64-ciphertext",
  "algorithm": "AES-256-GCM",
  "wrapped_at": 1704412800000
}
```

### Encrypted Space Keys

**Path:** `/login/users/{username}/space_keys`

**Data (JSON):**
```json
{
  "C_space1": {
    "nonce": "base64-nonce",
    "ciphertext": "base64-ciphertext"
  },
  "C_space2": {
    "nonce": "base64-nonce",
    "ciphertext": "base64-ciphertext"
  }
}
```

### Rate Limiting State

**Path:** `/login/rate_limit/{username}`

**Data (JSON):**
```json
{
  "failed_attempts": 3,
  "locked_until": 1704412900000,
  "last_attempt_at": 1704412850000,
  "last_attempt_ip": "192.0.2.1"
}
```

**Note:** Rate limiting state can be ephemeral (cleared on server restart) or persistent.

### Audit Log

**Path:** `/login/audit/{timestamp}/{username}`

**Data (JSON):**
```json
{
  "event_type": "login_success",
  "username": "alice@example.com",
  "user_id": "U_abc123...",
  "ip_address": "192.0.2.1",
  "user_agent": "Mozilla/5.0...",
  "timestamp": 1704412850000,
  "metadata": {
    "client_version": "1.0.0"
  }
}
```

### Server Configuration

The login service is a **separate FastAPI application** with the following configuration:

1. **Ed25519 Private Key** (32-byte seed in config file)
   - Derives login space ID (login service is the space creator)
   - Signs all state entries written to the space
   - God mode on login space (implicit admin rights as creator)

2. **Space Server API Endpoint** (where to store state)
   - HTTP(S) URL to the space server's REST API
   - Login service makes HTTP calls to `/api/v1/spaces/{space_id}/state/{path}` endpoints
   - Authenticated via Ed25519 challenge-response using login service's private key

3. **OPAQUE Server Identity** (domain name for protocol binding)

**Example config.yaml:**
```yaml
login_service:
  # Listen address for the login HTTP service
  host: "0.0.0.0"
  port: 8001

  # 32-byte hex-encoded seed for Ed25519 keypair
  private_key_seed: "a1b2c3d4e5f6..."

  # Space server API endpoint for state storage
  space_api_url: "https://api.reeeductio.com"
  # OR for local development:
  # space_api_url: "http://localhost:8000"

  # Server identity for OPAQUE protocol
  server_identity: "login.reeeductio.com"

  # Rate limiting configuration
  rate_limit:
    max_attempts_before_lockout: 3
    lockout_durations: [60, 300, 3600]  # seconds
```

**Directory Structure:**
```
reeeductio/
├── backend/           # Existing space server
│   ├── main.py
│   ├── space.py
│   └── ...
└── login-service/     # New login service
    ├── main.py        # FastAPI app for login endpoints
    ├── opaque.py      # OPAQUE protocol implementation
    ├── storage.py     # SpaceAPIClient for state storage
    ├── config.yaml    # Login service configuration
    └── requirements.txt
```

### Implementation: State Operations

The login service uses an HTTP client to interact with the space server's REST API:

```python
import httpx
from cryptography.hazmat.primitives.asymmetric import ed25519

class SpaceAPIClient:
    """HTTP client for storing login data in space state via REST API"""

    def __init__(self, api_url: str, server_private_key: ed25519.Ed25519PrivateKey):
        self.api_url = api_url.rstrip('/')
        self.private_key = server_private_key
        self.public_key = server_private_key.public_key()
        self.space_id = encode_space_id(self.public_key.public_bytes_raw())
        self.http_client = httpx.AsyncClient(timeout=10.0)

    async def authenticate(self) -> str:
        """Perform Ed25519 challenge-response to get JWT token"""
        # Request challenge
        resp = await self.http_client.post(
            f"{self.api_url}/api/v1/auth/challenge",
            json={"user_id": encode_user_id(self.public_key.public_bytes_raw())}
        )
        challenge = resp.json()["challenge"]

        # Sign challenge
        signature = self.private_key.sign(challenge.encode())

        # Submit signature
        resp = await self.http_client.post(
            f"{self.api_url}/api/v1/auth/verify",
            json={
                "challenge": challenge,
                "signature": base64.b64encode(signature).decode()
            }
        )
        return resp.json()["token"]

class LoginStore:
    def __init__(self, space_client: SpaceAPIClient):
        self.client = space_client
        self.space_id = space_client.space_id
        self._token = None

    async def _ensure_authenticated(self):
        """Ensure we have a valid JWT token"""
        if not self._token:
            self._token = await self.client.authenticate()

    def _headers(self) -> dict:
        """Get HTTP headers with auth token"""
        return {"Authorization": f"Bearer {self._token}"}

    async def get_user(self, username: str) -> Optional[Dict]:
        """Fetch user record from space state via HTTP API"""
        await self._ensure_authenticated()
        path = f"login/users/{username}"

        resp = await self.client.http_client.get(
            f"{self.client.api_url}/api/v1/spaces/{self.space_id}/state/{path}",
            headers=self._headers()
        )

        if resp.status_code == 404:
            return None

        state = resp.json()
        # Decode base64 data
        data_bytes = base64.b64decode(state["data"])
        return json.loads(data_bytes)

    async def create_user(self, username: str, user_data: Dict) -> None:
        """Create new user record (signed state entry) via HTTP API"""
        await self._ensure_authenticated()
        path = f"login/users/{username}"
        data = json.dumps(user_data).encode()

        # Sign the state entry
        signed_at = int(time.time() * 1000)
        message = f"{self.space_id}|{path}|{base64.b64encode(data).decode()}|{signed_at}"
        signature = self.client.private_key.sign(message.encode())

        # POST to space state API
        resp = await self.client.http_client.post(
            f"{self.client.api_url}/api/v1/spaces/{self.space_id}/state/{path}",
            headers=self._headers(),
            json={
                "data": base64.b64encode(data).decode(),
                "signature": base64.b64encode(signature).decode(),
                "signed_by": encode_user_id(self.client.public_key.public_bytes_raw()),
                "signed_at": signed_at
            }
        )
        resp.raise_for_status()

    async def update_user(self, username: str, updates: Dict) -> None:
        """Update user record (overwrites state entry)"""
        user = await self.get_user(username)
        if not user:
            raise ValueError(f"User {username} not found")

        user.update(updates)
        await self.create_user(username, user)

    async def store_wrapped_secret(self, username: str, wrapped_data: Dict) -> None:
        """Store wrapped master secret"""
        path = f"login/users/{username}/wrapped_secret"
        data = json.dumps(wrapped_data).encode()

        signed_at = int(time.time() * 1000)
        message = f"{self.space_id}|{path}|{base64.b64encode(data).decode()}|{signed_at}"
        signature = self.private_key.sign(message.encode())

        await self.client.set_state(
            space_id=self.space_id,
            path=path,
            data=base64.b64encode(data).decode(),
            signature=base64.b64encode(signature).decode(),
            signed_by=encode_user_id(self.private_key.public_key().public_bytes_raw()),
            signed_at=signed_at
        )

    async def get_wrapped_secret(self, username: str) -> Optional[Dict]:
        """Fetch wrapped master secret"""
        path = f"login/users/{username}/wrapped_secret"
        state = await self.client.get_state(self.space_id, path)
        return json.loads(state["data"]) if state else None

    async def store_space_keys(self, username: str, encrypted_keys: Dict) -> None:
        """Store encrypted space keys"""
        path = f"login/users/{username}/space_keys"
        data = json.dumps(encrypted_keys).encode()

        signed_at = int(time.time() * 1000)
        message = f"{self.space_id}|{path}|{base64.b64encode(data).decode()}|{signed_at}"
        signature = self.private_key.sign(message.encode())

        await self.client.set_state(
            space_id=self.space_id,
            path=path,
            data=base64.b64encode(data).decode(),
            signature=base64.b64encode(signature).decode(),
            signed_by=encode_user_id(self.private_key.public_key().public_bytes_raw()),
            signed_at=signed_at
        )

    async def get_space_keys(self, username: str) -> Optional[Dict]:
        """Fetch encrypted space keys"""
        path = f"login/users/{username}/space_keys"
        state = await self.client.get_state(self.space_id, path)
        return json.loads(state["data"]) if state else None

    async def log_audit_event(self, username: str, event_data: Dict) -> None:
        """Write audit log entry"""
        timestamp = int(time.time() * 1000)
        path = f"login/audit/{timestamp}/{username}"
        data = json.dumps(event_data).encode()

        message = f"{self.space_id}|{path}|{base64.b64encode(data).decode()}|{timestamp}"
        signature = self.private_key.sign(message.encode())

        await self.client.set_state(
            space_id=self.space_id,
            path=path,
            data=base64.b64encode(data).decode(),
            signature=base64.b64encode(signature).decode(),
            signed_by=encode_user_id(self.private_key.public_key().public_bytes_raw()),
            signed_at=timestamp
        )
```

### Advantages of Space-Based Storage

1. **Zero Additional Infrastructure**
   - No PostgreSQL, MySQL, or separate database to manage
   - Reuses existing state_store infrastructure (SQLite/Firestore)

2. **Cryptographic Integrity**
   - All user records are signed by login server
   - Tampering is detectable via signature verification
   - Audit trail is immutable (state entries are append-only)

3. **Federation-Ready**
   - Multiple login servers can operate on same space
   - Read-after-write consistency via space state
   - Each server signs with its own private key

4. **Capability-Based Security**
   - Login server has god mode on its space (creator privilege)
   - Can delegate read-only access to monitoring tools
   - Fine-grained path-based permissions

5. **Built-In Replication**
   - If space server uses Firestore → automatic multi-region replication
   - If space server uses SQLite → can sync space state files
   - State is portable across deployments

6. **Privacy-Preserving**
   - Space state can be encrypted (future enhancement)
   - Server only stores opaque OPRF records (no passwords)
   - Separation from space data (different space ID)

### Querying Users

Since spaces don't have SQL-style indexing, we use two strategies:

**1. Direct Lookup (O(1))**
```python
# Lookup by username (primary key)
user = await store.get_user("alice@example.com")
```

**2. List All Users (O(n))**
```python
# List all users under /login/users/ prefix
users = await client.list_state(space_id, "login/users/")
# Returns: ["login/users/alice@example.com", "login/users/bob@example.com", ...]
```

**3. User ID Lookup (requires iteration)**
```python
async def get_user_by_id(user_id: str) -> Optional[Dict]:
    """Find user by user_id (requires scanning all users)"""
    users = await client.list_state(space_id, "login/users/")
    for user_path in users:
        # Skip nested paths (wrapped_secret, space_keys)
        if user_path.count('/') > 3:
            continue

        state = await client.get_state(space_id, user_path)
        user_data = json.loads(state["data"])
        if user_data["user_id"] == user_id:
            return user_data
    return None
```

**Optimization:** Cache `user_id → username` mapping in memory (invalidate on password change).

### Migration from SQL Database (If Needed)

If you already have a SQL database, migration is straightforward:

```python
async def migrate_from_sql_to_space():
    """Migrate existing SQL users to space state"""
    sql_users = db.execute("SELECT * FROM login_users")

    for sql_user in sql_users:
        # Create user record
        await store.create_user(sql_user["username"], {
            "user_id": sql_user["user_id"],
            "auth_public_key": sql_user["auth_public_key"],
            "opaque_record": sql_user["opaque_record"],
            "created_at": sql_user["created_at"],
            "password_changed_at": sql_user["password_changed_at"],
            "last_login_at": sql_user["last_login_at"]
        })

        # Store wrapped secret
        await store.store_wrapped_secret(sql_user["username"], {
            "nonce": sql_user["wrapped_master_secret_nonce"],
            "ciphertext": sql_user["wrapped_master_secret_ciphertext"],
            "algorithm": sql_user["wrapping_algorithm"]
        })

        # Store space keys
        space_keys = json.loads(sql_user["encrypted_space_keys"])
        await store.store_space_keys(sql_user["username"], space_keys)
```

### Rate Limiting with Space State

Rate limiting can be:

**Option A: Ephemeral (in-memory)**
- Fast, simple
- Lost on server restart (acceptable for rate limits)
- Use Python dict: `rate_limits[username] = {failed_attempts, locked_until}`

**Option B: Persistent (space state)**
- Survives restarts
- Shared across multiple login servers
- Slightly slower (network round-trip)

**Hybrid Approach:**
```python
class RateLimiter:
    def __init__(self, store: SpaceBasedLoginStore):
        self.store = store
        self.cache = {}  # In-memory cache

    async def check_rate_limit(self, username: str) -> None:
        # Check cache first
        if username in self.cache:
            limit_data = self.cache[username]
        else:
            # Fetch from space state
            path = f"login/rate_limit/{username}"
            state = await self.store.client.get_state(self.store.space_id, path)
            limit_data = json.loads(state["data"]) if state else {"failed_attempts": 0}
            self.cache[username] = limit_data

        # Check if locked
        now = int(time.time() * 1000)
        if limit_data.get("locked_until", 0) > now:
            remaining = (limit_data["locked_until"] - now) // 1000
            raise RateLimitError(f"Account locked for {remaining}s")

    async def record_failure(self, username: str) -> None:
        limit_data = self.cache.get(username, {"failed_attempts": 0})
        limit_data["failed_attempts"] += 1
        limit_data["last_attempt_at"] = int(time.time() * 1000)

        # Calculate lockout
        if limit_data["failed_attempts"] >= 10:
            limit_data["locked_until"] = limit_data["last_attempt_at"] + 3600000
        elif limit_data["failed_attempts"] >= 5:
            limit_data["locked_until"] = limit_data["last_attempt_at"] + 300000
        elif limit_data["failed_attempts"] >= 3:
            limit_data["locked_until"] = limit_data["last_attempt_at"] + 60000

        self.cache[username] = limit_data

        # Persist to space state (async, non-blocking)
        asyncio.create_task(self._persist_rate_limit(username, limit_data))
```

## API Endpoints

### POST /api/v1/login/register
**Request:**
```json
{
  "username": "alice@example.com",
  "registration_request": "base64-opaque-request",
  "client_version": "1.0.0"
}
```

**Response:**
```json
{
  "registration_response": "base64-opaque-response",
  "server_identity": "login.reeeductio.com"
}
```

### POST /api/v1/login/finalize-registration
**Request:**
```json
{
  "username": "alice@example.com",
  "user_id": "U_abc123...",
  "auth_public_key": "base64-ed25519-pubkey",
  "opaque_record": "base64-record",
  "wrapped_master_secret": {
    "nonce": "base64-nonce",
    "ciphertext": "base64-ciphertext",
    "algorithm": "AES-256-GCM"
  },
  "encrypted_space_keys": {
    "C_space1": {"nonce": "...", "ciphertext": "..."}
  }
}
```

### POST /api/v1/login/start
**Request:**
```json
{
  "username": "alice@example.com",
  "login_request": "base64-opaque-request"
}
```

**Response:**
```json
{
  "login_response": "base64-opaque-response",
  "user_id": "U_abc123...",
  "wrapped_master_secret": {"nonce": "...", "ciphertext": "..."},
  "encrypted_space_keys": {...}
}
```

### POST /api/v1/login/change-password/finalize
**Request:**
```json
{
  "username": "alice@example.com",
  "user_id": "U_abc123...",
  "new_opaque_record": "base64-record",
  "new_wrapped_master_secret": {"nonce": "...", "ciphertext": "..."}
}
```

**Response:**
```json
{
  "success": true,
  "user_id": "U_abc123...",
  "password_changed_at": 1704412800000
}
```

## Security Properties

### Threat Mitigations

| Threat | Mitigation |
|--------|-----------|
| Password database breach | OPAQUE record useless without password; no plaintext/hash stored |
| Server compromise | Server cannot derive keys or impersonate users |
| Online brute force | Rate limiting with exponential backoff (1 min → 5 min → 1 hour) |
| Offline brute force | Client-side Argon2 makes each guess expensive (~100ms) |
| Credential stuffing | Argon2 salt = SHA256(username) prevents rainbow tables |
| Phishing | OPAQUE binds to server identity; fake servers fail verification |
| MITM attack | TLS required; OPAQUE provides mutual authentication |
| Username enumeration | Timing-safe fake responses for non-existent users |
| Replay attacks | OPAQUE uses fresh randomness per attempt |
| Ciphertext substitution | AES-GCM AAD binds wrapped_master_secret to user context |
| Nonce reuse | Cryptographically random 96-bit nonces prevent collisions (2^48 birthday bound) |

### Rate Limiting Policy

```python
failed_attempts → lockout_duration
0-2            → No lockout
3-4            → 60 seconds
5-9            → 300 seconds (5 minutes)
10+            → 3600 seconds (1 hour)
```

Lockout resets on successful login.

## Implementation Libraries

### Backend (Rust/Python)
- **OPAQUE:** [facebook/opaque-ke](https://github.com/facebook/opaque-ke) - Rust implementation aligned with RFC 9497
  - Implements OPAQUE-3DH with ristretto255 or P-256 groups
  - Well-maintained by Meta's security team
  - Can be called from Python via FFI bindings if needed
- **Argon2:** Standard `argon2` crate (Rust) or `argon2-cffi` (Python)
- **HKDF/AES-GCM:** Built into `cryptography` crate (Rust) or library (Python)
- **Ed25519:** `ed25519-dalek` (Rust) or `cryptography` (Python)

### Web Client (TypeScript/JavaScript)
- **OPAQUE:** [serenitykit/opaque](https://github.com/serenitykit/opaque) - TypeScript/WASM implementation
  - Compatible with opaque-ke protocol version
  - Pure JavaScript with WASM for performance-critical operations
  - Supports both Node.js and browser environments
- **Argon2:** [@noble/hashes](https://github.com/paulmillr/noble-hashes) - Pure JS implementation (no WASM required)
  - Includes Argon2id with configurable parameters
  - ~50KB minified, well-audited
- **HKDF/AES-GCM:** Native WebCrypto API (`crypto.subtle`)
  - `crypto.subtle.importKey()` + `crypto.subtle.deriveKey()` for HKDF
  - `crypto.subtle.encrypt()` / `crypto.subtle.decrypt()` for AES-GCM
- **Ed25519:** Native WebCrypto API (Chrome 137+, Firefox 129+, Safari 17.0+)
  - `crypto.subtle.generateKey("Ed25519")` for keypair generation
  - `crypto.subtle.sign()` / `crypto.subtle.verify()` for signatures
  - For older browsers: [@noble/ed25519](https://github.com/paulmillr/noble-ed25519) polyfill

### Library Compatibility Note

The combination of **opaque-ke** (backend) and **serenitykit/opaque** (frontend) ensures protocol compatibility:
- Both implement the modern OPAQUE specification (aligned with RFC 9497/draft-18)
- Both support ristretto255 and P-256 elliptic curve groups
- Both use the same OPRF construction from RFC 9497

**Avoid using cloudflare/opaque-ts** - it implements the outdated draft-07 specification and is NOT compatible with modern OPAQUE implementations.

## Implementation Checklist

### Backend (Login Server)
- [ ] Install `opaque-ke` Rust library (or Python bindings)
- [ ] Create space-based storage infrastructure
- [ ] Implement registration endpoints
- [ ] Implement login endpoints
- [ ] Implement password change endpoints
- [ ] Add rate limiting middleware
- [ ] Add timing-safe username enumeration prevention
- [ ] Add audit logging
- [ ] Add TLS/HTTPS enforcement
- [ ] Write integration tests

### Client
- [ ] Install dependencies: OPAQUE, `cryptography`, `argon2-cffi`
- [ ] Implement registration flow
- [ ] Implement login flow
- [ ] Implement password change flow
- [ ] Implement key derivation (HKDF)
- [ ] Implement key wrapping (AES-GCM)
- [ ] Implement space key encryption (AES-256-GCM)
- [ ] Implement secure key storage (OS keychain)
- [ ] Implement password validation (entropy + HIBP check)
- [ ] Write unit tests

### Security Audit
- [ ] Code review by security team
- [ ] Penetration testing (brute force, timing attacks)
- [ ] Verify constant-time operations in OPAQUE library
- [ ] Test rate limiting effectiveness
- [ ] Verify TLS configuration (A+ on SSL Labs)
- [ ] Review audit logging coverage

## Comparison: With vs Without Key Wrapping

### Without Key Wrapping (Naive Approach)
```
Password Change:
Old Password → Old export_key → Old auth_seed → Old Ed25519 keypair → Old user_id (U_abc)
New Password → New export_key → New auth_seed → New Ed25519 keypair → New user_id (U_xyz)

Result: Different user_id → Lost space memberships → Need re-invitation ❌
```

### With Key Wrapping (This Design)
```
Registration:
Password → export_key → KWK → Wrap(master_secret) → Store wrapped blob
master_secret → STABLE auth_seed → STABLE Ed25519 keypair → STABLE user_id (U_abc)

Password Change:
Old Password → Old KWK → Unwrap(master_secret)
New Password → New KWK → Re-wrap(SAME master_secret)

Result: SAME user_id → Space memberships preserved → No re-invitation ✅
```

## Future Enhancements

### Account Recovery
- **Recovery codes:** Generate 10 random codes during registration, encrypted server-side
- **Social recovery:** Shamir Secret Sharing with trusted friends (2-of-3 threshold)
- **Hardware tokens:** YubiKey/FIDO2 as backup authentication method

### Multi-Factor Authentication
- **FIDO2/WebAuthn:** Hardware security keys as second factor
- **TOTP:** Time-based one-time passwords (Google Authenticator)
- **Hybrid:** `final_seed = HKDF(auth_seed || hardware_attestation)`

### Key Rotation Policy
- Configurable password expiry (e.g., 90 days for high-security deployments)
- Automated re-encryption of space keys on rotation
- Audit trail of all password changes

### Federated Deployment
- Multiple organizations run separate login servers
- Space server accepts Ed25519 signatures from any federation member
- Privacy: Space server never sees passwords, only public keys