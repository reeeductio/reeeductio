# TypeScript SDK Reference

**Package:** `@reeeductio/client`
**Requires:** Node.js ≥ 18 or a modern browser (Web Crypto API required)

The main entry point is the `Space` class:

```typescript
import { Space } from '@reeeductio/client';
```

---

## `Space`

High-level client for interacting with a rEEEductio space.

### Constructor

```typescript
new Space({
  spaceId: string,
  keyPair: KeyPair,
  symmetricRoot: Uint8Array,
  baseUrl?: string,
  fetch?: typeof fetch,
  localStore?: MessageStore,
})
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `spaceId` | `string` | 44-char space identifier (`S...`) |
| `keyPair` | `KeyPair` | Ed25519 key pair for signing |
| `symmetricRoot` | `Uint8Array` | 32-byte root encryption key |
| `baseUrl` | `string` | Server URL (default: `http://localhost:8000`) |
| `fetch` | `typeof fetch` | Custom fetch implementation (Node.js or browser) |
| `localStore` | `MessageStore \| undefined` | Optional local message cache |

```typescript
const space = new Space({
  spaceId: 'S...',
  keyPair: { privateKey, publicKey },
  symmetricRoot,
  baseUrl: 'https://my-server.example.com',
});
```

### Derived attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `spaceId` | `string` | Space identifier |
| `keyPair` | `KeyPair` | This member's key pair |
| `messageKey` | `Uint8Array` | Derived message encryption key |
| `stateKey` | `Uint8Array` | Derived state encryption key |
| `dataKey` | `Uint8Array` | Derived data encryption key |

### `getUserId() → string`

Returns the user ID derived from this space's key pair.

```typescript
const userId = space.getUserId(); // 'U...'
```

---

## Authentication

### `authenticate() → Promise<string>`

Perform challenge-response authentication. Returns a JWT token. Usually called automatically on the first API call.

```typescript
const token = await space.authenticate();
```

### `static Space.fromOpaqueLogin(options) → Promise<Space>`

Create a `Space` by logging in with a username and password via OPAQUE.

```typescript
const space = await Space.fromOpaqueLogin({
  baseUrl: 'https://my-server.example.com',
  spaceId: 'S...',
  username: 'alice',
  password: 'my-password',
});
```

---

## Messages

### `postMessage(topicId, msgType, data, prevHash?) → Promise<MessageCreated>`

Post raw (unencrypted) bytes to a topic.

```typescript
const result = await space.postMessage('general', 'chat.text', encryptedBytes);
console.log(result.message_hash); // M...
```

### `postEncryptedMessage(topicId, msgType, plaintext, prevHash?) → Promise<MessageCreated>`

Encrypt `plaintext` client-side with the topic key, then post it.

```typescript
const encoder = new TextEncoder();
const result = await space.postEncryptedMessage(
  'general',
  'chat.text',
  encoder.encode('Hello!')
);
```

### `decryptMessageData(msg, topicId) → Uint8Array`

Decrypt the `data` field of a message returned by `getMessages`.

```typescript
const messages = await space.getMessages('general');
for (const msg of messages.messages) {
  const plaintext = space.decryptMessageData(msg, 'general');
  console.log(new TextDecoder().decode(plaintext));
}
```

### `getMessages(topicId, query?, options?) → Promise<MessagesResponse>`

Retrieve messages from a topic. Results are ordered by `server_timestamp` ascending.

```typescript
const result = await space.getMessages('general', { limit: 50 });
for (const msg of result.messages) {
  const text = space.decryptMessageData(msg, 'general');
}
```

| Query field | Type | Description |
|-------------|------|-------------|
| `from` | `number` | Start timestamp (ms) |
| `to` | `number` | End timestamp (ms) |
| `limit` | `number` | Max messages (default 100, max 1000) |

### `getMessage(topicId, messageHash, options?) → Promise<Message>`

Retrieve a single message by its hash.

```typescript
const msg = await space.getMessage('general', 'M...');
```

### `deriveTopicKey(topicId) → Uint8Array`

Derive the 32-byte encryption key for a topic. Rarely needed directly.

---

## State

### `getPlaintextState(path) → Promise<Uint8Array>`

Get the current value at a state path as raw bytes.

```typescript
const data = await space.getPlaintextState('profiles/alice');
const profile = JSON.parse(new TextDecoder().decode(data));
```

### `getEncryptedState(path) → Promise<Uint8Array>`

Get and decrypt the value at a state path.

### `setPlaintextState(path, data, prevHash?) → Promise<MessageCreated>`

Write bytes to a state path.

```typescript
const encoder = new TextEncoder();
await space.setPlaintextState(
  'profiles/alice',
  encoder.encode(JSON.stringify({ name: 'Alice' }))
);
```

### `setEncryptedState(path, data, prevHash?) → Promise<MessageCreated>`

Encrypt and write a value to a state path.

### `getStateHistory(query?) → Promise<MessagesResponse>`

Retrieve the full event log of state changes.

---

## Blobs

### `encryptAndUploadBlob(data, associatedData?) → Promise<EncryptedBlobCreated>`

Encrypt `data` with a random per-blob DEK and upload it. Returns `blob_id` and `key` (the DEK).

```typescript
const result = await space.encryptAndUploadBlob(fileBytes);
// Save result.blob_id and result.key — you need both to download
```

### `downloadAndDecryptBlob(blobId, key, associatedData?) → Promise<Uint8Array>`

Download and decrypt a blob using its DEK.

```typescript
const data = await space.downloadAndDecryptBlob(blobId, dek);
```

### `uploadPlaintextBlob(data) → Promise<BlobCreated>`

Upload unencrypted bytes. Returns `blob_id`.

### `downloadPlaintextBlob(blobId) → Promise<Uint8Array>`

Download unencrypted bytes.

### `deleteBlob(blobId) → Promise<void>`

Delete a blob.

---

## Data (KV store)

### `getPlaintextData(path) → Promise<Uint8Array>`

Get a value from the key-value store.

### `getEncryptedData(path) → Promise<Uint8Array>`

Get and decrypt a value.

### `setPlaintextData(path, data) → Promise<DataSetResponse>`

Set a value. Returns the response with a signed timestamp.

### `setEncryptedData(path, data) → Promise<DataSetResponse>`

Encrypt and set a value.

---

## Authorization

### `createUser(userId, description?, prevHash?) → Promise<MessageCreated>`

Register a user in the space (writes to `auth/users/{userId}`).

### `createTool(description, options?) → Promise<ToolCreated>`

Register a tool account. Returns a `ToolCreated` with the tool's `keyPair`.

```typescript
const { keyPair, tool } = await space.createTool('CI/CD poster');
// Save keyPair.privateKey securely
```

### `createRole(roleName, description?, prevHash?) → Promise<MessageCreated>`

Create a role definition.

### `grantCapabilityToRole(roleName, capId, capability, prevHash?) → Promise<MessageCreated>`

Grant a capability to a role. `capability` is `{ op: 'read' | 'create' | ..., path: '...' }`.

### `assignRoleToUser(userId, roleName, prevHash?) → Promise<MessageCreated>`

Assign a role to a user.

### `grantCapabilityToUser(userId, capId, capability, prevHash?) → Promise<MessageCreated>`

Grant a direct capability to a user.

### `grantCapabilityToTool(toolId, capId, capability, prevHash?) → Promise<MessageCreated>`

Grant a capability to a tool.

---

## WebSocket

### `getWebSocketConnectionUrl() → Promise<string>`

Get an authenticated WebSocket URL. The token is embedded in the URL query string.

```typescript
const wsUrl = await space.getWebSocketConnectionUrl();
const ws = new WebSocket(wsUrl);
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data) as Message;
  const plaintext = space.decryptMessageData(msg, msg.topic_id);
};
```

### `handleIncomingMessage(message) → Promise<void>`

Process and cache an incoming WebSocket message in the local store.

---

## Crypto utilities

```typescript
import {
  generateKeyPair,
  toSpaceId,
  toUserId,
  toToolId,
  stringToBytes,
  bytesToString,
  encodeBase64,
  decodeBase64,
  encodeUrlSafeBase64,
  decodeUrlSafeBase64,
  deriveKey,
} from '@reeeductio/client';
```

### `generateKeyPair() → Promise<KeyPair>`

Returns `{ privateKey, publicKey }` as 32-byte `Uint8Array` values.

### `toSpaceId(publicKey) → string`

Encode an Ed25519 public key as a space ID (`S...`).

### `toUserId(publicKey) → string`

Encode as a user ID (`U...`).

### `toToolId(publicKey) → string`

Encode as a tool ID (`T...`).

### `deriveKey(rootKey, info, length?) → Uint8Array`

Derive a key using HKDF-SHA256.

---

## OPAQUE (password-based key recovery)

### `opaqueRegister(username, password) → Promise<OpaqueRegistrationResult>`

Register OPAQUE credentials for the current user.

### `enableOpaque() → Promise<EnableOpaqueResult>`

Enable OPAQUE for this space (admin only).

---

## Exceptions

| Exception | When raised |
|-----------|-------------|
| `AuthenticationError` | Challenge-response or token refresh failed |
| `AuthorizationError` | Server returned 403 |
| `NotFoundError` | Resource does not exist (404) |
| `ValidationError` | Invalid request or data (400) |
| `ChainError` | Message chain conflict (409) |
| `BlobError` | Blob upload or download failed |
| `OpaqueError` | OPAQUE protocol error |
| `OpaqueNotEnabledError` | OPAQUE not enabled on server (501) |
| `OpaqueRateLimitError` | Too many OPAQUE attempts (429) |
| `StreamError` | WebSocket stream error |

```typescript
import { NotFoundError, ChainError } from '@reeeductio/client';

try {
  const data = await space.getPlaintextState('profiles/alice');
} catch (e) {
  if (e instanceof NotFoundError) {
    console.log('No profile yet');
  }
}
```

---

## Models

Key types returned by SDK methods:

| Type | Fields |
|------|--------|
| `Message` | `message_hash`, `topic_id`, `prev_hash`, `type`, `data`, `sender`, `signature`, `server_timestamp` |
| `MessagesResponse` | `messages: Message[]`, `has_more: boolean` |
| `MessageCreated` | `message_hash`, `server_timestamp` |
| `BlobCreated` | `blob_id`, `size` |
| `EncryptedBlobCreated` | `blob_id`, `size`, `key` (32-byte DEK as `Uint8Array`) |
| `DataSetResponse` | `path`, `signed_at` |
| `KeyPair` | `privateKey: Uint8Array`, `publicKey: Uint8Array` |
| `Capability` | `op: CapabilityOp`, `path: string` |
| `ToolCreated` | `tool_id`, `keyPair`, `description` |

### `CapabilityOp`

```typescript
type CapabilityOp = 'read' | 'create' | 'modify' | 'delete' | 'write';
```

---

## Local message store

The SDK ships two `MessageStore` implementations for offline-first caching:

| Class | Environment | Backend |
|-------|-------------|---------|
| `InMemoryMessageStore` | Node.js or browser | In-memory map |
| `IndexedDBMessageStore` | Browser only | IndexedDB |

```typescript
import { Space, InMemoryMessageStore } from '@reeeductio/client';

const store = new InMemoryMessageStore();
const space = new Space({ ..., localStore: store });
```
