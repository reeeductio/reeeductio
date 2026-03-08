# TypeScript Quick Start

This guide walks you through sending your first encrypted message with the TypeScript SDK.
It assumes you have a server running locally — see [Running the Server](running-the-server.md) if you haven't done that yet.

The SDK works in both Node.js (≥18) and the browser.

## Install the SDK

```bash
npm install reeeductio
```

## Create a space and send a message

Save the following as `quickstart.ts` and run it:

```typescript
import { writeFileSync } from 'node:fs';
import {
  Space,
  generateKeyPair,
  toSpaceId,
  toUserId,
  stringToBytes,
  bytesToString,
} from 'reeeductio';

// --- Step 1: Generate credentials ---
// The key pair is the root identity for this space.
// The symmetricRoot is the shared secret used to derive all encryption keys.
// Save both somewhere safe — you need them to reconnect to this space.
const keyPair = await generateKeyPair();
const symmetricRoot = crypto.getRandomValues(new Uint8Array(32));

const spaceId = toSpaceId(keyPair.publicKey);   // starts with 'S'
const userId  = toUserId(keyPair.publicKey);    // starts with 'U'

console.log('Space ID:         ', spaceId);
console.log('User ID:          ', userId);
console.log('Private key (hex):', Buffer.from(keyPair.privateKey).toString('hex'));
console.log('Symmetric root:   ', Buffer.from(symmetricRoot).toString('hex'));

// Save credentials so you can reconnect later
const creds = {
  spaceId,
  privateKeyHex: Buffer.from(keyPair.privateKey).toString('hex'),
  publicKeyHex:  Buffer.from(keyPair.publicKey).toString('hex'),
  symmetricRootHex: Buffer.from(symmetricRoot).toString('hex'),
};
writeFileSync('space_creds.json', JSON.stringify(creds, null, 2));
console.log('\nCredentials saved to space_creds.json');

// --- Step 2: Connect ---
// With auto_create_spaces enabled on the server, the space is created
// automatically the first time you connect to it.
const space = new Space({
  spaceId,
  keyPair,
  symmetricRoot,
  baseUrl: 'http://localhost:8000',
});

// --- Step 3: Post an encrypted message ---
// Messages are encrypted client-side before leaving your machine.
// The server never sees plaintext.
const topicId = 'general';
const result = await space.postEncryptedMessage(
  topicId,
  'chat.text',
  stringToBytes('Hello, encrypted world!')
);
console.log('\nPosted message:', result.message_hash);

// --- Step 4: Read it back ---
const { messages } = await space.getMessages(topicId);
console.log(`\nMessages in '${topicId}' (${messages.length} total):`);

for (const msg of messages) {
  const plaintext = bytesToString(space.decryptMessageData(msg, topicId));
  console.log(`  [${msg.message_hash.slice(0, 12)}...] ${plaintext}`);
}
```

Run it with Node.js (no compile step needed for `.ts` with modern tooling):

=== "tsx"

    ```bash
    npx tsx quickstart.ts
    ```

=== "Node.js --experimental-strip-types"

    ```bash
    node --experimental-strip-types quickstart.ts
    ```

=== "Compile first"

    ```bash
    npx tsc quickstart.ts --module nodenext --moduleresolution nodenext
    node quickstart.js
    ```

You should see output like:

```
Space ID:          S...
User ID:           U...
Private key (hex): ...
Symmetric root:    ...

Credentials saved to space_creds.json

Posted message: M...

Messages in 'general' (1 total):
  [Mxyz123abc456...] Hello, encrypted world!
```

## Reconnecting to an existing space

Your credentials are in `space_creds.json`. Load them to reconnect:

```typescript
import { readFileSync } from 'node:fs';
import { Space, bytesToString } from 'reeeductio';

const creds = JSON.parse(readFileSync('space_creds.json', 'utf8'));

const keyPair = {
  privateKey: Uint8Array.from(Buffer.from(creds.privateKeyHex, 'hex')),
  publicKey:  Uint8Array.from(Buffer.from(creds.publicKeyHex,  'hex')),
};
const symmetricRoot = Uint8Array.from(Buffer.from(creds.symmetricRootHex, 'hex'));

const space = new Space({
  spaceId: creds.spaceId,
  keyPair,
  symmetricRoot,
  baseUrl: 'http://localhost:8000',
});

const topicId = 'general';
const { messages } = await space.getMessages(topicId);

for (const msg of messages) {
  const plaintext = bytesToString(space.decryptMessageData(msg, topicId));
  console.log(plaintext);
}
```

!!! warning "Keep your credentials safe"
    The `privateKey` and `symmetricRoot` are the keys to your space.
    Anyone who has them can read and write everything in it.
    Never commit them to source control.

## Using the SDK in the browser

The SDK has no Node.js dependencies and works in modern browsers as-is.
Swap out the `node:fs` credential-saving code for `localStorage` or your app's
preferred storage, and everything else is identical:

```typescript
import { Space, generateKeyPair, toSpaceId, stringToBytes } from 'reeeductio';

const keyPair = await generateKeyPair();
const symmetricRoot = crypto.getRandomValues(new Uint8Array(32));

// Store credentials in localStorage (use a proper secure store in production)
localStorage.setItem('privateKey', btoa(String.fromCharCode(...keyPair.privateKey)));
localStorage.setItem('symmetricRoot', btoa(String.fromCharCode(...symmetricRoot)));

const space = new Space({
  spaceId: toSpaceId(keyPair.publicKey),
  keyPair,
  symmetricRoot,
  baseUrl: 'http://localhost:8000',
});

await space.postEncryptedMessage('general', 'chat.text', stringToBytes('Hello from the browser!'));
```

## What just happened?

- **Key generation**: `generateKeyPair()` created an Ed25519 keypair. The public key
  is encoded into your space ID (`S...`) and user ID (`U...`).
- **Key derivation**: `symmetricRoot` is used with HKDF to derive separate encryption
  keys per topic, state, blobs, and data — without you managing any of that.
- **Client-side encryption**: `postEncryptedMessage()` encrypted your message with
  AES-GCM before sending it. The server stored only ciphertext.
- **Decryption**: `space.decryptMessageData(msg, topicId)` derives the topic key and
  decrypts locally — the server is never involved in decryption.

## Next steps

- [Add more users to your space](../how-to/add-users.md)
- [Store encrypted files](../how-to/store-files.md)
- [Explore the full TypeScript SDK reference](../reference/typescript-sdk.md)
