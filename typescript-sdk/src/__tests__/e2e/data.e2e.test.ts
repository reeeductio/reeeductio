/**
 * E2E tests for key-value data store.
 *
 * Run with: npm run test:e2e
 * Requires: docker-compose -f backend/docker-compose.e2e.yml up -d
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { Space } from '../../client.js';
import { generateKeyPair, toSpaceId, stringToBytes, bytesToString } from '../../crypto.js';
import { NotFoundError } from '../../exceptions.js';
import { E2E_BACKEND_URL, waitForBackend, randomDataPath } from './setup.js';

describe('E2E: Data Store', () => {
  beforeAll(async () => {
    await waitForBackend();
  }, 60000);

  it('should store and retrieve plaintext data', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(1);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const path = randomDataPath();
    const content = { message: 'Hello from TypeScript SDK!', value: 42 };
    const dataBytes = stringToBytes(JSON.stringify(content));

    // Store data
    const result = await space.setPlaintextData(path, dataBytes);

    expect(result.path).toBe(path);
    expect(result.signed_at).toBeDefined();

    // Retrieve data
    const retrieved = await space.getPlaintextData(path);

    expect(retrieved).toBeInstanceOf(Uint8Array);
    const retrievedContent = JSON.parse(bytesToString(retrieved));
    expect(retrievedContent).toEqual(content);
  });

  it('should store and retrieve encrypted data', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(2);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const path = randomDataPath();
    const content = { secret: 'This is encrypted!', password: 'hunter2' };
    const dataBytes = stringToBytes(JSON.stringify(content));

    // Store encrypted data
    const result = await space.setEncryptedData(path, dataBytes);

    expect(result.path).toBe(path);

    // Retrieve and decrypt data
    const retrieved = await space.getEncryptedData(path);

    expect(retrieved).toBeInstanceOf(Uint8Array);
    const retrievedContent = JSON.parse(bytesToString(retrieved));
    expect(retrievedContent).toEqual(content);
  });

  it('should overwrite existing data', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(3);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const path = randomDataPath();

    // Store first value
    await space.setPlaintextData(path, stringToBytes('first'));

    // Overwrite with second value
    await space.setPlaintextData(path, stringToBytes('second'));

    // Retrieve should return second value
    const retrieved = await space.getPlaintextData(path);
    expect(bytesToString(retrieved)).toBe('second');
  });

  it('should throw NotFoundError for non-existent path', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(4);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const path = randomDataPath();

    await expect(space.getPlaintextData(path)).rejects.toThrow(NotFoundError);
  });

  it('should handle nested paths', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(5);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const basePath = `test/${Date.now()}`;
    const paths = [
      `${basePath}/level1/level2/item1`,
      `${basePath}/level1/level2/item2`,
      `${basePath}/level1/item3`,
    ];

    // Store data at each path
    for (const path of paths) {
      await space.setPlaintextData(path, stringToBytes(`data at ${path}`));
    }

    // Retrieve each
    for (const path of paths) {
      const retrieved = await space.getPlaintextData(path);
      expect(bytesToString(retrieved)).toBe(`data at ${path}`);
    }
  });

  it('should handle binary data', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(6);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const path = randomDataPath();

    // Create binary data with all byte values
    const binaryData = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      binaryData[i] = i;
    }

    // Store binary data
    await space.setPlaintextData(path, binaryData);

    // Retrieve and verify
    const retrieved = await space.getPlaintextData(path);

    expect(retrieved.length).toBe(256);
    for (let i = 0; i < 256; i++) {
      expect(retrieved[i]).toBe(i);
    }
  });
});
