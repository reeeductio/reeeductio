/**
 * E2E tests for state management.
 *
 * Run with: npm run test:e2e
 * Requires: docker-compose -f backend/docker-compose.e2e.yml up -d
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { Space } from '../../client.js';
import { generateKeyPair, toSpaceId, decodeBase64, bytesToString } from '../../crypto.js';
import { NotFoundError } from '../../exceptions.js';
import { E2E_BACKEND_URL, waitForBackend, randomStatePath } from './setup.js';

/** Helper to decode base64 state data returned by getPlaintextState */
function decodePlaintext(base64: string): string {
  return bytesToString(decodeBase64(base64));
}

describe('E2ET: State', () => {
  beforeAll(async () => {
    await waitForBackend();
  }, 60000);

  it('should set and get plaintext state', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(1);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const path = randomStatePath();
    const stateData = 'Hello from state e2e test!';

    // Set state
    const result = await space.setPlaintextState(path, stateData, null);

    expect(result.message_hash).toBeDefined();
    expect(result.message_hash[0]).toBe('M');
    expect(result.server_timestamp).toBeDefined();

    // Get state (returns base64, need to decode)
    const retrieved = await space.getPlaintextState(path);

    expect(decodePlaintext(retrieved)).toBe(stateData);
  });

  it('should set and get encrypted state', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(2);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const path = randomStatePath();
    const stateData = 'Secret state data!';

    // Set encrypted state
    const result = await space.setEncryptedState(path, stateData, null);

    expect(result.message_hash).toBeDefined();

    // Get and decrypt state
    const retrieved = await space.getEncryptedState(path);

    expect(retrieved).toBe(stateData);
  });

  it('should update state with new value', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(3);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const path = randomStatePath();

    // Set initial state
    const result1 = await space.setPlaintextState(path, 'initial value', null);

    // Update state (prev_hash should be auto-fetched)
    const result2 = await space.setPlaintextState(path, 'updated value');

    expect(result2.message_hash).not.toBe(result1.message_hash);

    // Get current state - should be the updated value
    const retrieved = await space.getPlaintextState(path);

    expect(decodePlaintext(retrieved)).toBe('updated value');
  });

  it('should track state history', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(4);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const path1 = randomStatePath();
    const path2 = randomStatePath();

    // Set state at multiple paths
    await space.setPlaintextState(path1, 'value at path1', null);
    await space.setPlaintextState(path2, 'value at path2');
    await space.setPlaintextState(path1, 'updated path1');

    // Get state history
    const { messages, has_more } = await space.getStateHistory();

    expect(messages.length).toBe(3);
    expect(has_more).toBe(false);

    // Verify the messages are in order
    expect(messages[0].type).toBe(path1);
    expect(messages[1].type).toBe(path2);
    expect(messages[2].type).toBe(path1);
  });

  it('should throw NotFoundError for non-existent path', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(5);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const nonExistentPath = randomStatePath();

    await expect(space.getPlaintextState(nonExistentPath)).rejects.toThrow(NotFoundError);
  });

  it('should handle state with special characters in path', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(6);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    // Path with nested structure
    const path = `users/U_${Date.now()}/profile/settings`;
    const stateData = JSON.stringify({ theme: 'dark', language: 'en' });

    // Set state
    await space.setPlaintextState(path, stateData, null);

    // Get state (returns base64, need to decode)
    const retrieved = decodePlaintext(await space.getPlaintextState(path));

    expect(retrieved).toBe(stateData);
    expect(JSON.parse(retrieved)).toEqual({ theme: 'dark', language: 'en' });
  });

  it('should support binary state data with encryption', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(7);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const path = randomStatePath();
    // Create some binary-like content
    const binaryContent = String.fromCharCode(...Array.from({ length: 256 }, (_, i) => i));

    // Set encrypted state with binary content
    await space.setEncryptedState(path, binaryContent, null);

    // Get and verify
    const retrieved = await space.getEncryptedState(path);

    expect(retrieved).toBe(binaryContent);
  });
});
