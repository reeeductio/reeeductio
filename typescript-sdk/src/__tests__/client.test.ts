import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Space, AdminClient } from '../client.js';
import {
  generateKeyPair,
  toSpaceId,
  toUserId,
  encodeBase64,
  decodeBase64,
  deriveKey,
  encryptAesGcm,
  decryptAesGcm,
} from '../crypto.js';

describe('Space', () => {
  let mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  describe('constructor', () => {
    it('should create a Space with required config', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      expect(space.spaceId).toBe(spaceId);
      expect(space.getUserId()).toBe(toUserId(keyPair.publicKey));
    });

    it('should derive keys from symmetric root', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      // Verify keys are derived
      const expectedMessageKey = deriveKey(symmetricRoot, `message key | ${spaceId}`);
      const expectedDataKey = deriveKey(symmetricRoot, `data key | ${spaceId}`);
      const expectedStateKey = deriveKey(expectedMessageKey, 'topic key | state');

      expect(space.messageKey).toEqual(expectedMessageKey);
      expect(space.dataKey).toEqual(expectedDataKey);
      expect(space.stateKey).toEqual(expectedStateKey);
    });

    it('should reject invalid symmetricRoot length', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const badRoot = new Uint8Array(16); // Wrong length

      expect(() => new Space({
        spaceId,
        keyPair,
        symmetricRoot: badRoot,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      })).toThrow(/32 bytes/);
    });
  });

  describe('authentication', () => {
    it('should authenticate with challenge-response', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      const challengeBytes = new Uint8Array(32).fill(1);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: encodeBase64(challengeBytes) }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            token: 'mock-token',
            expires_at: Date.now() + 3600000,
          }),
        });

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      const token = await space.authenticate();

      expect(token).toBe('mock-token');
    });
  });

  describe('deriveTopicKey', () => {
    it('should derive a topic key', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      const topicKey = space.deriveTopicKey('chat');

      expect(topicKey).toBeInstanceOf(Uint8Array);
      expect(topicKey.length).toBe(32);
    });

    it('should derive different keys for different topics', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      const key1 = space.deriveTopicKey('chat');
      const key2 = space.deriveTopicKey('events');

      expect(key1).not.toEqual(key2);
    });
  });

  describe('user-private encryption', () => {
    const userSymmetricKey = new Uint8Array(32).fill(7);

    it('should derive user keys from the user symmetric key', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        userSymmetricKey,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      const expectedMessageKey = deriveKey(userSymmetricKey, `user message key | ${spaceId}`);
      const expectedDataKey = deriveKey(userSymmetricKey, `user data key | ${spaceId}`);

      expect(space.userSymmetricKey).toEqual(userSymmetricKey);
      expect(space.userMessageKey).toEqual(expectedMessageKey);
      expect(space.userDataKey).toEqual(expectedDataKey);
      // User keys must differ from space keys
      expect(space.userDataKey).not.toEqual(space.dataKey);
      expect(space.userMessageKey).not.toEqual(space.messageKey);
    });

    it('should leave user keys null when no user key is provided', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      expect(space.userSymmetricKey).toBeNull();
      expect(space.userMessageKey).toBeNull();
      expect(space.userDataKey).toBeNull();
    });

    it('should reject invalid userSymmetricKey length', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      expect(() => new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        userSymmetricKey: new Uint8Array(16),
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      })).toThrow(/32 bytes/);
    });

    it('getEncryptedData should use a provided key over the data key', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);
      const customKey = new Uint8Array(32).fill(9);
      const plaintext = new Uint8Array([1, 2, 3, 4]);
      const encrypted = encryptAesGcm(plaintext, customKey);

      mockFetch
        .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: encodeBase64(new Uint8Array(32).fill(1)) }) })
        .mockResolvedValueOnce({ ok: true, json: async () => ({ token: 'mock-token', expires_at: Date.now() + 3600000 }) })
        .mockResolvedValueOnce({ ok: true, json: async () => ({ data: encodeBase64(encrypted) }) });

      const space = new Space({
        spaceId, keyPair, symmetricRoot, baseUrl: 'https://api.example.com', fetch: mockFetch,
      });

      const result = await space.getEncryptedData('some/path', customKey);
      expect(result).toEqual(plaintext);
    });

    it('setEncryptedData should encrypt with a provided key over the data key', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);
      const customKey = new Uint8Array(32).fill(9);
      const plaintext = new Uint8Array([5, 6, 7, 8]);

      let sentBody: string | undefined;
      mockFetch
        .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: encodeBase64(new Uint8Array(32).fill(1)) }) })
        .mockResolvedValueOnce({ ok: true, json: async () => ({ token: 'mock-token', expires_at: Date.now() + 3600000 }) })
        .mockImplementationOnce(async (_url: string, init: { body: string }) => {
          sentBody = init.body;
          return { ok: true, json: async () => ({ path: 'some/path', signed_at: 123 }) };
        });

      const space = new Space({
        spaceId, keyPair, symmetricRoot, baseUrl: 'https://api.example.com', fetch: mockFetch,
      });

      await space.setEncryptedData('some/path', plaintext, customKey);

      expect(sentBody).toBeDefined();
      const body = JSON.parse(sentBody!);
      const stored = decodeBase64(body.data);
      // Must decrypt with the custom key, not the space data key
      expect(decryptAesGcm(stored, customKey)).toEqual(plaintext);
    });

    it('user data round trips through the user namespace path', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);
      const plaintext = new Uint8Array([10, 20, 30]);

      const space = new Space({
        spaceId, keyPair, symmetricRoot, userSymmetricKey, baseUrl: 'https://api.example.com', fetch: mockFetch,
      });

      const userId = space.getUserId();
      let putUrl: string | undefined;
      let stored: Uint8Array | undefined;

      mockFetch
        .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: encodeBase64(new Uint8Array(32).fill(1)) }) })
        .mockResolvedValueOnce({ ok: true, json: async () => ({ token: 'mock-token', expires_at: Date.now() + 3600000 }) })
        .mockImplementationOnce(async (url: string, init: { body: string }) => {
          putUrl = url;
          stored = decodeBase64(JSON.parse(init.body).data);
          return { ok: true, json: async () => ({ path: `user/${userId}/notes`, signed_at: 123 }) };
        })
        .mockImplementationOnce(async () => ({ ok: true, json: async () => ({ data: encodeBase64(stored!) }) }));

      await space.setEncryptedUserData('notes', plaintext);
      expect(putUrl).toContain(`/data/user/${userId}/notes`);
      // Stored ciphertext must decrypt with the user data key only
      expect(decryptAesGcm(stored!, space.userDataKey!)).toEqual(plaintext);

      const result = await space.getEncryptedUserData('notes');
      expect(result).toEqual(plaintext);
    });

    it('user data methods throw when no user key was provided', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      const space = new Space({
        spaceId, keyPair, symmetricRoot, baseUrl: 'https://api.example.com', fetch: mockFetch,
      });

      await expect(space.getEncryptedUserData('notes')).rejects.toThrow(/userSymmetricKey/);
      await expect(space.setEncryptedUserData('notes', new Uint8Array([1]))).rejects.toThrow(/userSymmetricKey/);
    });
  });

  describe('WebSocket URL', () => {
    it('should generate correct WebSocket URL', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      const wsUrl = space.getWebSocketUrl();

      expect(wsUrl).toBe(`wss://api.example.com/spaces/${spaceId}/stream`);
    });

    it('should convert http to ws protocol', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: 'http://localhost:8080',
        fetch: mockFetch,
      });

      const wsUrl = space.getWebSocketUrl();

      expect(wsUrl).toBe(`ws://localhost:8080/spaces/${spaceId}/stream`);
    });

    it('should generate connection URL with token', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(42);

      const challengeBytes = new Uint8Array(32).fill(1);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: encodeBase64(challengeBytes) }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            token: 'mock-token',
            expires_at: Date.now() + 3600000,
          }),
        });

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      const wsUrl = await space.getWebSocketConnectionUrl();

      expect(wsUrl).toContain('wss://api.example.com');
      expect(wsUrl).toContain('token=mock-token');
    });
  });
});

describe('AdminClient', () => {
  let mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  describe('constructor', () => {
    it('should create an AdminClient', async () => {
      const keyPair = await generateKeyPair();

      const client = new AdminClient({
        keyPair,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      expect(client.baseUrl).toBe('https://api.example.com');
      expect(client.getUserId()).toBe(toUserId(keyPair.publicKey));
    });
  });

  describe('authentication', () => {
    it('should authenticate as admin', async () => {
      const keyPair = await generateKeyPair();
      const challengeBytes = new Uint8Array(32).fill(1);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: encodeBase64(challengeBytes) }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            token: 'admin-token',
            expires_at: Date.now() + 3600000,
          }),
        });

      const client = new AdminClient({
        keyPair,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      const token = await client.authenticate();

      expect(token).toBe('admin-token');
    });
  });

  describe('getSpaceId', () => {
    it('should fetch the admin space ID', async () => {
      const keyPair = await generateKeyPair();
      const challengeBytes = new Uint8Array(32).fill(1);
      const adminSpaceId = 'S' + 'a'.repeat(43);

      mockFetch
        // Auth challenge
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: encodeBase64(challengeBytes) }),
        })
        // Auth verify
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            token: 'admin-token',
            expires_at: Date.now() + 3600000,
          }),
        })
        // Get admin space
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ space_id: adminSpaceId }),
        });

      const client = new AdminClient({
        keyPair,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      const spaceId = await client.getSpaceId();

      expect(spaceId).toBe(adminSpaceId);
    });
  });

  describe('deleteBlob', () => {
    it('should delete a blob via admin API', async () => {
      const keyPair = await generateKeyPair();
      const challengeBytes = new Uint8Array(32).fill(1);
      const blobId = 'B' + 'a'.repeat(43);

      mockFetch
        // Auth challenge
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: encodeBase64(challengeBytes) }),
        })
        // Auth verify
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            token: 'admin-token',
            expires_at: Date.now() + 3600000,
          }),
        })
        // Delete blob
        .mockResolvedValueOnce({
          ok: true,
          status: 204,
        });

      const client = new AdminClient({
        keyPair,
        baseUrl: 'https://api.example.com',
        fetch: mockFetch,
      });

      await client.deleteBlob(blobId);

      // Verify the delete was called with correct URL
      const lastCall = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
      expect(lastCall[0]).toBe(`https://api.example.com/admin/blobs/${blobId}`);
      expect(lastCall[1].method).toBe('DELETE');
    });
  });
});
