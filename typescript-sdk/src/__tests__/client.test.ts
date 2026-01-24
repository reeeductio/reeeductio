import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Space, AdminClient } from '../client.js';
import {
  generateKeyPair,
  toSpaceId,
  toUserId,
  encodeBase64,
  deriveKey,
} from '../crypto.js';

describe('Space', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

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
      const expectedBlobKey = deriveKey(symmetricRoot, `blob key | ${spaceId}`);
      const expectedDataKey = deriveKey(symmetricRoot, `data key | ${spaceId}`);
      const expectedStateKey = deriveKey(expectedMessageKey, 'topic key | state');

      expect(space.messageKey).toEqual(expectedMessageKey);
      expect(space.blobKey).toEqual(expectedBlobKey);
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
  let mockFetch: ReturnType<typeof vi.fn>;

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
      const adminSpaceId = 'C' + 'a'.repeat(43);

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
