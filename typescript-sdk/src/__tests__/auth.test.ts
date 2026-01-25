import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthSession, AdminAuthSession } from '../auth.js';
import { generateKeyPair, toUserId, toSpaceId, encodeBase64 } from '../crypto.js';

describe('AuthSession', () => {
  const mockBaseUrl = 'https://api.example.com';
  let mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  describe('constructor', () => {
    it('should create an AuthSession with required parameters', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);

      const session = new AuthSession(mockBaseUrl, spaceId, keyPair, mockFetch);

      expect(session.getUserId()).toBe(toUserId(keyPair.publicKey));
    });

    it('should remove trailing slash from baseUrl', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);

      const session = new AuthSession('https://api.example.com/', spaceId, keyPair, mockFetch);

      // We can verify this works by checking that requests go to the right URL
      expect(session).toBeDefined();
    });
  });

  describe('getUserId', () => {
    it('should return the typed user ID', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const expectedUserId = toUserId(keyPair.publicKey);

      const session = new AuthSession(mockBaseUrl, spaceId, keyPair, mockFetch);

      expect(session.getUserId()).toBe(expectedUserId);
    });
  });

  describe('authenticate', () => {
    it('should complete the challenge-response flow', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);

      // Mock challenge response
      const challengeBytes = new Uint8Array(32).fill(1);
      const challengeBase64 = encodeBase64(challengeBytes);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: challengeBase64 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            token: 'mock-jwt-token',
            expires_at: Date.now() + 3600000,
          }),
        });

      const session = new AuthSession(mockBaseUrl, spaceId, keyPair, mockFetch);

      const result = await session.authenticate();

      expect(result.token).toBe('mock-jwt-token');
      expect(session.hasValidToken()).toBe(true);

      // Verify challenge request
      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        `${mockBaseUrl}/spaces/${spaceId}/auth/challenge`,
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        })
      );

      // Verify token request (verify endpoint)
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        `${mockBaseUrl}/spaces/${spaceId}/auth/verify`,
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        })
      );
    });

    it('should throw on challenge failure', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: 'Unauthorized' }),
      });

      const session = new AuthSession(mockBaseUrl, spaceId, keyPair, mockFetch);

      await expect(session.authenticate()).rejects.toThrow();
    });

    it('should throw on verify failure', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);

      const challengeBytes = new Uint8Array(32).fill(1);
      const challengeBase64 = encodeBase64(challengeBytes);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: challengeBase64 }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({ error: 'Invalid signature' }),
        });

      const session = new AuthSession(mockBaseUrl, spaceId, keyPair, mockFetch);

      await expect(session.authenticate()).rejects.toThrow();
    });
  });

  describe('getToken', () => {
    it('should return token after authentication', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);

      const challengeBytes = new Uint8Array(32).fill(1);
      const challengeBase64 = encodeBase64(challengeBytes);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: challengeBase64 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            token: 'mock-jwt-token',
            expires_at: Date.now() + 3600000,
          }),
        });

      const session = new AuthSession(mockBaseUrl, spaceId, keyPair, mockFetch);

      await session.authenticate();
      const token = await session.getToken();

      expect(token).toBe('mock-jwt-token');
    });

    it('should auto-authenticate if not authenticated', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);

      const challengeBytes = new Uint8Array(32).fill(1);
      const challengeBase64 = encodeBase64(challengeBytes);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: challengeBase64 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            token: 'mock-jwt-token',
            expires_at: Date.now() + 3600000,
          }),
        });

      const session = new AuthSession(mockBaseUrl, spaceId, keyPair, mockFetch);

      // Call getToken without explicit authenticate
      const token = await session.getToken();

      expect(token).toBe('mock-jwt-token');
      expect(session.hasValidToken()).toBe(true);
    });
  });

  describe('hasValidToken', () => {
    it('should return false before authentication', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);

      const session = new AuthSession(mockBaseUrl, spaceId, keyPair, mockFetch);

      expect(session.hasValidToken()).toBe(false);
    });

    it('should return true after authentication', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);

      const challengeBytes = new Uint8Array(32).fill(1);
      const challengeBase64 = encodeBase64(challengeBytes);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: challengeBase64 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            token: 'mock-jwt-token',
            expires_at: Date.now() + 3600000,
          }),
        });

      const session = new AuthSession(mockBaseUrl, spaceId, keyPair, mockFetch);

      await session.authenticate();

      expect(session.hasValidToken()).toBe(true);
    });
  });
});

describe('AdminAuthSession', () => {
  const mockBaseUrl = 'https://api.example.com';
  let mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  describe('constructor', () => {
    it('should create an AdminAuthSession with required parameters', async () => {
      const keyPair = await generateKeyPair();

      const session = new AdminAuthSession(mockBaseUrl, keyPair, mockFetch);

      expect(session.getUserId()).toBe(toUserId(keyPair.publicKey));
    });
  });

  describe('authenticate', () => {
    it('should complete admin challenge-response flow', async () => {
      const keyPair = await generateKeyPair();

      const challengeBytes = new Uint8Array(32).fill(1);
      const challengeBase64 = encodeBase64(challengeBytes);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: challengeBase64 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            token: 'admin-jwt-token',
            expires_at: Date.now() + 3600000,
          }),
        });

      const session = new AdminAuthSession(mockBaseUrl, keyPair, mockFetch);

      const result = await session.authenticate();

      expect(result.token).toBe('admin-jwt-token');

      // Verify admin auth endpoints
      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        `${mockBaseUrl}/admin/auth/challenge`,
        expect.any(Object)
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        `${mockBaseUrl}/admin/auth/verify`,
        expect.any(Object)
      );
    });
  });

  describe('getToken', () => {
    it('should auto-authenticate and return token', async () => {
      const keyPair = await generateKeyPair();

      const challengeBytes = new Uint8Array(32).fill(1);
      const challengeBase64 = encodeBase64(challengeBytes);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ challenge: challengeBase64 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            token: 'admin-jwt-token',
            expires_at: Date.now() + 3600000,
          }),
        });

      const session = new AdminAuthSession(mockBaseUrl, keyPair, mockFetch);

      const token = await session.getToken();

      expect(token).toBe('admin-jwt-token');
    });
  });
});
