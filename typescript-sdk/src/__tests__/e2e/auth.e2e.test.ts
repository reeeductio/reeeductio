/**
 * E2E tests for authentication.
 *
 * Run with: npm run test:e2e
 * Requires: docker-compose -f backend/docker-compose.e2e.yml up -d
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { AuthSession } from '../../auth.js';
import { generateKeyPair, toSpaceId, toUserId, encodeBase64 } from '../../crypto.js';
import { E2E_BACKEND_URL, waitForBackend } from './setup.js';

describe('E2E: Authentication', () => {
  beforeAll(async () => {
    await waitForBackend();
  }, 60000);

  it('should complete challenge-response authentication flow', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const userId = toUserId(keyPair.publicKey);

    const session = new AuthSession(E2E_BACKEND_URL, spaceId, keyPair);

    // Authenticate
    const result = await session.authenticate();

    expect(result.token).toBeDefined();
    expect(typeof result.token).toBe('string');
    expect(result.token.length).toBeGreaterThan(0);
    expect(result.expires_at).toBeDefined();
    expect(session.hasValidToken()).toBe(true);
    expect(session.getUserId()).toBe(userId);
  });

  it('should auto-authenticate on getToken', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);

    const session = new AuthSession(E2E_BACKEND_URL, spaceId, keyPair);

    expect(session.hasValidToken()).toBe(false);

    // getToken should auto-authenticate
    const token = await session.getToken();

    expect(token).toBeDefined();
    expect(session.hasValidToken()).toBe(true);
  });

  it('should reject invalid signatures', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const userId = toUserId(keyPair.publicKey);

    // Request challenge manually
    const challengeResponse = await fetch(
      `${E2E_BACKEND_URL}/spaces/${spaceId}/auth/challenge`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ public_key: userId }),
      }
    );

    expect(challengeResponse.ok).toBe(true);
    const { challenge } = await challengeResponse.json() as { challenge: string };

    // Send invalid signature
    const invalidSignature = encodeBase64(new Uint8Array(64).fill(0));

    const verifyResponse = await fetch(
      `${E2E_BACKEND_URL}/spaces/${spaceId}/auth/verify`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          public_key: userId,
          challenge,
          signature: invalidSignature,
        }),
      }
    );

    expect(verifyResponse.ok).toBe(false);
    expect(verifyResponse.status).toBe(401);
  });

  it('should be able to use token for authenticated requests', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);

    const session = new AuthSession(E2E_BACKEND_URL, spaceId, keyPair);
    const token = await session.getToken();

    // Use token to access a protected endpoint
    const response = await fetch(
      `${E2E_BACKEND_URL}/spaces/${spaceId}/topics/test/messages`,
      {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${token}` },
      }
    );

    expect(response.ok).toBe(true);
    const data = await response.json() as { messages: unknown[] };
    expect(data.messages).toBeDefined();
  });
});
