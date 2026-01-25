/**
 * Authentication module for reeeductio Spaces API.
 *
 * Implements challenge-response authentication using Ed25519 signatures.
 */

import {
  signData,
  toUserId,
  encodeBase64,
  stringToBytes,
} from './crypto.js';
import { debugLog, infoLog, warnLog, errorLog } from './debug.js';
import type {
  ChallengeResponse,
  TokenResponse,
  KeyPair,
  ApiError,
} from './types.js';
import { createApiError, AuthenticationError } from './exceptions.js';

/**
 * Authentication session for a space.
 *
 * Handles challenge-response authentication and JWT token management.
 */
export class AuthSession {
  private baseUrl: string;
  private spaceId: string;
  private keyPair: KeyPair;
  private fetchFn: typeof fetch;

  private token: string | null = null;
  private tokenExpiresAt: number | null = null;

  /** Refresh token before this many milliseconds of expiry */
  private readonly refreshBuffer: number = 60_000; // 1 minute

  constructor(
    baseUrl: string,
    spaceId: string,
    keyPair: KeyPair,
    fetchFn: typeof fetch = fetch
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, ''); // Remove trailing slash
    this.spaceId = spaceId;
    this.keyPair = keyPair;
    this.fetchFn = fetchFn;
  }

  /**
   * Get the user ID for this session's key pair.
   */
  getUserId(): string {
    return toUserId(this.keyPair.publicKey);
  }

  /**
   * Get a valid JWT token, authenticating if necessary.
   *
   * Automatically refreshes the token if it's about to expire.
   */
  async getToken(): Promise<string> {
    // Check if we need to authenticate or refresh
    if (!this.token || !this.tokenExpiresAt) {
      debugLog('auth', 'No cached token; authenticating', { spaceId: this.spaceId });
      await this.authenticate();
    } else if (Date.now() >= this.tokenExpiresAt - this.refreshBuffer) {
      // Token is about to expire, try to refresh
      debugLog('auth', 'Token expiring; refreshing', { spaceId: this.spaceId });
      try {
        await this.refresh();
      } catch {
        // Refresh failed, re-authenticate
        warnLog('auth', 'Token refresh failed; re-authenticating', { spaceId: this.spaceId });
        await this.authenticate();
      }
    }

    if (!this.token) {
      throw new AuthenticationError('Failed to obtain authentication token');
    }

    return this.token;
  }

  /**
   * Check if we have a valid token.
   */
  hasValidToken(): boolean {
    if (!this.token || !this.tokenExpiresAt) {
      return false;
    }
    return Date.now() < this.tokenExpiresAt - this.refreshBuffer;
  }

  /**
   * Perform full challenge-response authentication.
   */
  async authenticate(): Promise<TokenResponse> {
    // Step 1: Request challenge
    const userId = this.getUserId();
    infoLog('auth', 'Authenticating', { spaceId: this.spaceId, userId });
    const challengeResponse = await this.requestChallenge(userId);

    // Step 2: Sign the challenge (sign the base64 string as UTF-8 bytes, not the decoded bytes)
    const challengeBytes = stringToBytes(challengeResponse.challenge);
    const signature = await signData(challengeBytes, this.keyPair.privateKey);

    // Step 3: Verify and get token
    const tokenResponse = await this.verifyChallenge(
      userId,
      encodeBase64(signature),
      challengeResponse.challenge
    );

    this.token = tokenResponse.token;
    this.tokenExpiresAt = tokenResponse.expires_at;

    infoLog('auth', 'Authenticated', {
      spaceId: this.spaceId,
      userId,
      expiresAt: tokenResponse.expires_at,
    });
    return tokenResponse;
  }

  /**
   * Refresh the current token.
   */
  async refresh(): Promise<TokenResponse> {
    if (!this.token) {
      throw new AuthenticationError('No token to refresh');
    }

    const url = `${this.baseUrl}/spaces/${this.spaceId}/auth/refresh`;

    debugLog('auth', 'Refreshing token', { spaceId: this.spaceId, url });
    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      errorLog('auth', 'Token refresh failed', { spaceId: this.spaceId, status: response.status, error });
      throw createApiError(response.status, error);
    }

    const tokenResponse = (await response.json()) as TokenResponse;
    this.token = tokenResponse.token;
    this.tokenExpiresAt = tokenResponse.expires_at;

    infoLog('auth', 'Token refreshed', {
      spaceId: this.spaceId,
      expiresAt: tokenResponse.expires_at,
    });
    return tokenResponse;
  }

  /**
   * Request an authentication challenge.
   */
  private async requestChallenge(publicKey: string): Promise<ChallengeResponse> {
    const url = `${this.baseUrl}/spaces/${this.spaceId}/auth/challenge`;

    debugLog('auth', 'Requesting challenge', { spaceId: this.spaceId, url, publicKey });
    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ public_key: publicKey }),
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      errorLog('auth', 'Challenge request failed', { spaceId: this.spaceId, status: response.status, error });
      throw createApiError(response.status, error);
    }

    return (await response.json()) as ChallengeResponse;
  }

  /**
   * Verify signed challenge and get JWT token.
   */
  private async verifyChallenge(
    publicKey: string,
    signature: string,
    challenge: string
  ): Promise<TokenResponse> {
    const url = `${this.baseUrl}/spaces/${this.spaceId}/auth/verify`;

    debugLog('auth', 'Verifying challenge', { spaceId: this.spaceId, url, publicKey });
    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        public_key: publicKey,
        signature,
        challenge,
      }),
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      errorLog('auth', 'Challenge verification failed', {
        spaceId: this.spaceId,
        status: response.status,
        error,
      });
      throw createApiError(response.status, error);
    }

    return (await response.json()) as TokenResponse;
  }

  /**
   * Parse error response from API.
   */
  private async parseError(response: Response): Promise<ApiError | undefined> {
    try {
      return (await response.json()) as ApiError;
    } catch {
      return undefined;
    }
  }
}

/**
 * Admin authentication session.
 *
 * Uses the /admin/auth/* endpoints for convenience authentication.
 */
export class AdminAuthSession {
  private baseUrl: string;
  private keyPair: KeyPair;
  private fetchFn: typeof fetch;

  private token: string | null = null;
  private tokenExpiresAt: number | null = null;
  private adminSpaceId: string | null = null;

  private readonly refreshBuffer: number = 60_000;

  constructor(baseUrl: string, keyPair: KeyPair, fetchFn: typeof fetch = fetch) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.keyPair = keyPair;
    this.fetchFn = fetchFn;
  }

  /**
   * Get the user ID for this session's key pair.
   */
  getUserId(): string {
    return toUserId(this.keyPair.publicKey);
  }

  /**
   * Get a valid JWT token for admin operations.
   */
  async getToken(): Promise<string> {
    if (!this.token || !this.tokenExpiresAt) {
      debugLog('admin-auth', 'No cached token; authenticating', {});
      await this.authenticate();
    } else if (Date.now() >= this.tokenExpiresAt - this.refreshBuffer) {
      debugLog('admin-auth', 'Token expiring; re-authenticating', {});
      await this.authenticate();
    }

    if (!this.token) {
      throw new AuthenticationError('Failed to obtain admin authentication token');
    }

    return this.token;
  }

  /**
   * Get the admin space ID.
   */
  async getAdminSpaceId(): Promise<string> {
    if (!this.adminSpaceId) {
      await this.fetchAdminSpaceId();
    }

    if (!this.adminSpaceId) {
      throw new AuthenticationError('Failed to obtain admin space ID');
    }

    return this.adminSpaceId;
  }

  /**
   * Perform admin authentication.
   */
  async authenticate(): Promise<TokenResponse> {
    const userId = this.getUserId();

    // Request challenge
    infoLog('admin-auth', 'Authenticating', { userId });
    const challengeResponse = await this.requestChallenge(userId);

    // Sign challenge (sign the base64 string as UTF-8 bytes, not the decoded bytes)
    const challengeBytes = stringToBytes(challengeResponse.challenge);
    const signature = await signData(challengeBytes, this.keyPair.privateKey);

    // Verify and get token
    const tokenResponse = await this.verifyChallenge(
      userId,
      encodeBase64(signature),
      challengeResponse.challenge
    );

    this.token = tokenResponse.token;
    this.tokenExpiresAt = tokenResponse.expires_at;

    infoLog('admin-auth', 'Authenticated', { userId, expiresAt: tokenResponse.expires_at });
    return tokenResponse;
  }

  /**
   * Request admin authentication challenge.
   */
  private async requestChallenge(publicKey: string): Promise<ChallengeResponse> {
    const url = `${this.baseUrl}/admin/auth/challenge`;

    debugLog('admin-auth', 'Requesting challenge', { url, publicKey });
    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ public_key: publicKey }),
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      errorLog('admin-auth', 'Challenge request failed', { status: response.status, error });
      throw createApiError(response.status, error);
    }

    return (await response.json()) as ChallengeResponse;
  }

  /**
   * Verify admin challenge and get JWT.
   */
  private async verifyChallenge(
    publicKey: string,
    signature: string,
    challenge: string
  ): Promise<TokenResponse> {
    const url = `${this.baseUrl}/admin/auth/verify`;

    debugLog('admin-auth', 'Verifying challenge', { url, publicKey });
    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        public_key: publicKey,
        signature,
        challenge,
      }),
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      errorLog('admin-auth', 'Challenge verification failed', { status: response.status, error });
      throw createApiError(response.status, error);
    }

    return (await response.json()) as TokenResponse;
  }

  /**
   * Fetch the admin space ID.
   */
  private async fetchAdminSpaceId(): Promise<void> {
    const token = await this.getToken();
    const url = `${this.baseUrl}/admin/space`;

    debugLog('admin-auth', 'Fetching admin space ID', { url });
    const response = await this.fetchFn(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      errorLog('admin-auth', 'Fetch admin space ID failed', { status: response.status, error });
      throw createApiError(response.status, error);
    }

    const data = (await response.json()) as { space_id: string };
    this.adminSpaceId = data.space_id;
  }

  private async parseError(response: Response): Promise<ApiError | undefined> {
    try {
      return (await response.json()) as ApiError;
    } catch {
      return undefined;
    }
  }
}
