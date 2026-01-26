/**
 * High-level Space client for reeeductio.
 *
 * Provides convenient methods for interacting with spaces, handling
 * authentication, messages, state, blobs, and data.
 */

import { AuthSession, AdminAuthSession } from './auth.js';
import {
  deriveKey,
  encryptAesGcm,
  decryptAesGcm,
  decodeBase64,
  toUserId,
  stringToBytes,
  bytesToString,
} from './crypto.js';
import { postMessage, getMessages, getMessage } from './messages.js';
import { getState, setState, getStateHistory } from './state.js';
import { getData, setData } from './kvdata.js';
import { uploadBlob, downloadBlob, deleteBlob } from './blobs.js';
import type {
  KeyPair,
  Message,
  MessageCreated,
  MessageQuery,
  MessagesResponse,
  DataSetResponse,
  BlobCreated,
  ApiError,
} from './types.js';
import { createApiError } from './exceptions.js';

/**
 * High-level client for interacting with a reeeductio space.
 *
 * Handles authentication, state management, messaging, blob storage, and key-value data.
 */
export class Space {
  /** Typed space identifier */
  readonly spaceId: string;
  /** Ed25519 key pair for authentication and signing */
  readonly keyPair: KeyPair;
  /** 256-bit root key for HKDF derivation */
  readonly symmetricRoot: Uint8Array;
  /** Base URL of the reeeductio server */
  readonly baseUrl: string;
  /** Authentication session manager */
  readonly auth: AuthSession;

  /** Derived key for message encryption (32 bytes) */
  readonly messageKey: Uint8Array;
  /** Derived key for blob encryption (32 bytes) */
  readonly blobKey: Uint8Array;
  /** Derived key for data encryption (32 bytes) */
  readonly dataKey: Uint8Array;
  /** Derived key for state encryption (32 bytes) */
  readonly stateKey: Uint8Array;

  private fetchFn: typeof fetch;

  constructor(options: {
    spaceId: string;
    keyPair: KeyPair;
    symmetricRoot: Uint8Array;
    baseUrl?: string;
    fetch?: typeof fetch;
  }) {
    const { spaceId, keyPair, symmetricRoot, baseUrl = 'http://localhost:8000' } = options;

    if (symmetricRoot.length !== 32) {
      throw new Error(`symmetricRoot must be exactly 32 bytes, got ${symmetricRoot.length}`);
    }

    this.spaceId = spaceId;
    this.keyPair = keyPair;
    this.symmetricRoot = symmetricRoot;
    this.baseUrl = baseUrl.replace(/\/$/, ''); // Remove trailing slash
    this.fetchFn = options.fetch ?? fetch;

    // Derive encryption keys from symmetricRoot using HKDF
    // Include spaceId in info for domain separation
    this.messageKey = deriveKey(symmetricRoot, `message key | ${spaceId}`);
    this.blobKey = deriveKey(symmetricRoot, `blob key | ${spaceId}`);
    this.dataKey = deriveKey(symmetricRoot, `data key | ${spaceId}`);
    // State key is a topic key for the "state" topic
    this.stateKey = deriveKey(this.messageKey, 'topic key | state');

    // Create authentication session
    this.auth = new AuthSession(this.baseUrl, spaceId, keyPair, this.fetchFn);
  }

  /**
   * Get the user ID for this space's key pair.
   */
  getUserId(): string {
    return toUserId(this.keyPair.publicKey);
  }

  /**
   * Derive a topic key for encrypting messages in a specific topic.
   *
   * @param topicId - Topic identifier
   * @returns 32-byte topic key
   */
  deriveTopicKey(topicId: string): Uint8Array {
    return deriveKey(this.messageKey, `topic key | ${topicId}`);
  }

  /**
   * Perform authentication.
   *
   * @returns JWT bearer token
   */
  async authenticate(): Promise<string> {
    const result = await this.auth.authenticate();
    return result.token;
  }

  // ============================================================
  // State Management
  // ============================================================

  /**
   * Get current plaintext state value at path.
   *
   * @param path - State path (e.g., "auth/users/U_abc123")
   * @returns Base64-encoded state data
   */
  async getPlaintextState(path: string): Promise<string> {
    const token = await this.auth.getToken();
    const message = await getState(this.fetchFn, this.baseUrl, token, this.spaceId, path);
    return message.data;
  }

  /**
   * Get encrypted state value at path and decrypt it.
   *
   * @param path - State path
   * @returns Decrypted plaintext string
   */
  async getEncryptedState(path: string): Promise<string> {
    const token = await this.auth.getToken();
    const message = await getState(this.fetchFn, this.baseUrl, token, this.spaceId, path);

    if (!message.data || message.data.length === 0) {
      return '';
    }

    // Base64 decode to get encrypted bytes
    const encryptedBytes = decodeBase64(message.data);

    // Decrypt using state key
    const plaintextBytes = decryptAesGcm(encryptedBytes, this.stateKey);

    return bytesToString(plaintextBytes);
  }

  /**
   * Set plaintext state value at path.
   *
   * @param path - State path
   * @param data - Plaintext string data to store
   * @param prevHash - Previous message hash (optional, fetched if not provided)
   * @returns MessageCreated with message_hash and server_timestamp
   */
  async setPlaintextState(
    path: string,
    data: string,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    const dataBytes = stringToBytes(data);
    return this._setState(path, dataBytes, prevHash);
  }

  /**
   * Set encrypted state value at path.
   *
   * @param path - State path
   * @param data - Plaintext string data to encrypt and store
   * @param prevHash - Previous message hash (optional, fetched if not provided)
   * @returns MessageCreated with message_hash and server_timestamp
   */
  async setEncryptedState(
    path: string,
    data: string,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    // Encrypt using state key
    const plaintextBytes = stringToBytes(data);
    const encryptedBytes = encryptAesGcm(plaintextBytes, this.stateKey);

    // Pass encrypted bytes directly - postMessage handles base64 encoding
    return this._setState(path, encryptedBytes, prevHash);
  }

  /**
   * Internal: set state value at path.
   */
  private async _setState(
    path: string,
    data: Uint8Array,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    const token = await this.auth.getToken();

    // Fetch prev_hash if not provided (get latest message using reverse order)
    if (prevHash === undefined) {
      const now = Date.now();
      const msgs = await this.getMessages('state', { from: now, to: 0, limit: 1 });
      prevHash = msgs.messages.length > 0 ? msgs.messages[0].message_hash : null;
    }

    return setState(
      this.fetchFn,
      this.baseUrl,
      token,
      this.spaceId,
      path,
      data,
      prevHash ?? null,
      this.getUserId(),
      this.keyPair.privateKey
    );
  }

  /**
   * Get all state change messages (event log).
   *
   * @param query - Optional query parameters
   * @returns Messages response
   */
  async getStateHistory(query?: MessageQuery): Promise<MessagesResponse> {
    const token = await this.auth.getToken();
    return getStateHistory(this.fetchFn, this.baseUrl, token, this.spaceId, query);
  }

  // ============================================================
  // Message Management
  // ============================================================

  /**
   * Get messages from a topic.
   *
   * @param topicId - Topic identifier
   * @param query - Optional query parameters
   * @returns Messages response
   */
  async getMessages(topicId: string, query?: MessageQuery): Promise<MessagesResponse> {
    const token = await this.auth.getToken();
    return getMessages(this.fetchFn, this.baseUrl, token, this.spaceId, topicId, query);
  }

  /**
   * Get a specific message by hash.
   *
   * @param topicId - Topic identifier
   * @param messageHash - Typed message identifier
   * @returns Message
   */
  async getMessage(topicId: string, messageHash: string): Promise<Message> {
    const token = await this.auth.getToken();
    return getMessage(this.fetchFn, this.baseUrl, token, this.spaceId, topicId, messageHash);
  }

  /**
   * Post a message to a topic.
   *
   * @param topicId - Topic identifier
   * @param msgType - Message type/category
   * @param data - Message data (raw bytes)
   * @param prevHash - Hash of previous message (optional, fetched if not provided)
   * @returns MessageCreated with message_hash and server_timestamp
   */
  async postMessage(
    topicId: string,
    msgType: string,
    data: Uint8Array,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    const token = await this.auth.getToken();

    // Fetch prev_hash if not provided
    if (prevHash === undefined) {
      const now = Date.now();
      const msgs = await this.getMessages(topicId, { from: now, to: 0, limit: 1 });
      prevHash = msgs.messages.length > 0 ? msgs.messages[0].message_hash : null;
    }

    return postMessage(
      this.fetchFn,
      this.baseUrl,
      token,
      this.spaceId,
      topicId,
      msgType,
      data,
      prevHash ?? null,
      this.getUserId(),
      this.keyPair.privateKey
    );
  }

  /**
   * Post an encrypted message to a topic.
   *
   * @param topicId - Topic identifier
   * @param msgType - Message type/category
   * @param plaintext - Plaintext message data
   * @param prevHash - Hash of previous message (optional)
   * @returns MessageCreated
   */
  async postEncryptedMessage(
    topicId: string,
    msgType: string,
    plaintext: Uint8Array,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    const topicKey = this.deriveTopicKey(topicId);
    const encrypted = encryptAesGcm(plaintext, topicKey);
    return this.postMessage(topicId, msgType, encrypted, prevHash);
  }

  // ============================================================
  // Blob Management
  // ============================================================

  /**
   * Upload plaintext blob.
   *
   * @param data - Plaintext blob data
   * @returns BlobCreated with blob_id and size
   */
  async uploadPlaintextBlob(data: Uint8Array): Promise<BlobCreated> {
    const token = await this.auth.getToken();
    return uploadBlob(this.fetchFn, this.baseUrl, token, this.spaceId, data);
  }

  /**
   * Encrypt and upload a blob.
   *
   * @param data - Plaintext blob data to encrypt and upload
   * @returns BlobCreated with blob_id and size
   */
  async encryptAndUploadBlob(data: Uint8Array): Promise<BlobCreated> {
    const encryptedData = encryptAesGcm(data, this.blobKey);
    const token = await this.auth.getToken();
    return uploadBlob(this.fetchFn, this.baseUrl, token, this.spaceId, encryptedData);
  }

  /**
   * Download plaintext blob.
   *
   * @param blobId - Typed blob identifier
   * @returns Plaintext blob data
   */
  async downloadPlaintextBlob(blobId: string): Promise<Uint8Array> {
    const token = await this.auth.getToken();
    return downloadBlob(this.fetchFn, this.baseUrl, token, this.spaceId, blobId);
  }

  /**
   * Download and decrypt encrypted blob.
   *
   * @param blobId - Typed blob identifier
   * @returns Decrypted plaintext blob data
   */
  async downloadAndDecryptBlob(blobId: string): Promise<Uint8Array> {
    const token = await this.auth.getToken();
    const encryptedData = await downloadBlob(this.fetchFn, this.baseUrl, token, this.spaceId, blobId);
    return decryptAesGcm(encryptedData, this.blobKey);
  }

  /**
   * Delete blob.
   *
   * @param blobId - Typed blob identifier
   */
  async deleteBlob(blobId: string): Promise<void> {
    const token = await this.auth.getToken();
    return deleteBlob(this.fetchFn, this.baseUrl, token, this.spaceId, blobId);
  }

  // ============================================================
  // Key-Value Data Management
  // ============================================================

  /**
   * Get plaintext data value at path.
   *
   * @param path - Data path
   * @returns Plaintext data bytes
   */
  async getPlaintextData(path: string): Promise<Uint8Array> {
    const token = await this.auth.getToken();
    const entry = await getData(this.fetchFn, this.baseUrl, token, this.spaceId, path);
    return decodeBase64(entry.data);
  }

  /**
   * Get encrypted data value at path and decrypt it.
   *
   * @param path - Data path
   * @returns Decrypted plaintext data bytes
   */
  async getEncryptedData(path: string): Promise<Uint8Array> {
    const token = await this.auth.getToken();
    const entry = await getData(this.fetchFn, this.baseUrl, token, this.spaceId, path);
    const encryptedBytes = decodeBase64(entry.data);
    return decryptAesGcm(encryptedBytes, this.dataKey);
  }

  /**
   * Set plaintext data value at path.
   *
   * @param path - Data path
   * @param data - Plaintext data bytes to store
   * @returns DataSetResponse with path and timestamp
   */
  async setPlaintextData(path: string, data: Uint8Array): Promise<DataSetResponse> {
    const token = await this.auth.getToken();
    return setData(
      this.fetchFn,
      this.baseUrl,
      token,
      this.spaceId,
      path,
      data,
      this.getUserId(),
      this.keyPair.privateKey
    );
  }

  /**
   * Set encrypted data value at path.
   *
   * @param path - Data path
   * @param data - Plaintext data bytes to encrypt and store
   * @returns DataSetResponse with path and timestamp
   */
  async setEncryptedData(path: string, data: Uint8Array): Promise<DataSetResponse> {
    const encryptedBytes = encryptAesGcm(data, this.dataKey);
    const token = await this.auth.getToken();
    return setData(
      this.fetchFn,
      this.baseUrl,
      token,
      this.spaceId,
      path,
      encryptedBytes,
      this.getUserId(),
      this.keyPair.privateKey
    );
  }

  // ============================================================
  // WebSocket Streaming
  // ============================================================

  /**
   * Get the WebSocket URL for this space.
   */
  getWebSocketUrl(): string {
    const wsUrl = this.baseUrl.replace('http://', 'ws://').replace('https://', 'wss://');
    return `${wsUrl}/spaces/${this.spaceId}/stream`;
  }

  /**
   * Connect to the space's WebSocket stream.
   *
   * Note: This returns the connection options. In browser environments,
   * use the native WebSocket API. In Node.js, use a WebSocket library.
   *
   * @returns WebSocket URL with token
   */
  async getWebSocketConnectionUrl(): Promise<string> {
    const token = await this.auth.getToken();
    return `${this.getWebSocketUrl()}?token=${token}`;
  }
}

/**
 * Admin client for authenticating to the admin space.
 *
 * Provides a simple way to authenticate against the admin space
 * without knowing its ID in advance.
 */
export class AdminClient {
  /** Ed25519 key pair for authentication and signing */
  readonly keyPair: KeyPair;
  /** Base URL of the reeeductio server */
  readonly baseUrl: string;
  /** Authentication session manager */
  readonly auth: AdminAuthSession;

  private fetchFn: typeof fetch;

  constructor(options: {
    keyPair: KeyPair;
    baseUrl?: string;
    fetch?: typeof fetch;
  }) {
    const { keyPair, baseUrl = 'http://localhost:8000' } = options;

    this.keyPair = keyPair;
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetchFn = options.fetch ?? fetch;

    this.auth = new AdminAuthSession(this.baseUrl, keyPair, this.fetchFn);
  }

  /**
   * Get the user ID for this client's key pair.
   */
  getUserId(): string {
    return toUserId(this.keyPair.publicKey);
  }

  /**
   * Perform admin authentication.
   *
   * @returns JWT bearer token
   */
  async authenticate(): Promise<string> {
    const result = await this.auth.authenticate();
    return result.token;
  }

  /**
   * Get the admin space ID.
   *
   * @returns The admin space ID (44-char base64)
   */
  async getSpaceId(): Promise<string> {
    return this.auth.getAdminSpaceId();
  }

  /**
   * Delete a blob directly from the server's blob storage.
   *
   * This is an admin operation that bypasses normal space-scoped blob deletion.
   *
   * @param blobId - Typed blob identifier
   */
  async deleteBlob(blobId: string): Promise<void> {
    const token = await this.auth.getToken();
    const url = `${this.baseUrl}/admin/blobs/${blobId}`;

    const response = await this.fetchFn(url, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      let error: ApiError | undefined;
      try {
        error = (await response.json()) as ApiError;
      } catch {
        // Ignore JSON parse errors
      }
      throw createApiError(response.status, error);
    }
  }
}
