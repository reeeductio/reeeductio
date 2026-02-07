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
  toToolId,
  generateKeyPair,
  stringToBytes,
} from './crypto.js';
import { postMessage, getMessages, getMessage } from './messages.js';
import { getState, setState, getStateHistory } from './state.js';
import { getData, setData } from './kvdata.js';
import { uploadBlob, downloadBlob, deleteBlob, encryptAndUploadBlob, downloadAndDecryptBlob } from './blobs.js';
import { performOpaqueRegistration, loginWithOpaque } from './opaque.js';
import type {
  KeyPair,
  Message,
  MessageCreated,
  MessageQuery,
  MessagesResponse,
  DataSetResponse,
  BlobCreated,
  ApiError,
  Tool,
  ToolCreated,
  Capability,
  OpaqueRegistrationResult,
} from './types.js';
import type { EncryptedBlobCreated } from './blobs.js';
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
   * @returns State data
   */
  async getPlaintextState(path: string): Promise<Uint8Array> {
    const token = await this.auth.getToken();
    const message = await getState(this.fetchFn, this.baseUrl, token, this.spaceId, path);
    return decodeBase64(message.data);
  }

  /**
   * Get encrypted state value at path and decrypt it.
   *
   * @param path - State path
   * @returns Decrypted plaintext data
   */
  async getEncryptedState(path: string): Promise<Uint8Array> {
    const token = await this.auth.getToken();
    const message = await getState(this.fetchFn, this.baseUrl, token, this.spaceId, path);

    if (!message.data || message.data.length === 0) {
      return new Uint8Array([]);
    }

    // Base64 decode to get encrypted bytes
    const encryptedBytes = decodeBase64(message.data);

    // Decrypt using state key
    const plaintextBytes = decryptAesGcm(encryptedBytes, this.stateKey);

    return plaintextBytes;
  }

  /**
   * Set plaintext state value at path.
   *
   * @param path - State path
   * @param data - Plaintext data to store
   * @param prevHash - Previous message hash (optional, fetched if not provided)
   * @returns MessageCreated with message_hash and server_timestamp
   */
  async setPlaintextState(
    path: string,
    data: Uint8Array,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    return this._setState(path, data, prevHash);
  }

  /**
   * Set encrypted state value at path.
   *
   * @param path - State path
   * @param data - Plaintext data to encrypt and store
   * @param prevHash - Previous message hash (optional, fetched if not provided)
   * @returns MessageCreated with message_hash and server_timestamp
   */
  async setEncryptedState(
    path: string,
    data: Uint8Array,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    // Encrypt using state key
    const encryptedBytes = encryptAesGcm(data, this.stateKey);

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
   * Encrypt and upload a blob using a random per-blob DEK.
   *
   * @param data - Plaintext blob data to encrypt and upload
   * @param associatedData - Optional additional authenticated data (AAD)
   * @returns EncryptedBlobCreated with blob_id, size, and the generated DEK
   */
  async encryptAndUploadBlob(data: Uint8Array, associatedData?: Uint8Array): Promise<EncryptedBlobCreated> {
    const token = await this.auth.getToken();
    return encryptAndUploadBlob(this.fetchFn, this.baseUrl, token, this.spaceId, data, associatedData);
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
   * Download and decrypt an encrypted blob using the provided DEK.
   *
   * @param blobId - Typed blob identifier
   * @param key - 32-byte AES-256 data encryption key (DEK)
   * @param associatedData - Optional additional authenticated data (AAD)
   * @returns Decrypted plaintext blob data
   */
  async downloadAndDecryptBlob(blobId: string, key: Uint8Array, associatedData?: Uint8Array): Promise<Uint8Array> {
    const token = await this.auth.getToken();
    return downloadAndDecryptBlob(this.fetchFn, this.baseUrl, token, this.spaceId, blobId, key, associatedData);
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

  // ============================================================
  // Tool Management
  // ============================================================

  /**
   * Create a new tool in this space.
   *
   * Tools are limited-use keypairs with NO ambient authority. They can only
   * perform actions explicitly granted via capabilities.
   *
   * @param description - Human-readable description of the tool's purpose
   * @param options - Optional settings for the tool
   * @param options.useLimit - Maximum number of write operations the tool can perform
   * @param options.capabilities - Capabilities to grant to the tool (keyed by capability ID)
   * @param options.prevHash - Previous state message hash (optional, fetched if not provided)
   * @returns ToolCreated with tool definition and keypair for authentication
   *
   * @example
   * ```typescript
   * // Create a tool with capabilities in one call
   * const { tool, keyPair } = await space.createTool('Security camera in lobby', {
   *   capabilities: {
   *     post_images: { op: 'create', path: 'topics/camera-feed' },
   *     read_config: { op: 'read', path: 'state/config/cameras/{self}' },
   *   },
   * });
   *
   * // The tool can now authenticate and use its granted capabilities
   * ```
   */
  async createTool(
    description: string,
    options?: {
      useLimit?: number;
      capabilities?: Record<string, Capability>;
      prevHash?: string | null;
    }
  ): Promise<ToolCreated> {
    // Generate a new keypair for the tool
    const keyPair = await generateKeyPair();

    // Create the tool ID from the public key
    const toolId = toToolId(keyPair.publicKey);

    // Create the tool definition
    const tool: Tool = {
      tool_id: toolId,
      description,
    };

    if (options?.useLimit !== undefined) {
      tool.use_limit = options.useLimit;
    }

    // Store the tool definition at auth/tools/{tool_id}
    const toolString = JSON.stringify(tool);
    const toolData = stringToBytes(toolString);
    await this.setPlaintextState(`auth/tools/${toolId}`, toolData, options?.prevHash);

    // Grant capabilities to the tool
    if (options?.capabilities) {
      for (const [capabilityId, capability] of Object.entries(options.capabilities)) {
        await this.grantCapabilityToTool(toolId, capabilityId, capability);
      }
    }

    return { tool, keyPair };
  }

  /**
   * Grant a capability to a tool.
   *
   * Capabilities define what operations a tool can perform. Tools have NO
   * inherited authority from roles - they can only use explicitly granted capabilities.
   *
   * @param toolId - The tool's typed identifier (starts with 'T')
   * @param capabilityId - Unique identifier for this capability (e.g., 'read_messages', 'post_images')
   * @param capability - The capability to grant
   * @param prevHash - Previous state message hash (optional, fetched if not provided)
   * @returns MessageCreated with message_hash and server_timestamp
   *
   * @example
   * ```typescript
   * // Grant read access to all state
   * await space.grantCapabilityToTool(toolId, 'read_all', {
   *   op: 'read',
   *   path: 'state/{...}',
   * });
   *
   * // Grant write access to a specific path
   * await space.grantCapabilityToTool(toolId, 'write_sensor_data', {
   *   op: 'write',
   *   path: 'state/sensors/{self}/{...}',
   * });
   * ```
   */
  async grantCapabilityToTool(
    toolId: string,
    capabilityId: string,
    capability: Capability,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    const capString = JSON.stringify(capability);
    const capData = stringToBytes(capString);
    return this.setPlaintextState(
      `auth/tools/${toolId}/rights/${capabilityId}`,
      capData,
      prevHash
    );
  }

  /**
   * Grant a capability to a user.
   *
   * Capabilities define what operations a user can perform. Users can also
   * inherit capabilities from roles they are assigned to.
   *
   * @param userId - The user's typed identifier (starts with 'U')
   * @param capabilityId - Unique identifier for this capability (e.g., 'read_messages', 'post_chat')
   * @param capability - The capability to grant
   * @param prevHash - Previous state message hash (optional, fetched if not provided)
   * @returns MessageCreated with message_hash and server_timestamp
   *
   * @example
   * ```typescript
   * // Grant read access to all profiles
   * await space.grantCapabilityToUser(userId, 'read_profiles', {
   *   op: 'read',
   *   path: 'state/profiles/{...}',
   * });
   *
   * // Grant write access only to user's own profile
   * await space.grantCapabilityToUser(userId, 'write_own_profile', {
   *   op: 'write',
   *   path: 'state/profiles/{self}',
   * });
   *
   * // Grant create access with ownership restriction
   * await space.grantCapabilityToUser(userId, 'create_posts', {
   *   op: 'create',
   *   path: 'state/posts/{...}',
   *   must_be_owner: true,
   * });
   * ```
   */
  async grantCapabilityToUser(
    userId: string,
    capabilityId: string,
    capability: Capability,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    const capString = JSON.stringify(capability);
    const capData = stringToBytes(capString);
    return this.setPlaintextState(
      `auth/users/${userId}/rights/${capabilityId}`,
      capData,
      prevHash
    );
  }

  // ============================================================
  // OPAQUE Password-Based Key Recovery
  // ============================================================

  /**
   * Register OPAQUE credentials for password-based login.
   *
   * This enables password-based key recovery for the current user or a tool account.
   * After registration, users can log in with `Space.fromOpaqueLogin()` using their
   * username and password to recover their keypair and symmetric root.
   *
   * **Important**: The caller must already be authenticated to the space. This method
   * registers the current space's keypair and symmetric root under the given username.
   *
   * @param username - Username for OPAQUE login (unique within the space)
   * @param password - Password for OPAQUE login
   * @returns Registration result with username and public key
   *
   * @example
   * ```typescript
   * // Register OPAQUE credentials for the current user
   * const result = await space.opaqueRegister('alice', 'my-secure-password');
   * console.log(`Registered ${result.username} with public key ${result.publicKey}`);
   *
   * // Later, log in with OPAQUE
   * const newSpace = await Space.fromOpaqueLogin({
   *   baseUrl: 'https://api.example.com',
   *   spaceId: 'C...',
   *   username: 'alice',
   *   password: 'my-secure-password',
   * });
   * ```
   */
  async opaqueRegister(username: string, password: string): Promise<OpaqueRegistrationResult> {
    const token = await this.auth.getToken();

    return performOpaqueRegistration({
      fetchFn: this.fetchFn,
      baseUrl: this.baseUrl,
      token,
      spaceId: this.spaceId,
      username,
      password,
      keyPair: this.keyPair,
      symmetricRoot: this.symmetricRoot,
      signingPrivateKey: this.keyPair.privateKey,
      signerId: this.getUserId(),
    });
  }

  /**
   * Register OPAQUE credentials for a new keypair (e.g., for tool accounts or invitations).
   *
   * This creates a new keypair and registers it with OPAQUE, allowing the recipient
   * to log in with a username and password. Use this for:
   * - Creating tool accounts for onboarding
   * - Inviting new users with password-based access
   *
   * @param username - Username for OPAQUE login
   * @param password - Password for OPAQUE login
   * @param options - Additional options
   * @returns Registration result with the new keypair
   *
   * @example
   * ```typescript
   * // Create a tool account for onboarding new users
   * const { keyPair, result } = await space.opaqueRegisterNewKeypair(
   *   'onboarding-tool',
   *   'shared-password-123'
   * );
   *
   * // Grant the tool limited capabilities
   * await space.grantCapabilityToTool(toToolId(keyPair.publicKey), 'add_users', {
   *   op: 'create',
   *   path: 'state/auth/users/{any}',
   * });
   * ```
   */
  async opaqueRegisterNewKeypair(
    username: string,
    password: string,
    options?: {
      /** Optional keypair to register (generates new one if not provided) */
      keyPair?: KeyPair;
    }
  ): Promise<{ keyPair: KeyPair; result: OpaqueRegistrationResult }> {
    const token = await this.auth.getToken();
    const keyPair = options?.keyPair ?? await generateKeyPair();

    const result = await performOpaqueRegistration({
      fetchFn: this.fetchFn,
      baseUrl: this.baseUrl,
      token,
      spaceId: this.spaceId,
      username,
      password,
      keyPair,
      symmetricRoot: this.symmetricRoot,
      signingPrivateKey: this.keyPair.privateKey,
      signerId: this.getUserId(),
    });

    return { keyPair, result };
  }

  /**
   * Create a Space client by logging in with OPAQUE.
   *
   * This performs the OPAQUE login protocol to recover the user's Ed25519 keypair
   * and symmetric root from their password, then creates and authenticates a Space client.
   *
   * @param options - Login options
   * @returns Authenticated Space client
   *
   * @example
   * ```typescript
   * const space = await Space.fromOpaqueLogin({
   *   baseUrl: 'https://api.example.com',
   *   spaceId: 'C...',
   *   username: 'alice',
   *   password: 'my-secure-password',
   * });
   *
   * // The space is ready to use
   * await space.postMessage('chat', 'text', new TextEncoder().encode('Hello!'));
   * ```
   */
  static async fromOpaqueLogin(options: {
    baseUrl: string;
    spaceId: string;
    username: string;
    password: string;
    fetch?: typeof fetch;
  }): Promise<Space> {
    const { credentials, keyPair } = await loginWithOpaque({
      baseUrl: options.baseUrl,
      spaceId: options.spaceId,
      username: options.username,
      password: options.password,
      fetch: options.fetch,
    });

    return new Space({
      spaceId: options.spaceId,
      keyPair,
      symmetricRoot: credentials.symmetricRoot,
      baseUrl: options.baseUrl,
      fetch: options.fetch,
    });
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
