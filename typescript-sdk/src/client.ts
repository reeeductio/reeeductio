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
import {
  postMessage,
  getMessages,
  getMessage,
  verifyMessageHash,
  validateMessageChainWithAnchor,
} from './messages.js';
import type { MessageStore } from './local_store.js';
import { ChainError } from './exceptions.js';
import { getState, setState, getStateHistory } from './state.js';
import { getData, setData } from './kvdata.js';
import { uploadBlob, downloadBlob, deleteBlob, encryptAndUploadBlob, downloadAndDecryptBlob } from './blobs.js';
import {
  performOpaqueRegistration,
  loginWithOpaque,
  createOpaqueSetup,
  OPAQUE_SERVER_SETUP_PATH,
  OPAQUE_USER_ROLE_ID,
  OPAQUE_USER_CAP_ID,
} from './opaque.js';
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
  EnableOpaqueResult,
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
  private localStore: MessageStore | null;

  constructor(options: {
    spaceId: string;
    keyPair: KeyPair;
    symmetricRoot: Uint8Array;
    baseUrl?: string;
    fetch?: typeof fetch;
    /** Optional local message store for caching. When provided,
     * messages are cached locally and retrieved from cache when available. */
    localStore?: MessageStore;
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
    this.localStore = options.localStore ?? null;

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
   * When a localStore is configured and useCache is true, this method:
   * 1. Checks if cached data might be stale (to > latest cached)
   * 2. Fetches newer messages from server if needed
   * 3. Validates message hashes and chain integrity
   * 4. Fetches gap-filling messages if there's a gap between cached and new
   * 5. Merges server results with cached data
   * 6. Caches any new messages
   *
   * @param topicId - Topic identifier
   * @param query - Optional query parameters
   * @param options - Caching and validation options
   * @returns Messages response
   */
  async getMessages(
    topicId: string,
    query?: MessageQuery,
    options?: {
      /** Whether to use local cache (default true) */
      useCache?: boolean;
      /** Whether to validate chain integrity (default true) */
      validateChain?: boolean;
    }
  ): Promise<MessagesResponse> {
    const useCache = options?.useCache ?? true;
    const validateChain = options?.validateChain ?? true;

    if (!useCache || !this.localStore) {
      const serverMessages = await this._fetchMessagesFromServer(topicId, query);
      if (validateChain && serverMessages.messages.length > 0) {
        this._validateAndVerifyMessages(serverMessages.messages);
      }
      return serverMessages;
    }

    // Get cached messages and latest cached timestamp
    const fromTimestamp = query?.from;
    const toTimestamp = query?.to;
    const limit = query?.limit ?? 100;

    const cached = await this.localStore.getMessages(this.spaceId, topicId, {
      fromTimestamp,
      toTimestamp,
      limit,
    });
    const latestCachedTs = await this.localStore.getLatestTimestamp(this.spaceId, topicId);

    // Determine if we need to fetch from server
    const needServerFetch =
      toTimestamp === undefined ||
      latestCachedTs === null ||
      toTimestamp > latestCachedTs;

    if (!needServerFetch && cached.length > 0) {
      return { messages: cached, has_more: cached.length >= limit };
    }

    // Fetch from server - either everything or just newer messages
    let serverFrom = fromTimestamp;
    if (latestCachedTs !== null && cached.length > 0) {
      serverFrom = latestCachedTs + 1;
    }

    const serverQuery: MessageQuery = { limit };
    if (serverFrom !== undefined) serverQuery.from = serverFrom;
    if (toTimestamp !== undefined) serverQuery.to = toTimestamp;

    const serverResponse = await this._fetchMessagesFromServer(topicId, serverQuery);
    const serverMessages = serverResponse.messages;

    if (serverMessages.length === 0) {
      return { messages: cached, has_more: cached.length >= limit };
    }

    // Validate hashes of all new messages
    if (validateChain) {
      for (const msg of serverMessages) {
        if (!verifyMessageHash(this.spaceId, msg)) {
          throw new ChainError(`Message hash verification failed for ${msg.message_hash}`);
        }
      }
    }

    // Check for gap between cached and new messages
    if (validateChain && cached.length > 0) {
      serverMessages.sort((a, b) => a.server_timestamp - b.server_timestamp);
      const oldestNew = serverMessages[0];
      const latestCached = cached.reduce((a, b) =>
        a.server_timestamp > b.server_timestamp ? a : b
      );

      if (oldestNew.prev_hash !== null && oldestNew.prev_hash !== latestCached.message_hash) {
        // Gap detected - fetch missing messages
        const gapMessages = await this._fetchGapMessages(
          topicId,
          latestCached.message_hash,
          oldestNew.prev_hash
        );
        if (gapMessages.length > 0) {
          serverMessages.unshift(...gapMessages);
        }
      }
    }

    // Validate chain integrity if we have both cached and new messages
    if (validateChain && cached.length > 0 && serverMessages.length > 0) {
      const latestCached = cached.reduce((a, b) =>
        a.server_timestamp > b.server_timestamp ? a : b
      );
      if (!validateMessageChainWithAnchor(this.spaceId, serverMessages, latestCached.message_hash)) {
        // Check if chain starts from beginning (prev_hash is null)
        serverMessages.sort((a, b) => a.server_timestamp - b.server_timestamp);
        if (serverMessages[0].prev_hash !== null) {
          throw new ChainError("Chain validation failed: new messages don't link to cached chain");
        }
      }
    }

    // Cache new messages (they've been validated)
    await this.localStore.putMessages(this.spaceId, serverMessages);

    // Merge cached and server messages, deduplicate by hash
    const seenHashes = new Set<string>();
    const merged: Message[] = [];
    for (const msg of [...cached, ...serverMessages]) {
      if (!seenHashes.has(msg.message_hash)) {
        seenHashes.add(msg.message_hash);
        merged.push(msg);
      }
    }
    merged.sort((a, b) => a.server_timestamp - b.server_timestamp);

    return {
      messages: merged.slice(0, limit),
      has_more: merged.length > limit || serverResponse.has_more,
    };
  }

  /**
   * Get a specific message by hash.
   *
   * @param topicId - Topic identifier
   * @param messageHash - Typed message identifier
   * @param options - Caching options
   * @returns Message
   */
  async getMessage(
    topicId: string,
    messageHash: string,
    options?: { useCache?: boolean }
  ): Promise<Message> {
    const useCache = options?.useCache ?? true;

    // Check local cache first
    if (useCache && this.localStore) {
      const cached = await this.localStore.getMessage(this.spaceId, topicId, messageHash);
      if (cached) {
        return cached;
      }
    }

    // Fetch from server
    const token = await this.auth.getToken();
    const message = await getMessage(this.fetchFn, this.baseUrl, token, this.spaceId, topicId, messageHash);

    // Cache the message
    if (useCache && this.localStore) {
      await this.localStore.putMessage(this.spaceId, message);
    }

    return message;
  }

  /**
   * Fetch messages directly from server without caching.
   */
  private async _fetchMessagesFromServer(
    topicId: string,
    query?: MessageQuery
  ): Promise<MessagesResponse> {
    const token = await this.auth.getToken();
    return getMessages(this.fetchFn, this.baseUrl, token, this.spaceId, topicId, query);
  }

  /**
   * Validate message hashes and chain for messages without cache.
   */
  private _validateAndVerifyMessages(messages: Message[]): void {
    for (const msg of messages) {
      if (!verifyMessageHash(this.spaceId, msg)) {
        throw new ChainError(`Message hash verification failed for ${msg.message_hash}`);
      }
    }

    // Validate chain links back to start or is internally consistent
    messages.sort((a, b) => a.server_timestamp - b.server_timestamp);
    if (messages.length > 0) {
      const anchor = messages[0].prev_hash;
      if (!validateMessageChainWithAnchor(this.spaceId, messages, anchor)) {
        throw new ChainError("Chain validation failed: messages don't form valid chain");
      }
    }
  }

  /**
   * Fetch messages to fill gap between cached head and new messages.
   */
  private async _fetchGapMessages(
    topicId: string,
    cachedHeadHash: string,
    targetPrevHash: string,
    maxIterations = 10
  ): Promise<Message[]> {
    const gapMessages: Message[] = [];
    let currentHash: string | null = targetPrevHash;

    for (let i = 0; i < maxIterations; i++) {
      if (currentHash === null || currentHash === cachedHeadHash) {
        break;
      }

      try {
        const msg = await this.getMessage(topicId, currentHash, { useCache: false });
        gapMessages.unshift(msg); // Prepend to maintain order
        currentHash = msg.prev_hash;
      } catch {
        break;
      }
    }

    return gapMessages;
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

    const message = await postMessage(
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

    // Cache the posted message locally so subsequent prev_hash lookups are fresh
    if (this.localStore) {
      await this.localStore.putMessage(this.spaceId, message);
    }

    return message;
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

  /**
   * Process an incoming WebSocket message and store it in the local cache.
   *
   * Call this from your WebSocket `onmessage` handler after parsing the
   * message JSON. This keeps the local store in sync so that operations
   * like `postMessage` (which looks up the latest `prev_hash`) use
   * up-to-date chain state.
   *
   * If the message's `prev_hash` doesn't match the latest cached message,
   * missing messages are fetched from the server to fill the gap before
   * storing the new message.
   *
   * @param message - Parsed Message object from the WebSocket stream
   * @throws ChainError if the message hash doesn't verify or the chain
   *   cannot be connected after gap filling
   */
  async handleIncomingMessage(message: Message): Promise<void> {
    // Verify the message hash
    if (!verifyMessageHash(this.spaceId, message)) {
      throw new ChainError(`Message hash verification failed for ${message.message_hash}`);
    }

    if (!this.localStore) {
      return;
    }

    // Check if we already have this message
    const existing = await this.localStore.getMessage(
      this.spaceId, message.topic_id, message.message_hash
    );
    if (existing) {
      return;
    }

    // Check chain continuity: does the new message link to our latest?
    const latestCached = await this.localStore.getLatestMessage(
      this.spaceId, message.topic_id
    );

    if (latestCached && message.prev_hash !== null &&
        message.prev_hash !== latestCached.message_hash) {
      // Gap detected — fetch missing messages from the server
      const gapMessages = await this._fetchGapMessages(
        message.topic_id,
        latestCached.message_hash,
        message.prev_hash
      );

      if (gapMessages.length > 0) {
        // Verify the gap connects to our cached chain
        const earliestGap = gapMessages[0];
        if (earliestGap.prev_hash !== latestCached.message_hash) {
          throw new ChainError(
            `Chain gap could not be filled: earliest fetched message's prev_hash ` +
            `(${earliestGap.prev_hash}) does not match cached head (${latestCached.message_hash})`
          );
        }

        await this.localStore.putMessages(this.spaceId, gapMessages);
      } else {
        // No gap messages found but prev_hash doesn't match — broken chain
        throw new ChainError(
          `Chain discontinuity: message prev_hash (${message.prev_hash}) ` +
          `does not match cached head (${latestCached.message_hash}) and no gap messages found`
        );
      }
    }

    await this.localStore.putMessage(this.spaceId, message);
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
  // Authorization Utilities
  // ============================================================

  /**
   * Create a role in the space.
   *
   * Roles are stored at auth/roles/{roleName} and can have capabilities
   * granted to them via grantCapabilityToRole().
   *
   * @param roleName - Name of the role to create
   * @param description - Optional description of the role
   * @param prevHash - Previous state message hash (optional, fetched if not provided)
   * @returns MessageCreated with message_hash and server_timestamp
   *
   * @example
   * ```typescript
   * // Create a moderator role
   * await space.createRole('moderator', 'Can moderate content');
   *
   * // Grant capabilities to the role
   * await space.grantCapabilityToRole('moderator', 'delete_posts', {
   *   op: 'delete',
   *   path: 'state/posts/{...}',
   * });
   * ```
   */
  async createRole(
    roleName: string,
    description?: string,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    const roleData: { role_id: string; description?: string } = {
      role_id: roleName,
    };
    if (description) {
      roleData.description = description;
    }

    const roleString = JSON.stringify(roleData);
    const data = stringToBytes(roleString);
    return this.setPlaintextState(`auth/roles/${roleName}`, data, prevHash);
  }

  /**
   * Create a user entry in the space.
   *
   * Users are stored at auth/users/{userId} and can have capabilities
   * granted to them via grantCapabilityToUser() or roles assigned via
   * assignRoleToUser().
   *
   * @param userId - Typed user identifier (U_...)
   * @param description - Optional description of the user
   * @param prevHash - Previous state message hash (optional, fetched if not provided)
   * @returns MessageCreated with message_hash and server_timestamp
   *
   * @example
   * ```typescript
   * // Create a user entry
   * await space.createUser('U_abc123...', 'Alice - project lead');
   *
   * // Assign a role to the user
   * await space.assignRoleToUser('U_abc123...', 'admin');
   * ```
   */
  async createUser(
    userId: string,
    description?: string,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    const userData: { user_id: string; description?: string } = {
      user_id: userId,
    };
    if (description) {
      userData.description = description;
    }

    const userString = JSON.stringify(userData);
    const data = stringToBytes(userString);
    return this.setPlaintextState(`auth/users/${userId}`, data, prevHash);
  }

  /**
   * Grant a capability to a role.
   *
   * Capabilities are stored at auth/roles/{roleName}/rights/{capabilityId}.
   * All users with this role will inherit the capability.
   *
   * @param roleName - Name of the role to grant the capability to
   * @param capabilityId - Unique identifier for this capability
   * @param capability - The capability to grant
   * @param prevHash - Previous state message hash (optional, fetched if not provided)
   * @returns MessageCreated with message_hash and server_timestamp
   *
   * @example
   * ```typescript
   * // Grant read access to all profiles for the 'member' role
   * await space.grantCapabilityToRole('member', 'read_profiles', {
   *   op: 'read',
   *   path: 'state/profiles/{...}',
   * });
   *
   * // Grant write access to a specific path pattern
   * await space.grantCapabilityToRole('admin', 'manage_users', {
   *   op: 'write',
   *   path: 'state/auth/users/{...}',
   * });
   * ```
   */
  async grantCapabilityToRole(
    roleName: string,
    capabilityId: string,
    capability: Capability,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    const capString = JSON.stringify(capability);
    const capData = stringToBytes(capString);
    return this.setPlaintextState(
      `auth/roles/${roleName}/rights/${capabilityId}`,
      capData,
      prevHash
    );
  }

  /**
   * Assign a role to a user.
   *
   * Role assignments are stored at auth/users/{userId}/roles/{roleName}.
   * The user will inherit all capabilities granted to the role.
   *
   * @param userId - Typed user identifier (U_...)
   * @param roleName - Name of the role to assign
   * @param prevHash - Previous state message hash (optional, fetched if not provided)
   * @returns MessageCreated with message_hash and server_timestamp
   *
   * @example
   * ```typescript
   * // Assign the 'admin' role to a user
   * await space.assignRoleToUser('U_abc123...', 'admin');
   *
   * // Assign multiple roles
   * await space.assignRoleToUser('U_abc123...', 'moderator');
   * await space.assignRoleToUser('U_abc123...', 'member');
   * ```
   */
  async assignRoleToUser(
    userId: string,
    roleName: string,
    prevHash?: string | null
  ): Promise<MessageCreated> {
    // Role grants must include both user_id and role_id matching the path
    const roleAssignment = { user_id: userId, role_id: roleName };
    const data = stringToBytes(JSON.stringify(roleAssignment));
    return this.setPlaintextState(
      `auth/users/${userId}/roles/${roleName}`,
      data,
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
   * Enable OPAQUE for this space.
   *
   * Sets up the OPAQUE server configuration and creates the opaque-user role
   * with the necessary permissions. This must be called by an admin before
   * users can register OPAQUE credentials.
   *
   * This method:
   * 1. Creates OPAQUE server setup if it doesn't exist (stored in data)
   * 2. Creates opaque-user role if it doesn't exist (stored in state)
   * 3. Adds CREATE capability for opaque/users/{any} if missing
   *
   * @returns Object indicating what was created
   *
   * @example
   * ```typescript
   * // As space admin, enable OPAQUE
   * const result = await space.enableOpaque();
   * if (result.serverSetupCreated) {
   *   console.log('OPAQUE server setup created');
   * }
   * ```
   */
  async enableOpaque(): Promise<EnableOpaqueResult> {
    const result: EnableOpaqueResult = {
      serverSetupCreated: false,
      roleCreated: false,
      capabilityCreated: false,
    };

    // Step 1: Check/create OPAQUE server setup (stored in data store)
    // The server setup is generated by the backend using opaque_snake to ensure
    // compatibility between TypeScript client and Python server.
    try {
      await this.getPlaintextData(OPAQUE_SERVER_SETUP_PATH);
      // Server setup exists
    } catch (error) {
      // Server setup doesn't exist, request one from the backend
      const token = await this.auth.getToken();
      const serverSetupB64 = await createOpaqueSetup(
        this.fetchFn,
        this.baseUrl,
        token,
        this.spaceId
      );
      // Store the backend-generated setup bytes
      await this.setPlaintextData(
        OPAQUE_SERVER_SETUP_PATH,
        decodeBase64(serverSetupB64)
      );
      result.serverSetupCreated = true;
    }

    // Step 2: Check/create opaque-user role (stored in state)
    try {
      await this.getPlaintextState(`auth/roles/${OPAQUE_USER_ROLE_ID}`);
      // Role exists
    } catch (error) {
      // Role doesn't exist, create it
      await this.createRole(
        OPAQUE_USER_ROLE_ID,
        'Role for users who can register OPAQUE credentials'
      );
      result.roleCreated = true;
    }

    // Step 3: Check/create CREATE capability for opaque/users/{any}
    const capPath = `auth/roles/${OPAQUE_USER_ROLE_ID}/rights/${OPAQUE_USER_CAP_ID}`;
    try {
      await this.getPlaintextState(capPath);
      // Capability exists
    } catch (error) {
      // Capability doesn't exist, create it
      await this.grantCapabilityToRole(
        OPAQUE_USER_ROLE_ID,
        OPAQUE_USER_CAP_ID,
        {
          op: 'create',
          path: 'data/opaque/users/{any}',
        }
      );
      result.capabilityCreated = true;
    }

    return result;
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
