/**
 * reeeductio TypeScript SDK
 *
 * End-to-end encrypted messaging with capability-based authorization.
 *
 * @example
 * ```typescript
 * import { Space, generateKeyPair } from 'reeeductio';
 *
 * // Generate a key pair
 * const keyPair = await generateKeyPair();
 *
 * // Create a Space client
 * const space = new Space({
 *   spaceId: 'C...',
 *   keyPair,
 *   symmetricRoot: new Uint8Array(32), // Your 32-byte symmetric key
 *   baseUrl: 'https://api.example.com',
 * });
 *
 * // Authenticate
 * await space.authenticate();
 *
 * // Read and write state
 * await space.setPlaintextState('profiles/alice', '{"name": "Alice"}');
 * const state = await space.getPlaintextState('profiles/alice');
 *
 * // Post messages
 * await space.postMessage('chat', 'text', new TextEncoder().encode('Hello!'));
 * ```
 */

// Types
export type {
  CapabilityOp,
  Capability,
  Message,
  MessageCreate,
  MessageCreated,
  MessageQuery,
  MessagesResponse,
  DataEntry,
  DataSetRequest,
  DataSetResponse,
  StateSetRequest,
  StateSetResponse,
  Member,
  Role,
  RoleGrant,
  ChallengeResponse,
  TokenResponse,
  BlobCreated,
  ApiError,
  SpaceConfig,
  AdminConfig,
  KeyPair,
  WebSocketMessage,
  WebSocketCloseInfo,
  WebSocketErrorInfo,
  WebSocketOptions,
} from './types.js';

export { IdType } from './types.js';

// Exceptions
export {
  ReeeductioError,
  AuthenticationError,
  AuthorizationError,
  ValidationError,
  NotFoundError,
  ChainError,
  BlobError,
  StreamError,
  ApiRequestError,
  createApiError,
} from './exceptions.js';

// Crypto utilities
export {
  generateKeyPair,
  signData,
  verifySignature,
  computeHash,
  deriveKey,
  encryptAesGcm,
  decryptAesGcm,
  encodeBase64,
  decodeBase64,
  encodeUrlSafeBase64,
  decodeUrlSafeBase64,
  toUserId,
  toToolId,
  toSpaceId,
  toMessageId,
  toBlobId,
  getIdentifierType,
  extractFromTypedId,
  extractPublicKey,
  concatBytes,
  stringToBytes,
  bytesToString,
} from './crypto.js';

// Authentication
export { AuthSession, AdminAuthSession } from './auth.js';

// Message operations
export {
  computeMessageHash,
  postMessage,
  getMessages,
  getMessage,
  validateMessageChain,
} from './messages.js';

// State operations
export { getState, setState, getStateHistory } from './state.js';

// Data operations
export { computeDataSignature, getData, setData } from './kvdata.js';

// Blob operations
export { computeBlobId, uploadBlob, downloadBlob, deleteBlob } from './blobs.js';

// Debug logging
export {
  LogLevel,
  Logger,
  createLogger,
  getLogLevel,
  setLogLevel,
  isDebugEnabled,
  setDebugEnabled,
  debugLog,
  infoLog,
  warnLog,
  errorLog,
  traceLog,
} from './debug.js';

// High-level clients
export { Space, AdminClient } from './client.js';
