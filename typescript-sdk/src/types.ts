/**
 * Typed identifier type values.
 *
 * Header format: [6 bits: type][2 bits: version]
 * The type value is shifted left by 2 bits in the header byte.
 */
export enum IdType {
  /** BLOB type (1 = 0b000001) - SHA256 hash identifier, prefix 'B' */
  BLOB = 0b000001,
  /** SPACE type (2 = 0b000010) - Ed25519 public key, prefix 'C' */
  SPACE = 0b000010,
  /** MESSAGE type (12 = 0b001100) - SHA256 hash identifier, prefix 'M' */
  MESSAGE = 0b001100,
  /** TOOL type (19 = 0b010011) - Ed25519 public key, prefix 'T' */
  TOOL = 0b010011,
  /** USER type (20 = 0b010100) - Ed25519 public key, prefix 'U' */
  USER = 0b010100,
}

/**
 * Capability operations.
 *
 * - read: Can read data
 * - create: Can create new entries (only if not exists)
 * - modify: Can update existing entries (only if exists)
 * - delete: Can delete entries
 * - write: Full write access (dominates create, modify, delete, and read)
 */
export type CapabilityOp = 'read' | 'create' | 'modify' | 'delete' | 'write';

/**
 * Capability definition for authorization.
 */
export interface Capability {
  /** Operation type */
  op: CapabilityOp;
  /**
   * State path pattern supporting wildcards:
   * - {self} - resolves to acting user's ID
   * - {any} - matches any single segment
   * - {other} - matches any ID except acting user
   * - {...} - matches remaining path segments
   * - Trailing / indicates prefix match
   */
  path: string;
  /** If true, user can only operate on objects they created/own */
  must_be_owner?: boolean;
}

/**
 * Message structure for blockchain-style message chains.
 */
export interface Message {
  /** Typed message identifier (SHA256 hash with header, starts with 'M') */
  message_hash: string;
  /** Topic identifier (slug format) */
  topic_id: string;
  /**
   * Message type/category. For state messages, contains the state path.
   * For regular messages, used for app-specific categorization.
   */
  type: string;
  /** Typed message identifier of previous message (null for first message) */
  prev_hash: string | null;
  /** Encrypted message or state data (base64-encoded) */
  data: string;
  /** Typed user identifier of message sender (starts with 'U') */
  sender: string;
  /** Ed25519 signature over message_hash by sender */
  signature: string;
  /** Unix timestamp in milliseconds (server-assigned) */
  server_timestamp: number;
}

/**
 * Message creation request (without server-assigned fields).
 */
export interface MessageCreate {
  /** Message type/category */
  type: string;
  /** Previous message hash (null for first message in topic) */
  prev_hash: string | null;
  /** Encrypted data (base64-encoded) */
  data: string;
  /** Client-computed message hash */
  message_hash: string;
  /** Ed25519 signature over message_hash */
  signature: string;
}

/**
 * Response from posting a message.
 */
export interface MessageCreated {
  /** The message hash */
  message_hash: string;
  /** Server timestamp in milliseconds */
  server_timestamp: number;
}

/**
 * Query parameters for message retrieval.
 */
export interface MessageQuery {
  /** Server timestamp in milliseconds (inclusive) - get messages after this time */
  from?: number;
  /** Server timestamp in milliseconds (inclusive) - get messages before this time */
  to?: number;
  /** Maximum number of messages to return (default 100, max 1000) */
  limit?: number;
}

/**
 * Response from querying messages.
 */
export interface MessagesResponse {
  /** Array of messages */
  messages: Message[];
  /** Whether more messages exist beyond the limit */
  has_more: boolean;
}

/**
 * Simple key-value data entry with cryptographic signature.
 */
export interface DataEntry {
  /** Data path using slug-formatted segments */
  path: string;
  /** Base64-encoded data */
  data: string;
  /** Ed25519 signature over (space_id|path|data|signed_at) */
  signature: string;
  /** Typed user/tool identifier of signer */
  signed_by: string;
  /** Unix timestamp in milliseconds when entry was signed */
  signed_at: number;
}

/**
 * Request body for setting data.
 */
export interface DataSetRequest {
  /** Base64-encoded data */
  data: string;
  /** Ed25519 signature */
  signature: string;
  /** Signer's identifier */
  signed_by: string;
  /** Timestamp when signed */
  signed_at: number;
}

/**
 * Response from setting data.
 */
export interface DataSetResponse {
  /** The data path */
  path: string;
  /** Timestamp from the signed data entry */
  signed_at: number;
}

/**
 * State set request (creates message in "state" topic).
 */
export interface StateSetRequest {
  /** Previous message hash in state topic */
  prev_hash: string | null;
  /** Base64-encoded state data */
  data: string;
  /** Client-computed message hash */
  message_hash: string;
  /** Ed25519 signature over message_hash */
  signature: string;
  /** Unix timestamp in milliseconds when signed */
  signed_at: number;
}

/**
 * Response from setting state.
 */
export interface StateSetResponse {
  /** The message hash */
  message_hash: string;
  /** Server timestamp in milliseconds */
  server_timestamp: number;
}

/**
 * Space member information.
 */
export interface Member {
  /** Typed user identifier */
  public_key: string;
  /** Unix timestamp in milliseconds when member was added */
  added_at: number;
  /** Typed user identifier of user who added this member */
  added_by: string;
}

/**
 * Role definition.
 */
export interface Role {
  /** Human-readable role identifier */
  role_id: string;
  /** Human-readable description */
  description: string;
  /** Typed user identifier of role creator */
  created_by: string;
  /** Unix timestamp in milliseconds when role was created */
  created_at: number;
  /** Ed25519 signature over the role definition */
  signature: string;
}

/**
 * Role grant to a user.
 */
export interface RoleGrant {
  /** Typed user identifier of the user receiving the role */
  user_id: string;
  /** Human-readable role identifier being granted */
  role_id: string;
  /** Typed user identifier of the user granting this role */
  granted_by: string;
  /** Unix timestamp in milliseconds when role was granted */
  granted_at: number;
  /** Optional Unix timestamp when role grant expires */
  expires_at?: number;
  /** Ed25519 signature over the role grant */
  signature: string;
}

/**
 * Challenge response from authentication endpoint.
 */
export interface ChallengeResponse {
  /** Random nonce to sign (base64-encoded) */
  challenge: string;
  /** Unix timestamp in milliseconds when challenge expires */
  expires_at: number;
}

/**
 * Token response from verification endpoint.
 */
export interface TokenResponse {
  /** JWT bearer token */
  token: string;
  /** Unix timestamp in milliseconds when token expires */
  expires_at: number;
}

/**
 * Response from uploading a blob.
 */
export interface BlobCreated {
  /** Typed blob identifier (SHA256 hash with header, starts with 'B') */
  blob_id: string;
  /** Size in bytes */
  size: number;
}

/**
 * API error response.
 */
export interface ApiError {
  /** Error message */
  error: string;
  /** Error code */
  code?: string;
  /** Additional error details */
  details?: Record<string, unknown>;
}

/**
 * Configuration options for the Space client.
 */
export interface SpaceConfig {
  /** Base URL of the API server */
  baseUrl: string;
  /** Space identifier (44-char base64, starts with 'C') */
  spaceId: string;
  /** Optional symmetric key for encryption (32 bytes) */
  symmetricKey?: Uint8Array;
  /** Optional fetch implementation for custom HTTP handling */
  fetch?: typeof fetch;
}

/**
 * Configuration for admin authentication.
 */
export interface AdminConfig {
  /** Base URL of the API server */
  baseUrl: string;
  /** Optional fetch implementation */
  fetch?: typeof fetch;
}

/**
 * Key pair for Ed25519 signing.
 */
export interface KeyPair {
  /** Private key (32 bytes) */
  privateKey: Uint8Array;
  /** Public key (32 bytes) */
  publicKey: Uint8Array;
}

/**
 * WebSocket message event.
 */
export interface WebSocketMessage {
  /** The received message */
  message: Message;
}

/**
 * WebSocket close event info.
 */
export interface WebSocketCloseInfo {
  code: number;
  reason: string;
  wasClean: boolean;
}

/**
 * WebSocket error info.
 */
export interface WebSocketErrorInfo {
  message?: string;
}

/**
 * WebSocket connection options.
 */
export interface WebSocketOptions {
  /** JWT token for authentication */
  token: string;
  /** Optional callback for connection open */
  onOpen?: () => void;
  /** Optional callback for connection close */
  onClose?: (event: WebSocketCloseInfo) => void;
  /** Optional callback for errors */
  onError?: (error: WebSocketErrorInfo) => void;
  /** Optional callback for messages */
  onMessage?: (message: Message) => void;
}

/**
 * Tool definition stored at auth/tools/{tool_id}.
 *
 * Tools are limited-use keypairs with NO ambient authority.
 * They can only perform actions explicitly granted via capabilities.
 */
export interface Tool {
  /** Typed tool identifier (44-char URL-safe base64, starts with 'T') */
  tool_id: string;
  /** Human-readable description of the tool's purpose */
  description: string;
  /** Optional maximum number of write operations the tool can perform */
  use_limit?: number;
}

/**
 * Response from creating a tool.
 *
 * Includes the tool definition and the keypair for authenticating as the tool.
 */
export interface ToolCreated {
  /** The tool definition */
  tool: Tool;
  /** The tool's Ed25519 keypair for authentication */
  keyPair: KeyPair;
}
