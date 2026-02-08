/**
 * Message handling helpers for reeeductio.
 *
 * Provides utilities for message hash computation, signing, and API operations.
 */

import {
  computeHash,
  toMessageId,
  decodeUrlSafeBase64,
  encodeBase64,
  signData,
  stringToBytes,
} from './crypto.js';
import { debugLog, warnLog, errorLog } from './debug.js';
import type {
  Message,
  MessageCreated,
  MessageQuery,
  MessagesResponse,
  ApiError,
} from './types.js';
import { createApiError } from './exceptions.js';

/**
 * Compute message hash for chain validation.
 *
 * Hash is computed over: space_id|topic_id|prev_hash|data|sender
 * where data is the base64-encoded message content.
 *
 * @param spaceId - Typed space identifier
 * @param topicId - Topic identifier
 * @param prevHash - Typed hash of previous message (null for first message)
 * @param dataBase64 - Base64-encoded message content
 * @param sender - Typed sender identifier
 * @returns Typed message hash (44-char base64 starting with 'M')
 */
export function computeMessageHash(
  spaceId: string,
  topicId: string,
  msgType: string,
  prevHash: string | null,
  dataBase64: string,
  sender: string
): string {
  // Hash is over: space_id|topic_id|prev_hash|data|sender
  // prev_hash is "null" when null, otherwise the actual hash
  const prevHashStr = prevHash ?? 'null';
  const hashInput = stringToBytes(`${spaceId}|${topicId}|${msgType}|${prevHashStr}|${dataBase64}|${sender}`);

  const hashBytes = computeHash(hashInput);
  return toMessageId(hashBytes);
}

/**
 * Post a message to a topic.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param topicId - Topic identifier
 * @param msgType - Message type/category
 * @param data - Encrypted message data
 * @param prevHash - Hash of previous message (null for first)
 * @param senderPublicKeyTyped - Typed sender public key
 * @param senderPrivateKey - Sender's private key for signing
 * @returns Message creation result
 */
export async function postMessage(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  topicId: string,
  msgType: string,
  data: Uint8Array,
  prevHash: string | null,
  senderPublicKeyTyped: string,
  senderPrivateKey: Uint8Array
): Promise<MessageCreated> {
  // Base64 encode the data first (needed for hash and request body)
  const dataBase64 = encodeBase64(data);

  // Compute message hash over: space_id|topic_id|prev_hash|data|sender
  const messageHash = computeMessageHash(
    spaceId,
    topicId,
    msgType,
    prevHash,
    dataBase64,
    senderPublicKeyTyped
  );

  // Sign the message hash (sign the typed identifier bytes)
  const messageHashBytes = decodeUrlSafeBase64(messageHash);
  const signature = await signData(messageHashBytes, senderPrivateKey);

  // Create request body
  const body = {
    type: msgType,
    prev_hash: prevHash,
    data: dataBase64,
    message_hash: messageHash,
    signature: encodeBase64(signature),
  };

  // Post message
  const url = `${baseUrl}/spaces/${spaceId}/topics/${topicId}/messages`;
  debugLog('messages', 'POST message', {
    url,
    spaceId,
    topicId,
    msgType,
    prevHash,
    dataBytes: data.length,
    messageHash,
  });
  const response = await fetchFn(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const error = await parseError(response);
  errorLog('messages', 'POST message failed', { status: response.status, error, messageHash });
    throw createApiError(response.status, error);
  }

  const created = (await response.json()) as MessageCreated;
  debugLog('messages', 'POST message ok', {
    status: response.status,
    messageHash: created.message_hash,
    serverTimestamp: created.server_timestamp,
  });
  return created;
}

/**
 * Get messages from a topic.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param topicId - Topic identifier
 * @param query - Optional query parameters
 * @returns Messages response with messages array and has_more flag
 *
 * Ordering:
 * - If query.from and query.to are both provided and from > to, results are
 *   returned in reverse-chronological order (newest first).
 * - Otherwise, results are returned in chronological order (oldest first).
 */
export async function getMessages(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  topicId: string,
  query?: MessageQuery
): Promise<MessagesResponse> {
  const params = new URLSearchParams();
  if (query?.from !== undefined) {
    params.set('from', query.from.toString());
  }
  if (query?.to !== undefined) {
    params.set('to', query.to.toString());
  }
  if (query?.limit !== undefined) {
    params.set('limit', query.limit.toString());
  }

  const queryString = params.toString();
  const url = `${baseUrl}/spaces/${spaceId}/topics/${topicId}/messages${queryString ? `?${queryString}` : ''}`;

  debugLog('messages', 'GET messages', { url, spaceId, topicId, query });
  const response = await fetchFn(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    if (response.status === 404) {
  debugLog('messages', 'GET messages not found', { status: response.status, spaceId, topicId });
      return { messages: [], has_more: false };
    }
    const error = await parseError(response);
    errorLog('messages', 'GET messages failed', { status: response.status, error, spaceId, topicId });
    throw createApiError(response.status, error);
  }

  const result = (await response.json()) as MessagesResponse;
  debugLog('messages', 'GET messages ok', {
    status: response.status,
    count: result.messages.length,
    hasMore: result.has_more,
    spaceId,
    topicId,
  });
  return result;
}

/**
 * Get a specific message by hash.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param topicId - Topic identifier
 * @param messageHash - Typed message identifier
 * @returns The message
 */
export async function getMessage(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  topicId: string,
  messageHash: string
): Promise<Message> {
  const url = `${baseUrl}/spaces/${spaceId}/topics/${topicId}/messages/${messageHash}`;

  debugLog('messages', 'GET message', { url, spaceId, topicId, messageHash });
  const response = await fetchFn(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    const error = await parseError(response);
  errorLog('messages', 'GET message failed', { status: response.status, error, messageHash });
    throw createApiError(response.status, error);
  }

  const message = (await response.json()) as Message;
  debugLog('messages', 'GET message ok', { status: response.status, messageHash });
  return message;
}

/**
 * Validate that a list of messages forms a valid chain.
 *
 * @param spaceId - Typed space identifier
 * @param messages - List of Message objects in chronological order
 * @returns True if chain is valid, False otherwise
 */
export function validateMessageChain(spaceId: string, messages: Message[]): boolean {
  let prevHash: string | null = null;

  for (const msg of messages) {
    // Check that prev_hash matches
    if (msg.prev_hash !== prevHash) {
      warnLog('messages', 'Message chain mismatch', {
        expectedPrevHash: prevHash,
        actualPrevHash: msg.prev_hash,
        messageHash: msg.message_hash,
      });
      return false;
    }

    // Skip validation if data is missing
    if (!msg.data) {
      prevHash = msg.message_hash;
      continue;
    }

    // Verify message hash - data is already base64-encoded
    const expectedHash = computeMessageHash(
      spaceId,
      msg.topic_id,
      msg.type,
      msg.prev_hash,
      msg.data,
      msg.sender
    );

    if (msg.message_hash !== expectedHash) {
      warnLog('messages', 'Message hash mismatch', {
        expectedHash,
        actualHash: msg.message_hash,
        messageHash: msg.message_hash,
      });
      return false;
    }

    prevHash = msg.message_hash;
  }

  return true;
}

/**
 * Parse error response from API.
 */
async function parseError(response: Response): Promise<ApiError | undefined> {
  try {
    return (await response.json()) as ApiError;
  } catch {
    return undefined;
  }
}
