/**
 * Simple key-value data store helpers for reeeductio.
 *
 * Provides utilities for reading and writing signed data entries.
 */

import {
  signData,
  encodeBase64,
  stringToBytes,
} from './crypto.js';
import { debugLog, errorLog } from './debug.js';
import type {
  DataEntry,
  DataSetResponse,
  ApiError,
} from './types.js';
import { createApiError, NotFoundError } from './exceptions.js';

/**
 * Compute signature for data entry.
 *
 * Signature is over: space_id|path|base64(data)|signed_at
 *
 * @param spaceId - Typed space identifier
 * @param path - Data path
 * @param data - Data bytes
 * @param signedAt - Unix timestamp in milliseconds
 * @param privateKey - Signer's Ed25519 private key
 * @returns 64-byte signature
 */
export async function computeDataSignature(
  spaceId: string,
  path: string,
  data: Uint8Array,
  signedAt: number,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  // Signature is over: space_id|path|base64(data)|signed_at
  // The server verifies against the base64-encoded data string from the JSON body,
  // so we must sign over the same base64 representation.
  const dataB64 = encodeBase64(data);
  const sigInput = stringToBytes(`${spaceId}|${path}|${dataB64}|${signedAt}`);
  return signData(sigInput, privateKey);
}

/**
 * Get data value at path.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param path - Data path (e.g., "profiles/alice", "settings/theme")
 * @returns DataEntry with the stored data
 */
export async function getData(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  path: string
): Promise<DataEntry> {
  const url = `${baseUrl}/spaces/${spaceId}/data/${path}`;

  debugLog('data', 'GET data', { url, spaceId, path });
  const response = await fetchFn(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    if (response.status === 404) {
      debugLog('data', 'GET data not found', { status: response.status, spaceId, path });
      throw new NotFoundError(`No data found at path: ${path}`);
    }
    const error = await parseError(response);
    errorLog('data', 'GET data failed', { status: response.status, error, spaceId, path });
    throw createApiError(response.status, error);
  }

  const entry = (await response.json()) as DataEntry;
  debugLog('data', 'GET data ok', { status: response.status, spaceId, path });
  return entry;
}

/**
 * Set data value at path with cryptographic signature.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param path - Data path
 * @param data - Data to store
 * @param signedBy - Typed user/tool identifier of signer
 * @param privateKey - Signer's Ed25519 private key
 * @returns DataSetResponse with the path and timestamp
 */
export async function setData(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  path: string,
  data: Uint8Array,
  signedBy: string,
  privateKey: Uint8Array
): Promise<DataSetResponse> {
  // Current timestamp in milliseconds
  const signedAt = Date.now();

  // Compute signature
  const signature = await computeDataSignature(
    spaceId,
    path,
    data,
    signedAt,
    privateKey
  );

  // Create request body
  const body = {
    data: encodeBase64(data),
    signature: encodeBase64(signature),
    signed_by: signedBy,
    signed_at: signedAt,
  };

  const url = `${baseUrl}/spaces/${spaceId}/data/${path}`;
  debugLog('data', 'PUT data', { url, spaceId, path, dataBytes: data.length, signedAt });
  const response = await fetchFn(url, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const error = await parseError(response);
    errorLog('data', 'PUT data failed', { status: response.status, error, spaceId, path });
    throw createApiError(response.status, error);
  }

  const result = (await response.json()) as DataSetResponse;
  debugLog('data', 'PUT data ok', { status: response.status, spaceId, path, signedAt: result.signed_at });
  return result;
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
