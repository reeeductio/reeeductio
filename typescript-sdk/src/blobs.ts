/**
 * Blob storage helpers for reeeductio.
 *
 * Provides utilities for uploading, downloading, and managing encrypted blobs.
 */

import { computeHash, toBlobId, encodeBase64, encryptAesGcm, decryptAesGcm } from './crypto.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { debugLog, errorLog, warnLog } from './debug.js';
import type { BlobCreated, ApiError } from './types.js';
import { createApiError, BlobError } from './exceptions.js';

/**
 * Compute blob identifier from content.
 *
 * The blob_id is a content-addressed identifier based on SHA256 hash.
 *
 * @param data - Raw blob data
 * @returns 44-char base64 blob identifier with 'B' prefix
 */
export function computeBlobId(data: Uint8Array): string {
  const hashBytes = computeHash(data);
  return toBlobId(hashBytes);
}

/**
 * Upload plaintext blob to the space.
 *
 * The blob_id is computed from the content hash.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param data - Encrypted blob data
 * @returns BlobCreated with blob_id and size
 */
export async function uploadBlob(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  data: Uint8Array
): Promise<BlobCreated> {
  // Compute blob ID from content
  const hashBytes = computeHash(data);
  const blobId = toBlobId(hashBytes);
  const url = `${baseUrl}/spaces/${spaceId}/blobs/${blobId}`;

  debugLog('blobs', 'PUT blob', { url, spaceId, blobId, dataBytes: data.length });
  const response = await fetchFn(url, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/octet-stream',
    },
    body: data,
    redirect: 'manual',
  });

  // Handle 307 redirect to S3 presigned URL
  if (response.status === 307) {
    const s3Url = response.headers.get('Location');
    if (!s3Url) {
      throw new BlobError('307 redirect missing Location header');
    }
    debugLog('blobs', 'Redirecting blob upload to S3', { blobId, s3Url });
    const s3Response = await fetchFn(s3Url, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/octet-stream',
        'x-amz-checksum-sha256': encodeBase64(hashBytes),
      },
      body: data,
    });

    if (!s3Response.ok) {
      errorLog('blobs', 'Blob upload to S3 (redirect) failed', { blobId, status: s3Response.status });
      throw new BlobError(`Failed to upload blob to S3: ${s3Response.status}`);
    }

    debugLog('blobs', 'Blob upload to S3 (redirect) ok', { blobId, size: data.length });
    return { blob_id: blobId, size: data.length };
  }

  // Handle 409 Conflict (blob already exists - fine for content-addressed storage)
  if (response.status === 409) {
    warnLog('blobs', 'Blob already exists', { blobId, size: data.length });
    return { blob_id: blobId, size: data.length };
  }

  if (!response.ok) {
    const error = await parseError(response);
    errorLog('blobs', 'PUT blob failed', { status: response.status, error, blobId });
    throw createApiError(response.status, error);
  }

  const result = (await response.json()) as BlobCreated & { upload_url?: string };

  // Check if server returned a presigned upload URL
  if (result.upload_url) {
    debugLog('blobs', 'Uploading blob to presigned URL', { blobId });
    const headers: Record<string, string> = {
      'Content-Type': 'application/octet-stream',
      // Presigned S3 URLs may require checksum enforcement.
      'x-amz-checksum-sha256': encodeBase64(hashBytes),
    };
    // Upload to S3 directly (no auth header for presigned URL)
    const s3Response = await fetchFn(result.upload_url, {
      method: 'PUT',
      headers,
      body: data,
    });

    if (!s3Response.ok) {
      errorLog('blobs', 'Blob upload to presigned URL failed', { blobId, status: s3Response.status });
      throw new BlobError(`Failed to upload blob to S3: ${s3Response.status}`);
    }

    debugLog('blobs', 'Blob upload to presigned URL ok', { blobId, size: data.length });
    return { blob_id: blobId, size: data.length };
  }

  // Direct upload completed (server stored the blob)
  debugLog('blobs', 'PUT blob ok', { status: response.status, blobId: result.blob_id, size: result.size });
  return { blob_id: result.blob_id, size: result.size };
}

/**
 * Result of encrypting and uploading a blob.
 */
export interface EncryptedBlobCreated extends BlobCreated {
  /** 32-byte AES-256 data encryption key (DEK) used to encrypt the blob */
  key: Uint8Array;
}

/**
 * Encrypt and upload a blob to the space.
 *
 * Generates a random AES-256 data encryption key (DEK), encrypts the data
 * using AES-GCM-256, and uploads the encrypted blob.
 * The blob_id is computed from the encrypted content hash.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param data - Plaintext blob data to encrypt
 * @param associatedData - Optional additional authenticated data (AAD)
 * @returns EncryptedBlobCreated with blob_id, size, and the generated DEK
 */
export async function encryptAndUploadBlob(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  data: Uint8Array,
  associatedData?: Uint8Array
): Promise<EncryptedBlobCreated> {
  // Generate random 32-byte DEK
  const key = randomBytes(32);

  debugLog('blobs', 'Encrypting blob', { plaintextBytes: data.length });
  const encrypted = encryptAesGcm(data, key, associatedData);
  debugLog('blobs', 'Blob encrypted', { encryptedBytes: encrypted.length });

  const result = await uploadBlob(fetchFn, baseUrl, token, spaceId, encrypted);
  return { ...result, key };
}

/**
 * Download plaintext blob from the space.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param blobId - Typed blob identifier
 * @returns Blob data
 */
export async function downloadBlob(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  blobId: string
): Promise<Uint8Array> {
  const url = `${baseUrl}/spaces/${spaceId}/blobs/${blobId}`;

  debugLog('blobs', 'GET blob', { url, spaceId, blobId });
  const response = await fetchFn(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
    redirect: 'manual',
  });

  // Handle 307 redirect to S3 presigned URL
  if (response.status === 307) {
    const s3Url = response.headers.get('Location');
    if (!s3Url) {
      throw new BlobError('307 redirect missing Location header');
    }
    debugLog('blobs', 'Redirecting blob download to S3', { blobId, s3Url });
    const s3Response = await fetchFn(s3Url, {
      method: 'GET',
    });

    if (!s3Response.ok) {
      errorLog('blobs', 'Blob download from S3 (redirect) failed', { blobId, status: s3Response.status });
      throw new BlobError(`Failed to download blob from S3: ${s3Response.status}`);
    }

    debugLog('blobs', 'Blob download from S3 (redirect) ok', { blobId });
    return new Uint8Array(await s3Response.arrayBuffer());
  }

  if (!response.ok) {
    const error = await parseError(response);
    errorLog('blobs', 'GET blob failed', { status: response.status, error, blobId });
    throw createApiError(response.status, error);
  }

  // Check if response is JSON with a download URL
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    const result = (await response.json()) as { download_url?: string };
    if (result.download_url) {
      debugLog('blobs', 'Downloading blob from presigned URL', { blobId });
      // Download from S3 directly (no auth header for presigned URL)
      const s3Response = await fetchFn(result.download_url, {
        method: 'GET',
      });

      if (!s3Response.ok) {
        errorLog('blobs', 'Blob download from presigned URL failed', { blobId, status: s3Response.status });
        throw new BlobError(`Failed to download blob from S3: ${s3Response.status}`);
      }

      debugLog('blobs', 'Blob download from presigned URL ok', { blobId });
      return new Uint8Array(await s3Response.arrayBuffer());
    }
  }

  // Direct download (server returned the blob content)
  debugLog('blobs', 'GET blob ok', { status: response.status, blobId });
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Download and decrypt a blob from the space.
 *
 * Downloads the encrypted blob and decrypts it using AES-GCM-256 with
 * the provided data encryption key (DEK).
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param blobId - Typed blob identifier
 * @param key - 32-byte AES-256 data encryption key (DEK)
 * @param associatedData - Optional additional authenticated data (AAD)
 * @returns Decrypted plaintext blob data
 */
export async function downloadAndDecryptBlob(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  blobId: string,
  key: Uint8Array,
  associatedData?: Uint8Array
): Promise<Uint8Array> {
  const encrypted = await downloadBlob(fetchFn, baseUrl, token, spaceId, blobId);

  debugLog('blobs', 'Decrypting blob', { blobId, encryptedBytes: encrypted.length });
  const plaintext = decryptAesGcm(encrypted, key, associatedData);
  debugLog('blobs', 'Blob decrypted', { blobId, plaintextBytes: plaintext.length });

  return plaintext;
}

/**
 * Delete blob from the space.
 *
 * Only the uploader or space admin can delete a blob.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param blobId - Typed blob identifier
 */
export async function deleteBlob(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  blobId: string
): Promise<void> {
  const url = `${baseUrl}/spaces/${spaceId}/blobs/${blobId}`;

  debugLog('blobs', 'DELETE blob', { url, spaceId, blobId });
  const response = await fetchFn(url, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    const error = await parseError(response);
    errorLog('blobs', 'DELETE blob failed', { status: response.status, error, blobId });
    throw createApiError(response.status, error);
  }

  debugLog('blobs', 'DELETE blob ok', { status: response.status, blobId });
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
