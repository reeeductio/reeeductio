/**
 * E2E tests for blob storage.
 *
 * Run with: npm run test:e2e
 * Requires: docker-compose -f backend/docker-compose.e2e.yml up -d
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { Space } from '../../client.js';
import { generateKeyPair, toSpaceId, stringToBytes, bytesToString } from '../../crypto.js';
import { computeBlobId } from '../../blobs.js';
import { E2E_BACKEND_URL, waitForBackend, fixMinioUrl } from './setup.js';

/**
 * Custom fetch that fixes MinIO URLs for local testing.
 *
 * When running with docker-compose, the backend returns presigned URLs
 * pointing to 'minio:9000', but from the host we need 'localhost:9000'.
 */
function createMinioFixingFetch(): typeof fetch {
  return async (input, init) => {
    const response = await fetch(input, init);

    // If we get a redirect with a MinIO URL, fix it
    if (response.status === 307) {
      const location = response.headers.get('Location');
      if (location && location.includes('minio:9000')) {
        // Create a new response with the fixed URL
        const fixedUrl = fixMinioUrl(location);
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: new Headers({
            ...Object.fromEntries(response.headers.entries()),
            'Location': fixedUrl,
          }),
        });
      }
    }

    return response;
  };
}

describe('E2E: Blob Storage', () => {
  beforeAll(async () => {
    await waitForBackend();
  }, 60000);

  it('should upload and download a blob', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(1);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
      fetch: createMinioFixingFetch(),
    });

    const content = 'This is test blob content from TypeScript SDK!';
    const data = stringToBytes(content);

    // Upload blob
    const result = await space.uploadPlaintextBlob(data);

    expect(result.blob_id).toBeDefined();
    expect(result.blob_id[0]).toBe('B');
    expect(result.size).toBe(data.length);

    // Verify blob ID matches content hash
    expect(result.blob_id).toBe(computeBlobId(data));

    // Download blob
    const downloaded = await space.downloadPlaintextBlob(result.blob_id);

    expect(downloaded).toBeInstanceOf(Uint8Array);
    expect(bytesToString(downloaded)).toBe(content);
  });

  it('should upload and download encrypted blob', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(2);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
      fetch: createMinioFixingFetch(),
    });

    const content = 'This is secret blob content!';
    const data = stringToBytes(content);

    // Encrypt and upload
    const result = await space.encryptAndUploadBlob(data);

    expect(result.blob_id).toBeDefined();
    expect(result.blob_id[0]).toBe('B');

    // Download and decrypt
    const downloaded = await space.downloadAndDecryptBlob(result.blob_id);

    expect(bytesToString(downloaded)).toBe(content);
  });

  it('should handle binary blob data', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(3);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
      fetch: createMinioFixingFetch(),
    });

    // Create binary data with all byte values
    const binaryData = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      binaryData[i] = i;
    }

    // Upload
    const result = await space.uploadPlaintextBlob(binaryData);

    // Download
    const downloaded = await space.downloadPlaintextBlob(result.blob_id);

    expect(downloaded.length).toBe(256);
    for (let i = 0; i < 256; i++) {
      expect(downloaded[i]).toBe(i);
    }
  });

  it('should handle large blobs', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(4);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
      fetch: createMinioFixingFetch(),
    });

    // Create 1MB of random-ish data
    const size = 1024 * 1024;
    const largeData = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      largeData[i] = i % 256;
    }

    // Upload
    const result = await space.uploadPlaintextBlob(largeData);

    expect(result.size).toBe(size);

    // Download
    const downloaded = await space.downloadPlaintextBlob(result.blob_id);

    expect(downloaded.length).toBe(size);

    // Verify content
    for (let i = 0; i < size; i += 10000) {
      expect(downloaded[i]).toBe(i % 256);
    }
  });

  it('should delete a blob', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(5);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
      fetch: createMinioFixingFetch(),
    });

    const data = stringToBytes('Blob to delete');

    // Upload
    const result = await space.uploadPlaintextBlob(data);

    // Delete should not throw
    await expect(space.deleteBlob(result.blob_id)).resolves.not.toThrow();

    // Downloading deleted blob should fail
    await expect(space.downloadPlaintextBlob(result.blob_id)).rejects.toThrow();
  });

  it('should handle content-addressed deduplication', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(6);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
      fetch: createMinioFixingFetch(),
    });

    const data = stringToBytes('Same content uploaded twice');

    // Upload same content twice
    const result1 = await space.uploadPlaintextBlob(data);
    const result2 = await space.uploadPlaintextBlob(data);

    // Should get same blob ID (content-addressed)
    expect(result1.blob_id).toBe(result2.blob_id);
  });
});
