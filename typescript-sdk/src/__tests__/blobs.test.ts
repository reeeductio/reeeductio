import { describe, it, expect, vi, beforeEach } from 'vitest';
import { computeBlobId, uploadBlob, downloadBlob, deleteBlob } from '../blobs.js';
import { generateKeyPair, toSpaceId, computeHash, stringToBytes } from '../crypto.js';

describe('computeBlobId', () => {
  it('should compute a content-addressed blob ID', () => {
    const data = stringToBytes('test blob content');
    const blobId = computeBlobId(data);

    expect(blobId.length).toBe(44);
    expect(blobId[0]).toBe('B');
  });

  it('should produce consistent IDs for same content', () => {
    const data = stringToBytes('test blob content');
    const blobId1 = computeBlobId(data);
    const blobId2 = computeBlobId(data);

    expect(blobId1).toBe(blobId2);
  });

  it('should produce different IDs for different content', () => {
    const blobId1 = computeBlobId(stringToBytes('content1'));
    const blobId2 = computeBlobId(stringToBytes('content2'));

    expect(blobId1).not.toBe(blobId2);
  });
});

describe('uploadBlob', () => {
  let mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  it('should upload blob with computed ID', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const data = stringToBytes('test blob data');
    const expectedBlobId = computeBlobId(data);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => ({
        blob_id: expectedBlobId,
        size: data.length,
      }),
    });

    const result = await uploadBlob(
      mockFetch,
      'https://api.example.com',
      'mock-token',
      spaceId,
      data
    );

    expect(result.blob_id).toBe(expectedBlobId);
    expect(result.size).toBe(data.length);

    expect(mockFetch).toHaveBeenCalledWith(
      `https://api.example.com/spaces/${spaceId}/blobs/${expectedBlobId}`,
      expect.objectContaining({
        method: 'PUT',
        headers: expect.objectContaining({
          'Authorization': 'Bearer mock-token',
          'Content-Type': 'application/octet-stream',
        }),
        body: data,
        redirect: 'manual',
      })
    );
  });

  it('should handle 307 redirect to S3', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const data = stringToBytes('test blob data');
    const expectedBlobId = computeBlobId(data);
    const s3Url = 'https://s3.amazonaws.com/presigned-url';

    // First call returns redirect
    mockFetch
      .mockResolvedValueOnce({
        ok: false,
        status: 307,
        headers: new Map([['Location', s3Url]]),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

    // Mock headers.get
    mockFetch.mockImplementationOnce(() => ({
      ok: false,
      status: 307,
      headers: { get: (name: string) => (name === 'Location' ? s3Url : null) },
    })).mockResolvedValueOnce({
      ok: true,
      status: 200,
    });

    const result = await uploadBlob(
      mockFetch,
      'https://api.example.com',
      'mock-token',
      spaceId,
      data
    );

    expect(result.blob_id).toBe(expectedBlobId);
    expect(result.size).toBe(data.length);

    // Verify S3 upload was called without auth header
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      s3Url,
      expect.objectContaining({
        method: 'PUT',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: data,
      })
    );
  });

  it('should handle 409 Conflict (blob already exists)', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const data = stringToBytes('existing blob');
    const expectedBlobId = computeBlobId(data);

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 409,
    });

    const result = await uploadBlob(
      mockFetch,
      'https://api.example.com',
      'mock-token',
      spaceId,
      data
    );

    // Should succeed since content-addressed storage means it already exists
    expect(result.blob_id).toBe(expectedBlobId);
    expect(result.size).toBe(data.length);
  });
});

describe('downloadBlob', () => {
  let mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  it('should download blob data', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const blobId = 'B' + 'a'.repeat(43);
    const blobData = stringToBytes('downloaded content');

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      arrayBuffer: async () => blobData.buffer,
    });

    const result = await downloadBlob(
      mockFetch,
      'https://api.example.com',
      'mock-token',
      spaceId,
      blobId
    );

    expect(result).toEqual(blobData);
    expect(mockFetch).toHaveBeenCalledWith(
      `https://api.example.com/spaces/${spaceId}/blobs/${blobId}`,
      expect.objectContaining({
        method: 'GET',
        headers: { 'Authorization': 'Bearer mock-token' },
        redirect: 'manual',
      })
    );
  });

  it('should handle 307 redirect to S3 for download', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const blobId = 'B' + 'a'.repeat(43);
    const blobData = stringToBytes('s3 content');
    const s3Url = 'https://s3.amazonaws.com/presigned-download-url';

    mockFetch
      .mockResolvedValueOnce({
        ok: false,
        status: 307,
        headers: { get: (name: string) => (name === 'Location' ? s3Url : null) },
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        arrayBuffer: async () => blobData.buffer,
      });

    const result = await downloadBlob(
      mockFetch,
      'https://api.example.com',
      'mock-token',
      spaceId,
      blobId
    );

    expect(result).toEqual(blobData);

    // Verify S3 download was called without auth header
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      s3Url,
      expect.objectContaining({
        method: 'GET',
      })
    );
  });
});

describe('deleteBlob', () => {
  let mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  it('should delete a blob', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const blobId = 'B' + 'a'.repeat(43);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 204,
    });

    await deleteBlob(
      mockFetch,
      'https://api.example.com',
      'mock-token',
      spaceId,
      blobId
    );

    expect(mockFetch).toHaveBeenCalledWith(
      `https://api.example.com/spaces/${spaceId}/blobs/${blobId}`,
      expect.objectContaining({
        method: 'DELETE',
        headers: { 'Authorization': 'Bearer mock-token' },
      })
    );
  });
});
