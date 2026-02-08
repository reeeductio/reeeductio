import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  computeMessageHash,
  postMessage,
  getMessages,
  getMessage,
  validateMessageChain,
} from '../messages.js';
import {
  generateKeyPair,
  toUserId,
  toSpaceId,
  stringToBytes,
  encodeBase64,
  encodeUrlSafeBase64,
} from '../crypto.js';

describe('computeMessageHash', () => {
  it('should compute hash over space_id|topic_id|prev_hash|data|sender', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);
    const topicId = 'test-topic';
    const dataBase64 = encodeBase64(stringToBytes('Hello, World!'));
    const prevHash = null;

    const hash = computeMessageHash(spaceId, topicId, 'text', prevHash, dataBase64, senderId);

    // Returns a typed message ID string (44 chars starting with 'M')
    expect(typeof hash).toBe('string');
    expect(hash.length).toBe(44);
    expect(hash[0]).toBe('M');
  });

  it('should produce consistent hashes', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);
    const topicId = 'test-topic';
    const dataBase64 = encodeBase64(stringToBytes('Hello, World!'));
    const prevHash = null;

    const hash1 = computeMessageHash(spaceId, topicId, 'text', prevHash, dataBase64, senderId);
    const hash2 = computeMessageHash(spaceId, topicId, 'text', prevHash, dataBase64, senderId);

    expect(hash1).toBe(hash2);
  });

  it('should include prev_hash in computation when provided', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);
    const topicId = 'test-topic';
    const dataBase64 = encodeBase64(stringToBytes('Hello, World!'));

    // Use a fake prev_hash that looks valid
    const prevHash = 'M' + 'a'.repeat(43);

    const hashWithPrev = computeMessageHash(spaceId, topicId, 'text', prevHash, dataBase64, senderId);
    const hashWithoutPrev = computeMessageHash(spaceId, topicId, 'text', null, dataBase64, senderId);

    expect(hashWithPrev).not.toBe(hashWithoutPrev);
  });

  it('should produce different hashes for different topics', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);
    const dataBase64 = encodeBase64(stringToBytes('Hello'));

    const hash1 = computeMessageHash(spaceId, 'topic1', 'text', null, dataBase64, senderId);
    const hash2 = computeMessageHash(spaceId, 'topic2', 'text', null, dataBase64, senderId);

    expect(hash1).not.toBe(hash2);
  });

  it('should produce different hashes for different spaces', async () => {
    const keyPair1 = await generateKeyPair();
    const keyPair2 = await generateKeyPair();
    const spaceId1 = toSpaceId(keyPair1.publicKey);
    const spaceId2 = toSpaceId(keyPair2.publicKey);
    const senderId = toUserId(keyPair1.publicKey);
    const dataBase64 = encodeBase64(stringToBytes('Hello'));

    const hash1 = computeMessageHash(spaceId1, 'topic', 'text', null, dataBase64, senderId);
    const hash2 = computeMessageHash(spaceId2, 'topic', 'text', null, dataBase64, senderId);

    expect(hash1).not.toBe(hash2);
  });
});

describe('postMessage', () => {
  let mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  it('should post a message with correct payload', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);
    const topicId = 'chat';
    const messageType = 'text';
    const data = stringToBytes('Hello!');

    const mockResponse = {
      message_hash: 'M' + 'x'.repeat(43),
      server_timestamp: Date.now(),
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => mockResponse,
    });

    const result = await postMessage(
      mockFetch,
      'https://api.example.com',
      'mock-token',
      spaceId,
      topicId,
      messageType,
      data,
      null,
      senderId,
      keyPair.privateKey
    );

    expect(result.message_hash).toBe(mockResponse.message_hash);
    expect(result.server_timestamp).toBe(mockResponse.server_timestamp);

    // Verify the request
    expect(mockFetch).toHaveBeenCalledWith(
      `https://api.example.com/spaces/${spaceId}/topics/${topicId}/messages`,
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Authorization': 'Bearer mock-token',
          'Content-Type': 'application/json',
        }),
      })
    );

    // Verify payload structure
    const callArgs = mockFetch.mock.calls[0];
    const body = JSON.parse(callArgs[1].body);

    expect(body.type).toBe(messageType);
    expect(body.prev_hash).toBeNull();
    expect(body.message_hash).toBeDefined();
    expect(body.signature).toBeDefined();
  });

  it('should include prev_hash when provided', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);
    const prevHash = 'M' + 'a'.repeat(43);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => ({
        message_hash: 'M' + 'x'.repeat(43),
        server_timestamp: Date.now(),
      }),
    });

    await postMessage(
      mockFetch,
      'https://api.example.com',
      'mock-token',
      spaceId,
      'chat',
      'text',
      stringToBytes('Hello!'),
      prevHash,
      senderId,
      keyPair.privateKey
    );

    const callArgs = mockFetch.mock.calls[0];
    const body = JSON.parse(callArgs[1].body);

    expect(body.prev_hash).toBe(prevHash);
  });
});

describe('getMessages', () => {
  let mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  it('should fetch messages from a topic', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);

    const mockMessages = {
      messages: [
        {
          message_hash: 'M' + 'a'.repeat(43),
          topic_id: 'chat',
          type: 'text',
          prev_hash: null,
          data: encodeUrlSafeBase64(stringToBytes('Hello')),
          sender: senderId,
          signature: 'sig1',
          server_timestamp: Date.now(),
        },
      ],
      has_more: false,
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockMessages,
    });

    const result = await getMessages(
      mockFetch,
      'https://api.example.com',
      'mock-token',
      spaceId,
      'chat'
    );

    expect(result.messages).toHaveLength(1);
    expect(result.has_more).toBe(false);
    expect(mockFetch).toHaveBeenCalledWith(
      `https://api.example.com/spaces/${spaceId}/topics/chat/messages`,
      expect.objectContaining({
        method: 'GET',
        headers: { 'Authorization': 'Bearer mock-token' },
      })
    );
  });

  it('should include query parameters when provided', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ messages: [], has_more: false }),
    });

    await getMessages(
      mockFetch,
      'https://api.example.com',
      'mock-token',
      spaceId,
      'chat',
      { from: 10, to: 20, limit: 50 }
    );

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('from=10'),
      expect.any(Object)
    );
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('to=20'),
      expect.any(Object)
    );
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('limit=50'),
      expect.any(Object)
    );
  });
});

describe('getMessage', () => {
  let mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  it('should fetch a single message by hash', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);
    const messageHash = 'M' + 'a'.repeat(43);

    const mockMessage = {
      message_hash: messageHash,
      topic_id: 'chat',
      type: 'text',
      prev_hash: null,
      data: encodeUrlSafeBase64(stringToBytes('Hello')),
      sender: senderId,
      signature: 'sig1',
      server_timestamp: Date.now(),
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockMessage,
    });

    const result = await getMessage(
      mockFetch,
      'https://api.example.com',
      'mock-token',
      spaceId,
      'chat',
      messageHash
    );

    expect(result.message_hash).toBe(messageHash);
    expect(mockFetch).toHaveBeenCalledWith(
      `https://api.example.com/spaces/${spaceId}/topics/chat/messages/${messageHash}`,
      expect.objectContaining({
        method: 'GET',
      })
    );
  });
});

describe('validateMessageChain', () => {
  it('should validate a correct message chain', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);

    // Create a chain of messages
    const data1Base64 = encodeBase64(stringToBytes('First'));
    const messageId1 = computeMessageHash(spaceId, 'chat', 'text', null, data1Base64, senderId);

    const data2Base64 = encodeBase64(stringToBytes('Second'));
    const messageId2 = computeMessageHash(spaceId, 'chat', 'text', messageId1, data2Base64, senderId);

    const messages = [
      {
        message_hash: messageId1,
        topic_id: 'chat',
        type: 'text',
        prev_hash: null,
        data: data1Base64,
        sender: senderId,
        signature: 'sig1',
        server_timestamp: Date.now(),
      },
      {
        message_hash: messageId2,
        topic_id: 'chat',
        type: 'text',
        prev_hash: messageId1,
        data: data2Base64,
        sender: senderId,
        signature: 'sig2',
        server_timestamp: Date.now(),
      },
    ];

    const isValid = validateMessageChain(spaceId, messages);
    expect(isValid).toBe(true);
  });

  it('should reject a chain with incorrect hash', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);

    const data1Base64 = encodeBase64(stringToBytes('First'));
    const fakeMessageId = 'M' + 'x'.repeat(43); // Wrong hash

    const messages = [
      {
        message_hash: fakeMessageId, // This doesn't match computed hash
        topic_id: 'chat',
        type: 'text',
        prev_hash: null,
        data: data1Base64,
        sender: senderId,
        signature: 'sig1',
        server_timestamp: Date.now(),
      },
    ];

    const isValid = validateMessageChain(spaceId, messages);
    expect(isValid).toBe(false);
  });

  it('should reject a chain with broken prev_hash link', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);

    const data1Base64 = encodeBase64(stringToBytes('First'));
    const messageId1 = computeMessageHash(spaceId, 'chat', 'text', null, data1Base64, senderId);

    const data2Base64 = encodeBase64(stringToBytes('Second'));
    const wrongPrevHash = 'M' + 'y'.repeat(43); // Wrong prev_hash
    const messageId2 = computeMessageHash(spaceId, 'chat', 'text', wrongPrevHash, data2Base64, senderId);

    const messages = [
      {
        message_hash: messageId1,
        topic_id: 'chat',
        type: 'text',
        prev_hash: null,
        data: data1Base64,
        sender: senderId,
        signature: 'sig1',
        server_timestamp: Date.now(),
      },
      {
        message_hash: messageId2,
        topic_id: 'chat',
        type: 'text',
        prev_hash: wrongPrevHash, // Doesn't point to previous message
        data: data2Base64,
        sender: senderId,
        signature: 'sig2',
        server_timestamp: Date.now(),
      },
    ];

    const isValid = validateMessageChain(spaceId, messages);
    expect(isValid).toBe(false);
  });

  it('should validate an empty chain', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const isValid = validateMessageChain(spaceId, []);
    expect(isValid).toBe(true);
  });

  it('should validate a single message chain', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const senderId = toUserId(keyPair.publicKey);

    const dataBase64 = encodeBase64(stringToBytes('Only message'));
    const messageId = computeMessageHash(spaceId, 'chat', 'text', null, dataBase64, senderId);

    const messages = [
      {
        message_hash: messageId,
        topic_id: 'chat',
        type: 'text',
        prev_hash: null,
        data: dataBase64,
        sender: senderId,
        signature: 'sig1',
        server_timestamp: Date.now(),
      },
    ];

    const isValid = validateMessageChain(spaceId, messages);
    expect(isValid).toBe(true);
  });
});
