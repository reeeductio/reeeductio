/**
 * E2E tests for messages.
 *
 * Run with: npm run test:e2e
 * Requires: docker-compose -f backend/docker-compose.e2e.yml up -d
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { Space } from '../../client.js';
import { generateKeyPair, toSpaceId, stringToBytes, bytesToString } from '../../crypto.js';
import { validateMessageChain } from '../../messages.js';
import { E2E_BACKEND_URL, waitForBackend, randomTopicId } from './setup.js';

describe('E2E: Messages', () => {
  beforeAll(async () => {
    await waitForBackend();
  }, 60000);

  it('should post and retrieve a message', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(1);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const topicId = randomTopicId();
    const messageData = stringToBytes('Hello from TypeScript SDK e2e test!');

    // Post message
    const result = await space.postMessage(topicId, 'chat.text', messageData, null);

    expect(result.message_hash).toBeDefined();
    expect(result.message_hash[0]).toBe('M');
    expect(result.server_timestamp).toBeDefined();

    // Retrieve messages
    const { messages } = await space.getMessages(topicId);

    expect(messages.length).toBeGreaterThanOrEqual(1);

    // Find our message
    const ourMessage = messages.find(m => m.message_hash === result.message_hash);
    expect(ourMessage).toBeDefined();
    expect(ourMessage!.sender).toBe(space.getUserId());
    expect(ourMessage!.type).toBe('chat.text');
  });

  it('should build a valid message chain', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(2);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const topicId = randomTopicId();

    // Post first message
    const msg1 = await space.postMessage(
      topicId,
      'chat.text',
      stringToBytes('First message'),
      null
    );

    // Post second message (should auto-fetch prev_hash)
    const msg2 = await space.postMessage(
      topicId,
      'chat.text',
      stringToBytes('Second message')
    );

    // Post third message
    const msg3 = await space.postMessage(
      topicId,
      'chat.text',
      stringToBytes('Third message')
    );

    // Retrieve and validate chain
    const { messages } = await space.getMessages(topicId);

    expect(messages.length).toBe(3);
    expect(validateMessageChain(spaceId, messages)).toBe(true);

    // Verify ordering
    expect(messages[0].message_hash).toBe(msg1.message_hash);
    expect(messages[1].message_hash).toBe(msg2.message_hash);
    expect(messages[2].message_hash).toBe(msg3.message_hash);

    // Verify chain links
    expect(messages[0].prev_hash).toBeNull();
    expect(messages[1].prev_hash).toBe(msg1.message_hash);
    expect(messages[2].prev_hash).toBe(msg2.message_hash);
  });

  it('should post and retrieve encrypted messages', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(3);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const topicId = randomTopicId();
    const plaintext = 'Secret message from TypeScript SDK!';
    const plaintextBytes = stringToBytes(plaintext);

    // Post encrypted message
    const result = await space.postEncryptedMessage(
      topicId,
      'chat.encrypted',
      plaintextBytes,
      null
    );

    expect(result.message_hash).toBeDefined();

    // Retrieve messages
    const { messages } = await space.getMessages(topicId);
    expect(messages.length).toBe(1);

    // The stored data should be encrypted (different from plaintext)
    const storedMessage = messages[0];
    expect(storedMessage.data).not.toBe(plaintext);
  });

  it('should get a specific message by hash', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(4);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const topicId = randomTopicId();
    const messageData = stringToBytes('Get me by hash!');

    // Post message
    const result = await space.postMessage(topicId, 'test', messageData, null);

    // Get specific message
    const message = await space.getMessage(topicId, result.message_hash);

    expect(message.message_hash).toBe(result.message_hash);
    expect(message.sender).toBe(space.getUserId());
  });

  it('should return empty array for topic with no messages', async () => {
    const keyPair = await generateKeyPair();
    const spaceId = toSpaceId(keyPair.publicKey);
    const symmetricRoot = new Uint8Array(32).fill(5);

    const space = new Space({
      spaceId,
      keyPair,
      symmetricRoot,
      baseUrl: E2E_BACKEND_URL,
    });

    const topicId = randomTopicId();

    // Get messages from empty topic
    const { messages, has_more } = await space.getMessages(topicId);

    expect(messages).toEqual([]);
    expect(has_more).toBe(false);
  });
});
