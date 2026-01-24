import { describe, it, expect } from 'vitest';
import {
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
} from '../crypto.js';
import { IdType } from '../types.js';

describe('Key Generation', () => {
  it('should generate a valid Ed25519 key pair', async () => {
    const keyPair = await generateKeyPair();

    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.privateKey.length).toBe(32);
    expect(keyPair.publicKey.length).toBe(32);
  });

  it('should generate unique key pairs', async () => {
    const keyPair1 = await generateKeyPair();
    const keyPair2 = await generateKeyPair();

    expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
    expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
  });
});

describe('Signing and Verification', () => {
  it('should sign and verify data', async () => {
    const keyPair = await generateKeyPair();
    const message = stringToBytes('Hello, World!');

    const signature = await signData(message, keyPair.privateKey);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);

    const isValid = await verifySignature(message, signature, keyPair.publicKey);
    expect(isValid).toBe(true);
  });

  it('should reject invalid signatures', async () => {
    const keyPair1 = await generateKeyPair();
    const keyPair2 = await generateKeyPair();
    const message = stringToBytes('Hello, World!');

    const signature = await signData(message, keyPair1.privateKey);

    // Verify with wrong public key
    const isValid = await verifySignature(message, signature, keyPair2.publicKey);
    expect(isValid).toBe(false);
  });

  it('should reject tampered messages', async () => {
    const keyPair = await generateKeyPair();
    const message = stringToBytes('Hello, World!');
    const tamperedMessage = stringToBytes('Hello, World?');

    const signature = await signData(message, keyPair.privateKey);

    const isValid = await verifySignature(tamperedMessage, signature, keyPair.publicKey);
    expect(isValid).toBe(false);
  });
});

describe('Hashing', () => {
  it('should compute SHA256 hash', () => {
    const data = stringToBytes('test data');
    const hash = computeHash(data);

    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
  });

  it('should produce consistent hashes', () => {
    const data = stringToBytes('test data');
    const hash1 = computeHash(data);
    const hash2 = computeHash(data);

    expect(hash1).toEqual(hash2);
  });

  it('should produce different hashes for different data', () => {
    const hash1 = computeHash(stringToBytes('data1'));
    const hash2 = computeHash(stringToBytes('data2'));

    expect(hash1).not.toEqual(hash2);
  });
});

describe('Key Derivation', () => {
  it('should derive a key using HKDF', () => {
    const rootKey = new Uint8Array(32).fill(1);
    const derivedKey = deriveKey(rootKey, 'test context');

    expect(derivedKey).toBeInstanceOf(Uint8Array);
    expect(derivedKey.length).toBe(32);
  });

  it('should derive different keys for different contexts', () => {
    const rootKey = new Uint8Array(32).fill(1);
    const key1 = deriveKey(rootKey, 'context1');
    const key2 = deriveKey(rootKey, 'context2');

    expect(key1).not.toEqual(key2);
  });

  it('should derive consistent keys', () => {
    const rootKey = new Uint8Array(32).fill(1);
    const key1 = deriveKey(rootKey, 'test context');
    const key2 = deriveKey(rootKey, 'test context');

    expect(key1).toEqual(key2);
  });

  it('should support custom key lengths', () => {
    const rootKey = new Uint8Array(32).fill(1);
    const key16 = deriveKey(rootKey, 'test', 16);
    const key64 = deriveKey(rootKey, 'test', 64);

    expect(key16.length).toBe(16);
    expect(key64.length).toBe(64);
  });
});

describe('AES-GCM Encryption', () => {
  it('should encrypt and decrypt data', () => {
    const key = new Uint8Array(32).fill(42);
    const plaintext = stringToBytes('Secret message');

    const encrypted = encryptAesGcm(plaintext, key);
    const decrypted = decryptAesGcm(encrypted, key);

    expect(bytesToString(decrypted)).toBe('Secret message');
  });

  it('should produce different ciphertext each time (random IV)', () => {
    const key = new Uint8Array(32).fill(42);
    const plaintext = stringToBytes('Secret message');

    const encrypted1 = encryptAesGcm(plaintext, key);
    const encrypted2 = encryptAesGcm(plaintext, key);

    // Different IVs mean different ciphertexts
    expect(encrypted1).not.toEqual(encrypted2);

    // But both decrypt to same plaintext
    expect(decryptAesGcm(encrypted1, key)).toEqual(decryptAesGcm(encrypted2, key));
  });

  it('should fail decryption with wrong key', () => {
    const key1 = new Uint8Array(32).fill(42);
    const key2 = new Uint8Array(32).fill(43);
    const plaintext = stringToBytes('Secret message');

    const encrypted = encryptAesGcm(plaintext, key1);

    expect(() => decryptAesGcm(encrypted, key2)).toThrow();
  });

  it('should support authenticated additional data (AAD)', () => {
    const key = new Uint8Array(32).fill(42);
    const plaintext = stringToBytes('Secret message');
    const aad = stringToBytes('additional data');

    const encrypted = encryptAesGcm(plaintext, key, aad);
    const decrypted = decryptAesGcm(encrypted, key, aad);

    expect(bytesToString(decrypted)).toBe('Secret message');
  });

  it('should fail decryption with wrong AAD', () => {
    const key = new Uint8Array(32).fill(42);
    const plaintext = stringToBytes('Secret message');
    const aad1 = stringToBytes('additional data 1');
    const aad2 = stringToBytes('additional data 2');

    const encrypted = encryptAesGcm(plaintext, key, aad1);

    expect(() => decryptAesGcm(encrypted, key, aad2)).toThrow();
  });

  it('should reject invalid key length', () => {
    const shortKey = new Uint8Array(16);
    const plaintext = stringToBytes('test');

    expect(() => encryptAesGcm(plaintext, shortKey)).toThrow(/32 bytes/);
  });

  it('should reject too-short ciphertext', () => {
    const key = new Uint8Array(32).fill(42);
    const tooShort = new Uint8Array(20);

    expect(() => decryptAesGcm(tooShort, key)).toThrow(/at least 28 bytes/);
  });
});

describe('Base64 Encoding', () => {
  it('should encode and decode standard base64', () => {
    const data = stringToBytes('Hello, World!');
    const encoded = encodeBase64(data);
    const decoded = decodeBase64(encoded);

    expect(bytesToString(decoded)).toBe('Hello, World!');
  });

  it('should encode and decode URL-safe base64', () => {
    const data = stringToBytes('Hello, World!');
    const encoded = encodeUrlSafeBase64(data);
    const decoded = decodeUrlSafeBase64(encoded);

    expect(bytesToString(decoded)).toBe('Hello, World!');
  });

  it('should not contain + or / in URL-safe base64', () => {
    // Create data that would produce + and / in standard base64
    const data = new Uint8Array([251, 239, 190]); // produces ++++ in base64
    const encoded = encodeUrlSafeBase64(data);

    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
  });
});

describe('Typed Identifiers', () => {
  describe('toUserId', () => {
    it('should create a 44-char identifier starting with U', async () => {
      const keyPair = await generateKeyPair();
      const userId = toUserId(keyPair.publicKey);

      expect(userId.length).toBe(44);
      expect(userId[0]).toBe('U');
    });

    it('should reject non-32-byte input', () => {
      expect(() => toUserId(new Uint8Array(31))).toThrow(/32 bytes/);
      expect(() => toUserId(new Uint8Array(33))).toThrow(/32 bytes/);
    });
  });

  describe('toToolId', () => {
    it('should create a 44-char identifier starting with T', async () => {
      const keyPair = await generateKeyPair();
      const toolId = toToolId(keyPair.publicKey);

      expect(toolId.length).toBe(44);
      expect(toolId[0]).toBe('T');
    });
  });

  describe('toSpaceId', () => {
    it('should create a 44-char identifier starting with C', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);

      expect(spaceId.length).toBe(44);
      expect(spaceId[0]).toBe('C');
    });
  });

  describe('toMessageId', () => {
    it('should create a 44-char identifier starting with M', () => {
      const hash = computeHash(stringToBytes('test'));
      const messageId = toMessageId(hash);

      expect(messageId.length).toBe(44);
      expect(messageId[0]).toBe('M');
    });
  });

  describe('toBlobId', () => {
    it('should create a 44-char identifier starting with B', () => {
      const hash = computeHash(stringToBytes('test'));
      const blobId = toBlobId(hash);

      expect(blobId.length).toBe(44);
      expect(blobId[0]).toBe('B');
    });
  });

  describe('getIdentifierType', () => {
    it('should correctly identify USER type', async () => {
      const keyPair = await generateKeyPair();
      const userId = toUserId(keyPair.publicKey);

      expect(getIdentifierType(userId)).toBe(IdType.USER);
    });

    it('should correctly identify TOOL type', async () => {
      const keyPair = await generateKeyPair();
      const toolId = toToolId(keyPair.publicKey);

      expect(getIdentifierType(toolId)).toBe(IdType.TOOL);
    });

    it('should correctly identify SPACE type', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);

      expect(getIdentifierType(spaceId)).toBe(IdType.SPACE);
    });

    it('should correctly identify MESSAGE type', () => {
      const hash = computeHash(stringToBytes('test'));
      const messageId = toMessageId(hash);

      expect(getIdentifierType(messageId)).toBe(IdType.MESSAGE);
    });

    it('should correctly identify BLOB type', () => {
      const hash = computeHash(stringToBytes('test'));
      const blobId = toBlobId(hash);

      expect(getIdentifierType(blobId)).toBe(IdType.BLOB);
    });

    it('should reject invalid length identifiers', () => {
      expect(() => getIdentifierType('short')).toThrow(/44 characters/);
    });
  });

  describe('extractFromTypedId', () => {
    it('should extract the original public key', async () => {
      const keyPair = await generateKeyPair();
      const userId = toUserId(keyPair.publicKey);
      const extracted = extractFromTypedId(userId);

      expect(extracted).toEqual(keyPair.publicKey);
    });

    it('should extract the original hash', () => {
      const hash = computeHash(stringToBytes('test'));
      const messageId = toMessageId(hash);
      const extracted = extractFromTypedId(messageId);

      expect(extracted).toEqual(hash);
    });
  });

  describe('extractPublicKey', () => {
    it('should extract public key from USER id', async () => {
      const keyPair = await generateKeyPair();
      const userId = toUserId(keyPair.publicKey);
      const extracted = extractPublicKey(userId);

      expect(extracted).toEqual(keyPair.publicKey);
    });

    it('should reject non-public-key types', () => {
      const hash = computeHash(stringToBytes('test'));
      const messageId = toMessageId(hash);

      expect(() => extractPublicKey(messageId)).toThrow(/not a public key type/);
    });
  });
});

describe('Utility Functions', () => {
  describe('concatBytes', () => {
    it('should concatenate multiple arrays', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([4, 5]);
      const c = new Uint8Array([6]);

      const result = concatBytes(a, b, c);

      expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
    });

    it('should handle empty arrays', () => {
      const a = new Uint8Array([1, 2]);
      const b = new Uint8Array([]);
      const c = new Uint8Array([3]);

      const result = concatBytes(a, b, c);

      expect(result).toEqual(new Uint8Array([1, 2, 3]));
    });
  });

  describe('stringToBytes / bytesToString', () => {
    it('should round-trip strings', () => {
      const original = 'Hello, 世界! 🌍';
      const bytes = stringToBytes(original);
      const result = bytesToString(bytes);

      expect(result).toBe(original);
    });
  });
});
