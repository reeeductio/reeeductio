/**
 * Cryptographic utilities for reeeductio.
 *
 * Provides Ed25519 signing/verification, AES-GCM encryption, hashing, and encoding helpers.
 */

import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { IdType, type KeyPair } from './types.js';

/**
 * Generate a new Ed25519 key pair.
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const privateKey = randomBytes(32);
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

/**
 * Sign data using Ed25519.
 *
 * @param data - Data to sign
 * @param privateKey - 32-byte Ed25519 private key
 * @returns 64-byte signature
 */
export async function signData(data: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  return ed.signAsync(data, privateKey);
}

/**
 * Verify Ed25519 signature.
 *
 * @param data - Data that was signed
 * @param signature - 64-byte signature
 * @param publicKey - 32-byte Ed25519 public key
 * @returns True if signature is valid
 */
export async function verifySignature(
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    return await ed.verifyAsync(signature, data, publicKey);
  } catch {
    return false;
  }
}

/**
 * Compute SHA256 hash of data.
 *
 * @param data - Data to hash
 * @returns 32-byte SHA256 hash
 */
export function computeHash(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * Derive a key using HKDF-SHA256.
 *
 * @param rootKey - Root key material (typically 32 bytes)
 * @param info - Context/purpose string for key derivation
 * @param length - Desired output key length in bytes (default: 32)
 * @returns Derived key of specified length
 */
export function deriveKey(rootKey: Uint8Array, info: string, length: number = 32): Uint8Array {
  const infoBytes = new TextEncoder().encode(info);
  return hkdf(sha256, rootKey, undefined, infoBytes, length);
}

/**
 * Encrypt data using AES-GCM-256.
 *
 * The output format is: IV (12 bytes) + ciphertext + tag (16 bytes)
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte AES-256 key
 * @param associatedData - Optional additional authenticated data (AAD)
 * @returns Encrypted data with IV + ciphertext + tag concatenated
 */
export function encryptAesGcm(
  plaintext: Uint8Array,
  key: Uint8Array,
  associatedData?: Uint8Array
): Uint8Array {
  if (key.length !== 32) {
    throw new Error(`AES-256 key must be exactly 32 bytes, got ${key.length}`);
  }

  // Generate random 12-byte IV (recommended for GCM)
  const iv = randomBytes(12);

  // Create cipher and encrypt
  const cipher = gcm(key, iv, associatedData);
  const ciphertextWithTag = cipher.encrypt(plaintext);

  // Return IV + ciphertext + tag
  const result = new Uint8Array(iv.length + ciphertextWithTag.length);
  result.set(iv, 0);
  result.set(ciphertextWithTag, iv.length);
  return result;
}

/**
 * Decrypt AES-GCM-256 encrypted data.
 *
 * Expects input format: IV (12 bytes) + ciphertext + tag (16 bytes)
 *
 * @param encrypted - Encrypted data (IV + ciphertext + tag)
 * @param key - 32-byte AES-256 key
 * @param associatedData - Optional additional authenticated data (AAD)
 * @returns Decrypted plaintext
 */
export function decryptAesGcm(
  encrypted: Uint8Array,
  key: Uint8Array,
  associatedData?: Uint8Array
): Uint8Array {
  if (key.length !== 32) {
    throw new Error(`AES-256 key must be exactly 32 bytes, got ${key.length}`);
  }

  // Minimum size is 12 (IV) + 16 (tag) = 28 bytes
  if (encrypted.length < 28) {
    throw new Error(`Encrypted data too short, must be at least 28 bytes, got ${encrypted.length}`);
  }

  // Extract IV (first 12 bytes)
  const iv = encrypted.slice(0, 12);

  // Rest is ciphertext + tag
  const ciphertextWithTag = encrypted.slice(12);

  // Decrypt and verify
  const cipher = gcm(key, iv, associatedData);
  return cipher.decrypt(ciphertextWithTag);
}

/**
 * Encode bytes as standard base64 string.
 */
export function encodeBase64(data: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(data).toString('base64');
  }
  // Browser environment
  return btoa(String.fromCharCode(...data));
}

/**
 * Decode base64 string to bytes.
 */
export function decodeBase64(data: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(data, 'base64'));
  }
  // Browser environment
  return new Uint8Array(atob(data).split('').map((c) => c.charCodeAt(0)));
}

/**
 * Encode bytes as URL-safe base64 string (with padding).
 */
export function encodeUrlSafeBase64(data: Uint8Array): string {
  const base64 = encodeBase64(data);
  return base64.replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Decode URL-safe base64 string to bytes.
 */
export function decodeUrlSafeBase64(data: string): Uint8Array {
  // Convert URL-safe to standard base64
  let base64 = data.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const padding = 4 - (base64.length % 4);
  if (padding !== 4) {
    base64 += '='.repeat(padding);
  }
  return decodeBase64(base64);
}

/**
 * Convert public key to user identifier format (44-char URL-safe base64).
 *
 * Creates header byte with USER type (0b010100) in first 6 bits and version 0 in last 2 bits.
 * The header value 0x50 (0b01010000) encodes to 'U' as the first base64 character.
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @returns 44-character URL-safe base64 string starting with 'U'
 */
export function toUserId(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`Public key must be exactly 32 bytes, got ${publicKey.length}`);
  }
  // Header: [6 bits: USER type (20 = 0b010100)][2 bits: version (0)]
  const header = (IdType.USER << 2) | 0; // = 0x50
  const typed = new Uint8Array(33);
  typed[0] = header;
  typed.set(publicKey, 1);
  return encodeUrlSafeBase64(typed);
}

/**
 * Convert public key to tool identifier format (44-char URL-safe base64).
 *
 * Creates header byte with TOOL type (0b010011) in first 6 bits and version 0 in last 2 bits.
 * The header value 0x4C (0b01001100) encodes to 'T' as the first base64 character.
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @returns 44-character URL-safe base64 string starting with 'T'
 */
export function toToolId(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`Public key must be exactly 32 bytes, got ${publicKey.length}`);
  }
  // Header: [6 bits: TOOL type (19 = 0b010011)][2 bits: version (0)]
  const header = (IdType.TOOL << 2) | 0; // = 0x4C
  const typed = new Uint8Array(33);
  typed[0] = header;
  typed.set(publicKey, 1);
  return encodeUrlSafeBase64(typed);
}

/**
 * Convert public key to space identifier format (44-char URL-safe base64).
 *
 * Creates header byte with SPACE type (0b000010) in first 6 bits and version 0 in last 2 bits.
 * The header value 0x08 (0b00001000) encodes to 'C' as the first base64 character.
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @returns 44-character URL-safe base64 string starting with 'C'
 */
export function toSpaceId(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`Public key must be exactly 32 bytes, got ${publicKey.length}`);
  }
  // Header: [6 bits: SPACE type (2 = 0b000010)][2 bits: version (0)]
  const header = (IdType.SPACE << 2) | 0; // = 0x08
  const typed = new Uint8Array(33);
  typed[0] = header;
  typed.set(publicKey, 1);
  return encodeUrlSafeBase64(typed);
}

/**
 * Convert hash to message identifier format (44-char URL-safe base64).
 *
 * Creates header byte with MESSAGE type (0b001100) in first 6 bits and version 0 in last 2 bits.
 * The header value 0x30 (0b00110000) encodes to 'M' as the first base64 character.
 *
 * @param hashBytes - 32-byte SHA256 hash
 * @returns 44-character URL-safe base64 string starting with 'M'
 */
export function toMessageId(hashBytes: Uint8Array): string {
  if (hashBytes.length !== 32) {
    throw new Error(`Hash must be exactly 32 bytes, got ${hashBytes.length}`);
  }
  // Header: [6 bits: MESSAGE type (12 = 0b001100)][2 bits: version (0)]
  const header = (IdType.MESSAGE << 2) | 0; // = 0x30
  const typed = new Uint8Array(33);
  typed[0] = header;
  typed.set(hashBytes, 1);
  return encodeUrlSafeBase64(typed);
}

/**
 * Convert hash to blob identifier format (44-char URL-safe base64).
 *
 * Creates header byte with BLOB type (0b000001) in first 6 bits and version 0 in last 2 bits.
 * The header value 0x04 (0b00000100) encodes to 'B' as the first base64 character.
 *
 * @param hashBytes - 32-byte SHA256 hash
 * @returns 44-character URL-safe base64 string starting with 'B'
 */
export function toBlobId(hashBytes: Uint8Array): string {
  if (hashBytes.length !== 32) {
    throw new Error(`Hash must be exactly 32 bytes, got ${hashBytes.length}`);
  }
  // Header: [6 bits: BLOB type (1 = 0b000001)][2 bits: version (0)]
  const header = (IdType.BLOB << 2) | 0; // = 0x04
  const typed = new Uint8Array(33);
  typed[0] = header;
  typed.set(hashBytes, 1);
  return encodeUrlSafeBase64(typed);
}

/**
 * Get the type of a typed identifier.
 *
 * @param typedId - 44-character URL-safe base64 string with typed header
 * @returns The identifier type
 */
export function getIdentifierType(typedId: string): IdType {
  if (typedId.length !== 44) {
    throw new Error(`Typed identifier must be 44 characters, got ${typedId.length}`);
  }

  const decoded = decodeUrlSafeBase64(typedId);
  if (decoded.length !== 33) {
    throw new Error(`Decoded identifier must be 33 bytes, got ${decoded.length}`);
  }

  const header = decoded[0];
  const typeBits = (header >> 2) & 0b111111;

  const validTypes = [IdType.USER, IdType.TOOL, IdType.SPACE, IdType.MESSAGE, IdType.BLOB];
  if (!validTypes.includes(typeBits)) {
    throw new Error(`Unknown identifier type: ${typeBits.toString(2).padStart(6, '0')}`);
  }

  return typeBits as IdType;
}

/**
 * Extract raw bytes (public key or hash) from typed identifier.
 *
 * @param typedId - 44-character URL-safe base64 string with typed header
 * @returns 32-byte raw data (public key or hash)
 */
export function extractFromTypedId(typedId: string): Uint8Array {
  if (typedId.length !== 44) {
    throw new Error(`Typed identifier must be 44 characters, got ${typedId.length}`);
  }

  const decoded = decodeUrlSafeBase64(typedId);
  if (decoded.length !== 33) {
    throw new Error(`Decoded identifier must be 33 bytes, got ${decoded.length}`);
  }

  // Return the 32-byte data (skip header)
  return decoded.slice(1);
}

/**
 * Extract public key from a USER, TOOL, or SPACE identifier.
 *
 * @param typedId - 44-character URL-safe base64 identifier
 * @returns 32-byte Ed25519 public key
 */
export function extractPublicKey(typedId: string): Uint8Array {
  const idType = getIdentifierType(typedId);
  const validPublicKeyTypes = [IdType.USER, IdType.TOOL, IdType.SPACE];

  if (!validPublicKeyTypes.includes(idType)) {
    throw new Error(`Identifier is not a public key type (USER, TOOL, or SPACE)`);
  }

  return extractFromTypedId(typedId);
}

/**
 * Concatenate multiple Uint8Arrays.
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Convert a string to UTF-8 bytes.
 */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Convert UTF-8 bytes to a string.
 */
export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
