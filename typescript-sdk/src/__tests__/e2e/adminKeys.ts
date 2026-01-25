/**
 * E2E test admin keypair constants.
 *
 * These values must match the admin configuration in backend/config.e2e.yaml.
 *
 * The private key is a deterministic test key (32 bytes of 0x01).
 * DO NOT use this key in production!
 */
import * as ed from '@noble/ed25519';
import { toSpaceId, toUserId, encodeBase64 } from '../../crypto.js';

/**
 * Deterministic admin private key for e2e tests.
 * 32 bytes of 0x01 - DO NOT use in production!
 */
export const ADMIN_PRIVATE_KEY = new Uint8Array(32).fill(0x01);

/**
 * Admin public key derived from the private key.
 * This is computed lazily since ed25519 operations are async.
 */
let _adminPublicKey: Uint8Array | null = null;
let _adminSpaceId: string | null = null;
let _adminUserId: string | null = null;

/**
 * Get the admin public key.
 */
export async function getAdminPublicKey(): Promise<Uint8Array> {
  if (!_adminPublicKey) {
    _adminPublicKey = await ed.getPublicKeyAsync(ADMIN_PRIVATE_KEY);
  }
  return _adminPublicKey;
}

/**
 * Get the admin space ID.
 */
export async function getAdminSpaceId(): Promise<string> {
  if (!_adminSpaceId) {
    const publicKey = await getAdminPublicKey();
    _adminSpaceId = toSpaceId(publicKey);
  }
  return _adminSpaceId;
}

/**
 * Get the admin user ID.
 */
export async function getAdminUserId(): Promise<string> {
  if (!_adminUserId) {
    const publicKey = await getAdminPublicKey();
    _adminUserId = toUserId(publicKey);
  }
  return _adminUserId;
}

/**
 * Get the admin keypair.
 */
export async function getAdminKeyPair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
  const publicKey = await getAdminPublicKey();
  return {
    privateKey: ADMIN_PRIVATE_KEY,
    publicKey,
  };
}

/**
 * Print admin credentials for config.e2e.yaml.
 * Run with: npx tsx src/__tests__/e2e/adminKeys.ts
 */
async function main(): Promise<void> {
  const publicKey = await getAdminPublicKey();
  const spaceId = await getAdminSpaceId();
  const userId = await getAdminUserId();
  const privateKeyB64 = encodeBase64(ADMIN_PRIVATE_KEY);

  console.log('Admin credentials for config.e2e.yaml:');
  console.log('');
  console.log('admin:');
  console.log(`  space_id: "${spaceId}"`);
  console.log(`  user_id: "${userId}"`);
  console.log(`  private_key: "${privateKeyB64}"`);
  console.log('');
  console.log('Raw values:');
  console.log(`  Public key (hex): ${Buffer.from(publicKey).toString('hex')}`);
  console.log(`  Private key (base64): ${privateKeyB64}`);
}

// Run if executed directly
if (typeof require !== 'undefined' && require.main === module) {
  main().catch(console.error);
}

// Also support ESM direct execution
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  main().catch(console.error);
}
