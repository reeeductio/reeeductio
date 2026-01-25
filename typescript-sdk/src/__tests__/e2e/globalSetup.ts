/**
 * Global setup for e2e tests.
 *
 * Starts docker-compose services before tests and stops them after.
 * Also verifies admin API is working.
 */
import { execSync } from 'child_process';
import path from 'path';
import { AdminClient } from '../../client.js';
import { getAdminKeyPair, getAdminSpaceId } from './adminKeys.js';

const DOCKER_COMPOSE_FILE = path.resolve(__dirname, '../../../../backend/docker-compose.e2e.yml');
const BACKEND_URL = process.env.E2E_BACKEND_URL || 'http://localhost:8000';
const MAX_WAIT_MS = 120000; // 2 minutes to start all services
const POLL_INTERVAL_MS = 2000;

/**
 * Check if the backend is healthy.
 */
async function isBackendHealthy(): Promise<boolean> {
  try {
    const response = await fetch(`${BACKEND_URL}/health`);
    if (response.ok) {
      const data = await response.json() as { status?: string };
      return data.status === 'healthy';
    }
  } catch {
    // Connection failed
  }
  return false;
}

/**
 * Wait for the backend to become healthy.
 */
async function waitForBackend(): Promise<void> {
  const startTime = Date.now();

  while (Date.now() - startTime < MAX_WAIT_MS) {
    if (await isBackendHealthy()) {
      console.log('✓ Backend is healthy');
      return;
    }
    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  throw new Error(`Backend did not become healthy within ${MAX_WAIT_MS / 1000}s`);
}

/**
 * Start docker-compose services.
 */
function startServices(): void {
  console.log('Starting docker-compose services...');
  console.log(`Using: ${DOCKER_COMPOSE_FILE}`);

  try {
    // Build and start in detached mode
    execSync(
      `docker-compose -f "${DOCKER_COMPOSE_FILE}" up -d --build`,
      {
        encoding: 'utf-8',
        stdio: 'inherit',
        cwd: path.dirname(DOCKER_COMPOSE_FILE),
      }
    );
  } catch (error) {
    console.error('Failed to start docker-compose services:', error);
    throw error;
  }
}

/**
 * Stop docker-compose services.
 */
function stopServices(): void {
  console.log('Stopping docker-compose services...');

  try {
    execSync(
      `docker-compose -f "${DOCKER_COMPOSE_FILE}" down`,
      {
        encoding: 'utf-8',
        stdio: 'inherit',
        cwd: path.dirname(DOCKER_COMPOSE_FILE),
      }
    );
  } catch (error) {
    console.error('Failed to stop docker-compose services:', error);
  }
}

/**
 * Verify admin API is working.
 */
async function verifyAdminApi(): Promise<void> {
  console.log('Verifying admin API...');

  const keyPair = await getAdminKeyPair();
  const expectedSpaceId = await getAdminSpaceId();

  const adminClient = new AdminClient({
    keyPair,
    baseUrl: BACKEND_URL,
  });

  // Authenticate and get admin space ID
  await adminClient.authenticate();
  const actualSpaceId = await adminClient.getSpaceId();

  if (actualSpaceId !== expectedSpaceId) {
    throw new Error(
      `Admin space ID mismatch!\n` +
      `  Expected: ${expectedSpaceId}\n` +
      `  Actual: ${actualSpaceId}\n` +
      `Make sure config.e2e.yaml has the correct admin credentials.`
    );
  }

  console.log('✓ Admin API verified');
}

/**
 * Global setup - runs before all tests.
 */
export async function setup(): Promise<void> {
  console.log('\n🚀 E2E Test Setup\n');

  // Check if services are already running
  if (await isBackendHealthy()) {
    console.log('✓ Backend already running, skipping docker-compose start');
    // Set flag so we don't stop services in teardown
    process.env.__E2E_SKIP_TEARDOWN = 'true';
    // Verify admin API works
    await verifyAdminApi();
    console.log('\n✓ E2E setup complete\n');
    return;
  }

  // Check if docker is available
  try {
    execSync('docker --version', { stdio: 'pipe' });
  } catch {
    throw new Error(
      'Docker is not available. Please install Docker to run e2e tests.\n' +
      'Alternatively, start the backend manually and set E2E_BACKEND_URL.'
    );
  }

  // Start services
  startServices();

  // Wait for backend to be healthy
  console.log('Waiting for backend to become healthy...');
  await waitForBackend();

  // Verify admin API works
  await verifyAdminApi();

  console.log('\n✓ E2E setup complete\n');
}

/**
 * Global teardown - runs after all tests.
 */
export async function teardown(): Promise<void> {
  console.log('\n🧹 E2E Test Teardown\n');

  // Skip if services were already running before tests
  if (process.env.__E2E_SKIP_TEARDOWN === 'true') {
    console.log('✓ Skipping teardown (services were already running)');
    return;
  }

  // Stop services
  stopServices();

  console.log('\n✓ E2E teardown complete\n');
}
