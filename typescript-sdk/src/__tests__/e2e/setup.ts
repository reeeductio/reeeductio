/**
 * E2E test setup and utilities.
 *
 * The global setup (globalSetup.ts) automatically starts docker-compose services.
 * Just run: npm run test:e2e
 */

export const E2E_BACKEND_URL = process.env.E2E_BACKEND_URL || 'http://localhost:8000';

/**
 * Wait for the backend to be healthy.
 *
 * Note: The global setup handles starting docker-compose and initial waiting.
 * This function is a quick sanity check that runs in each test file's beforeAll.
 */
export async function waitForBackend(
  baseUrl: string = E2E_BACKEND_URL,
  maxRetries: number = 5,
  retryDelayMs: number = 1000
): Promise<void> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) {
        const data = await response.json() as { status?: string };
        if (data.status === 'healthy') {
          return;
        }
      }
    } catch {
      // Connection failed, retry
    }

    if (i < maxRetries - 1) {
      await sleep(retryDelayMs);
    }
  }

  throw new Error(
    `Backend at ${baseUrl} not healthy after ${maxRetries * retryDelayMs / 1000}s. ` +
    'The global setup should have started docker-compose services. ' +
    'Check if Docker is running and the services started correctly.'
  );
}

/**
 * Fix MinIO presigned URLs for local testing.
 *
 * In Docker, the backend uses 'minio:9000' as the endpoint, but from
 * the host machine we need to use 'localhost:9000'.
 */
export function fixMinioUrl(url: string): string {
  return url.replace('http://minio:9000', 'http://localhost:9000');
}

/**
 * Sleep for a given number of milliseconds.
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Generate a random topic ID for testing.
 */
export function randomTopicId(): string {
  return `test-topic-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Generate a random data path for testing.
 */
export function randomDataPath(): string {
  return `test/data/${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Generate a random state path for testing.
 */
export function randomStatePath(): string {
  return `test/state/${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}
