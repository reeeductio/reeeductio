/**
 * Vitest config for end-to-end tests.
 *
 * E2E tests run against a real backend server.
 * The global setup will automatically start docker-compose services.
 *
 * Run with: npm run test:e2e
 *
 * To skip auto-start (if backend is already running):
 *   E2E_BACKEND_URL=http://localhost:8000 npm run test:e2e
 */
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/__tests__/e2e/**/*.e2e.test.ts'],
    globalSetup: ['src/__tests__/e2e/globalSetup.ts'],
    testTimeout: 30000, // E2E tests may be slower
    hookTimeout: 60000, // Backend startup may take time
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/__tests__/**', 'src/**/*.d.ts'],
    },
  },
});
