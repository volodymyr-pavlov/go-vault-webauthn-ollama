import { defineConfig, devices } from '@playwright/test';

// The tests run against the stand: start it with `make stand-up` first.
export default defineConfig({
  testDir: 'e2e',
  outputDir: '.reports/test-results',
  reporter: [['list']],
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  // A login waits for the local model, which takes several seconds on a CPU.
  expect: { timeout: 30_000 },
  use: {
    baseURL: process.env['E2E_BASE_URL'] ?? 'http://localhost:3000',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    // The virtual authenticator of the passkey tests exists only in Chromium.
    { name: 'firefox', use: { ...devices['Desktop Firefox'] }, testIgnore: /passkey\.spec\.ts/ },
    { name: 'webkit', use: { ...devices['Desktop Safari'] }, testIgnore: /passkey\.spec\.ts/ },
  ],
});
