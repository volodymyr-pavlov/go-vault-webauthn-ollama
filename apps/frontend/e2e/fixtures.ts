/** The `test` function of the end-to-end tests. It clears the rate limits of the stand before each test. */
import { test as base } from '@playwright/test';
import { flushRateLimits } from './helpers';

export const test = base.extend<{ rateLimits: undefined }>({
  rateLimits: [
    async ({}, use) => {
      await flushRateLimits();
      await use(undefined);
    },
    { auto: true },
  ],
});
