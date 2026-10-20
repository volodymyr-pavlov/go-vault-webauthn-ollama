/**
 * End-to-end tests of the session of a tab and of the clock of the device. They need no passkey, so they run in every
 * browser.
 */
import { expect, type Page } from '@playwright/test';
import { test } from './fixtures';
import { registerWithTotp, submitCode, submitPassword, totpCode, uniqueEmail, testPassword } from './helpers';

const password = testPassword;
const hour = 3_600_000;

/** Reads the session identifier that the page keeps for its tab. */
function storedSession(page: Page): Promise<string | null> {
  return page.evaluate(() => sessionStorage.getItem('vault-login.session'));
}

test('a reload of a tab continues its session without opening a new one', async ({ page }) => {
  const email = uniqueEmail();
  const secret = await registerWithTotp(page, email, password);
  await submitPassword(page, email, password);
  await submitCode(page, totpCode(secret, 1));
  await expect(page.getByText('You are logged in')).toBeVisible();
  const before = await storedSession(page);
  expect(before).toMatch(/^\d+$/);

  const opened: string[] = [];
  page.on('request', (request) => {
    if (request.method() === 'POST' && request.url().endsWith('/v1/session')) {
      opened.push(request.url());
    }
  });
  await page.reload();

  await expect(page.getByText('You are logged in')).toBeVisible();
  expect(await storedSession(page)).toBe(before);
  expect(opened).toHaveLength(0);
});

test('a new tab opens its own session and does not take over the login of the first tab', async ({ page, context }) => {
  const email = uniqueEmail();
  const secret = await registerWithTotp(page, email, password);
  await submitPassword(page, email, password);
  await submitCode(page, totpCode(secret, 1));
  await expect(page.getByText('You are logged in')).toBeVisible();

  // The second tab shares the device key and the local storage, but has no session identifier yet.
  const second = await context.newPage();
  await second.goto('/');
  await expect(second.getByRole('button', { name: 'Log in with a passkey' })).toBeVisible();
  await expect(second.getByText('You are logged in')).toHaveCount(0);
  expect(await storedSession(second)).toMatch(/^\d+$/);
  expect(await storedSession(second)).not.toBe(await storedSession(page));

  await second.reload();
  await expect(second.getByText('You are logged in')).toHaveCount(0);
  await page.reload();
  await expect(page.getByText('You are logged in')).toBeVisible();
});

test('a device with a clock that is an hour fast still works', async ({ page }) => {
  await page.addInitScript((offset) => {
    const real = Date.now.bind(Date);
    Date.now = () => real() + offset;
  }, hour);

  // The page reads the Date header of the server first, which corrects the clock before the first request.
  await page.goto('/');
  await expect(page.getByText('Opening a session…')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Register' })).toBeVisible();
  await expect(page.getByText('The service is not reachable')).toHaveCount(0);
});

test('the page takes the time of the server from a refusal when the clock is an hour slow', async ({ page }) => {
  await page.addInitScript((offset) => {
    const real = Date.now.bind(Date);
    Date.now = () => real() - offset;
  }, hour);
  // Without the Date header the first signature carries the wrong time.
  await page.route(/\/$/, (route) => (route.request().method() === 'HEAD' ? route.abort() : route.fallback()));

  const statuses: number[] = [];
  page.on('response', (response) => {
    if (response.request().method() === 'POST' && response.url().endsWith('/v1/session')) {
      statuses.push(response.status());
    }
  });
  await page.goto('/');

  await expect(page.getByRole('button', { name: 'Register' })).toBeVisible();
  expect(statuses).toEqual([401, 201]);
  expect(await storedSession(page)).toMatch(/^\d+$/);
});
