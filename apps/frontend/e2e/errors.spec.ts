/** End-to-end tests of the error messages of the page. They run in every browser, because they need no passkey. */
import { expect, type Page } from '@playwright/test';
import { test } from './fixtures';
import { registerWithTotp, submitCode, submitPassword, totpCode, uniqueEmail, testPassword } from './helpers';

const password = testPassword;
const refused = 'That did not work. Check what you typed and try again.';

/**
 * Makes the API answer a path with an error of its envelope, as the server sends it.
 *
 * @param page - The page of the test.
 * @param path - The path to answer.
 * @param status - The HTTP status.
 * @param code - The code of the error.
 * @param num - The number of the error.
 */
async function failWith(page: Page, path: string, status: number, code: string, num: number): Promise<void> {
  await page.route(`**${path}`, (route) =>
    route.fulfill({
      status,
      contentType: 'application/json',
      json: { error: { status, num, code, message: `The API says ${code}.` } },
    }),
  );
}

test('a wrong password for an authenticator app account is refused', async ({ page }) => {
  const email = uniqueEmail();
  await registerWithTotp(page, email, password);

  await submitPassword(page, email, 'a different password entirely');

  await expect(page.getByRole('alert')).toHaveText(refused);
  await expect(page.getByLabel('Code from your authenticator app')).toHaveCount(0);
});

test('a wrong code of the authenticator app is refused', async ({ page }) => {
  const email = uniqueEmail();
  const secret = await registerWithTotp(page, email, password);
  await submitPassword(page, email, password);

  // A code from the far future cannot be inside the window of the server.
  await submitCode(page, totpCode(secret, 1000));

  await expect(page.getByRole('alert')).toHaveText(refused);
  await expect(page.getByText('You are logged in')).toHaveCount(0);
});

test('a wrong recovery code is refused', async ({ page }) => {
  const email = uniqueEmail();
  await registerWithTotp(page, email, password);

  await page.getByRole('button', { name: 'Recover' }).click();
  await page.getByLabel('Email', { exact: true }).fill(email);
  await page.getByLabel('Recovery code').fill('AAAA-BBBB-CCCC-DDDD');
  await page.getByRole('button', { name: 'Use the code' }).click();

  await expect(page.getByRole('alert')).toHaveText(refused);
});

test('an unknown cancel token is refused and a malformed one is explained', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Recover' }).click();

  await page.getByLabel('Cancel token').fill('ab'.repeat(32));
  await page.getByRole('button', { name: 'Cancel the recovery' }).click();
  await expect(page.getByRole('alert')).toHaveText(refused);

  await page.getByLabel('Cancel token').fill('not a token');
  await page.getByRole('button', { name: 'Cancel the recovery' }).click();
  await expect(page.getByRole('alert')).toHaveText('The token has 64 hex digits. Check it and try again.');
  await expect(page.getByText('The recovery request is cancelled.')).toHaveCount(0);
});

test('the page says that a login was denied by the risk check', async ({ page }) => {
  await page.goto('/');
  await page.route('**/v1/auth/password', (route) => route.fulfill({ json: { data: { flags: 18 } } }));
  await failWith(page, '/v1/auth/totp', 403, 'RISK_DENIED', 10019);

  await submitPassword(page, 'someone@example.com', password);
  await submitCode(page, '123456');

  await expect(page.getByRole('alert')).toHaveText('The login was refused. Contact support if this is you.');
});

test('the page says that there were too many tries', async ({ page }) => {
  await page.goto('/');
  await failWith(page, '/v1/auth/password', 429, 'TOO_MANY_REQUESTS', 10025);

  await submitPassword(page, 'someone@example.com', password);

  await expect(page.getByRole('alert')).toHaveText('Too many tries. Wait a moment and try again.');
});
