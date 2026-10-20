/**
 * End-to-end tests of the flows that need no passkey, so they run in every browser: log in with a password and a code,
 * and cancel a delayed recovery.
 */
import { expect } from '@playwright/test';
import { test } from './fixtures';
import {
  newestToken,
  registerAndVerify,
  registerWithTotp,
  submitCode,
  submitPassword,
  totpCode,
  uniqueEmail,
  verificationToken,
  testPassword,
} from './helpers';

const password = testPassword;

test('a user without a passkey logs in with a password and a code', async ({ page }) => {
  const email = uniqueEmail();
  await page.goto('/');
  await page.getByRole('button', { name: 'Register' }).click();
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Register', exact: true }).last().click();

  await page.getByLabel('Verification token').fill(await verificationToken(email));
  await page.getByRole('button', { name: 'Verify' }).click();

  await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  const secret = (await page.locator('code').first().innerText()).trim();
  await expect(page.getByAltText('QR code of the secret')).toBeVisible();
  await page.getByLabel('The first code of the app').fill(totpCode(secret));
  await page.getByRole('button', { name: 'Confirm the app' }).click();
  await page.getByRole('button', { name: 'Continue to log in' }).click();

  await submitPassword(page, email, password);
  // The code of the first step is spent. The next step's code is inside the window of the server.
  await submitCode(page, totpCode(secret, 1));

  await expect(page.getByText('You are logged in')).toBeVisible();
});

test('the authenticator app stays on the account, and a second one is refused', async ({ page }) => {
  const email = uniqueEmail();
  const secret = await registerWithTotp(page, email, password);
  await submitPassword(page, email, password);
  await submitCode(page, totpCode(secret, 1));
  await expect(page.getByText('You are logged in')).toBeVisible();

  // The app is the only factor of the account, because a passkey and an app never share an account.
  await page.getByRole('button', { name: 'Remove the authenticator app' }).click();
  await expect(page.getByRole('alert')).toHaveText('The last factor cannot be removed. Add another one first.');

  await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'enrolled already' })).toHaveText(
    'A code generator is enrolled already.',
  );
});

test('the owner cancels a delayed recovery with the token from the email', async ({ page }) => {
  const email = uniqueEmail();
  await registerAndVerify(page, email, password);
  const verification = await verificationToken(email);
  await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  const secret = (await page.locator('code').first().innerText()).trim();
  await page.getByLabel('The first code of the app').fill(totpCode(secret));
  await page.getByRole('button', { name: 'Confirm the app' }).click();
  await page.getByRole('button', { name: 'Continue to log in' }).click();
  await expect(page.getByRole('button', { name: 'Log in with a passkey' })).toBeVisible();

  await page.getByRole('button', { name: 'Recover' }).click();
  await page.getByLabel('Email of the account').fill(email);
  await page.getByRole('button', { name: 'Ask for a recovery' }).click();
  await expect(page.getByText('If the account exists, we sent an email.')).toBeVisible();

  await page.getByLabel('Cancel token').fill(await newestToken(email, [verification]));
  await page.getByRole('button', { name: 'Cancel the recovery' }).click();
  await expect(page.getByText('The recovery request is cancelled.')).toBeVisible();
});

for (const decision of ['limit', 'review'] as const) {
  test(`the page shows the ${decision} decision of the risk check`, async ({ page }) => {
    const email = uniqueEmail();
    const secret = await registerWithTotp(page, email, password);
    // The server answers for real, and the route only changes the decision in the answer.
    await page.route('**/v1/auth/totp', async (route) => {
      const response = await route.fetch();
      const body = (await response.json()) as { data: { decision: string } };
      body.data.decision = decision;
      await route.fulfill({ response, json: body });
    });

    await submitPassword(page, email, password);
    await submitCode(page, totpCode(secret, 1));

    await expect(page.getByText('You are logged in')).toBeVisible();
    await expect(page.getByRole('status').filter({ hasText: /^The login was / })).toHaveText(
      decision === 'limit'
        ? 'The login was limited. A sensitive action needs a fresh login first.'
        : 'The login was flagged for review.',
    );
  });
}
