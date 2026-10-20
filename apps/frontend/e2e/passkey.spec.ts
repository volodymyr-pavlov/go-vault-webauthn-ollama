/**
 * End-to-end tests of the flows that use a passkey. They need the virtual authenticator of the Chrome DevTools
 * Protocol, so only the chromium project runs this file (see `testIgnore` in playwright.config.ts).
 */
import { expect, type Page } from '@playwright/test';
import { test } from './fixtures';
import {
  addPasskey,
  addVirtualAuthenticator,
  approveNewestRecovery,
  newestToken,
  registerAndVerify,
  registerWithPasskey,
  totpCode,
  uniqueEmail,
  verificationToken,
  testPassword,
} from './helpers';

const password = testPassword;

test('a new user registers, adds a passkey, and logs in with it', async ({ page, context }) => {
  await addVirtualAuthenticator(context, page);
  await registerAndVerify(page, uniqueEmail(), password);

  await addPasskey(page, 'Test laptop');
  await expect(page.getByText('Your account is ready')).toBeVisible();
  await page.getByRole('button', { name: 'Continue to log in' }).click();

  // The passkey names the account, so the page sends no email and the person types none.
  await expect(page.getByLabel('Email')).toHaveValue('');
  const begin = page.waitForRequest('**/v1/auth/passkey');
  await page.getByRole('button', { name: 'Log in with a passkey' }).click();
  expect((await begin).postDataJSON()).toEqual({});

  await expect(page.getByText('You are logged in')).toBeVisible();
  await expect(page.getByText('Test laptop')).toBeVisible();
  await expect(page.getByText('Risk score')).toBeVisible();
});

test('a passkey account is refused an authenticator app and issues recovery codes', async ({ page, context }) => {
  await addVirtualAuthenticator(context, page);
  await registerWithPasskey(page, uniqueEmail(), password, 'Manage test');

  await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  await expect(page.getByText('This account uses a passkey')).toBeVisible();

  await page.getByRole('button', { name: 'Issue recovery codes' }).click();
  await expect(page.getByText('Save these codes now')).toBeVisible();
  await expect(page.locator('li.font-mono, ul.font-mono li')).toHaveCount(8);
});

test('a recovery code adds a new passkey after the factors are lost', async ({ page, context }) => {
  await addVirtualAuthenticator(context, page);
  const email = uniqueEmail();
  await registerAndVerify(page, email, password);

  await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  const secret = (await page.locator('code').first().innerText()).trim();
  await page.getByLabel('The first code of the app').fill(totpCode(secret));
  await page.getByRole('button', { name: 'Confirm the app' }).click();
  await page.getByRole('button', { name: 'Issue recovery codes' }).click();
  const code = (await page.locator('ul.grid li').first().innerText()).trim();
  await page.getByRole('button', { name: 'Continue to log in' }).click();

  await page.getByRole('button', { name: 'Recover' }).click();
  await page.getByLabel('Email', { exact: true }).fill(email);
  await page.getByLabel('Recovery code').fill(code);
  await page.getByRole('button', { name: 'Use the code' }).click();

  await addPasskey(page, 'After recovery');
  await page.getByRole('button', { name: 'Continue to log in' }).click();
  await page.getByRole('button', { name: 'Log in with a passkey' }).click();
  await expect(page.getByText('You are logged in')).toBeVisible();
});

test('the session survives a reload until the person logs out', async ({ page, context }) => {
  await addVirtualAuthenticator(context, page);
  await registerWithPasskey(page, uniqueEmail(), password, 'Reload test');

  await page.reload();
  await expect(page.getByText('You are logged in')).toBeVisible();
  await expect(page.getByText('Reload test')).toBeVisible();

  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.getByRole('button', { name: 'Log in with a passkey' })).toBeVisible();
  await expect(page.getByText('You are logged in')).toHaveCount(0);

  await page.reload();
  await expect(page.getByRole('button', { name: 'Log in with a passkey' })).toBeVisible();
  await expect(page.getByText('You are logged in')).toHaveCount(0);
});

test('the last passkey cannot be removed, and another one can', async ({ page, context }) => {
  const removeFirst = (await addVirtualAuthenticator(context, page)).remove;
  await registerWithPasskey(page, uniqueEmail(), password, 'First key');

  await page.getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText('The last factor cannot be removed. Add another one first.');
  await expect(page.getByText('First key')).toBeVisible();

  // The first passkey lives on the authenticator and the page excludes it, so the second one needs an empty device.
  await removeFirst();
  await addVirtualAuthenticator(context, page);
  await addPasskey(page, 'Second key');
  await expect(page.getByText('Second key')).toBeVisible();

  await page
    .getByRole('listitem')
    .filter({ hasText: 'First key' })
    .getByRole('button', { name: 'Remove', exact: true })
    .click();
  await expect(page.getByText('First key')).toHaveCount(0);
  await expect(page.getByText('Second key')).toBeVisible();
});

test('the person downloads their data and deletes the account with a passkey', async ({ page, context }) => {
  await addVirtualAuthenticator(context, page);
  const email = uniqueEmail();
  await registerWithPasskey(page, email, password, 'Erase me');

  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download my data' }).click();
  expect((await download).suggestedFilename()).toBe('my-data.json');

  await page.getByRole('button', { name: 'Delete my account' }).click();
  await page.getByRole('button', { name: 'Yes, delete my account for good' }).click();

  await expect(page.getByText('You are logged in')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Log in with a passkey' })).toBeVisible();
});

test('the page shows the decision and the refusals of a passkey login', async ({ page, context }) => {
  await addVirtualAuthenticator(context, page);
  const email = uniqueEmail();
  await registerAndVerify(page, email, password);
  await addPasskey(page, 'Risk test');
  await page.getByRole('button', { name: 'Continue to log in' }).click();

  const login = page.getByRole('button', { name: 'Log in with a passkey' });
  const complete = '**/v1/auth/passkey/complete';

  await page.route(complete, (route) =>
    route.fulfill({
      status: 403,
      json: { error: { status: 403, num: 10019, code: 'RISK_DENIED', message: 'The login was refused.' } },
    }),
  );
  await login.click();
  await expect(page.getByRole('alert')).toHaveText('The login was refused. Contact support if this is you.');

  await page.unroute(complete);
  await page.route(complete, (route) =>
    route.fulfill({
      status: 429,
      json: { error: { status: 429, num: 10025, code: 'TOO_MANY_REQUESTS', message: 'Too many requests.' } },
    }),
  );
  await login.click();
  await expect(page.getByRole('alert')).toHaveText('Too many tries. Wait a moment and try again.');

  // With the route gone, the real server lets the same passkey in.
  await page.unroute(complete);
  await login.click();
  await expect(page.getByText('You are logged in')).toBeVisible();
});

test('an approved delayed recovery adds a new passkey and ends the old session', async ({ page, context, browser }) => {
  await addVirtualAuthenticator(context, page);
  const email = uniqueEmail();
  await registerAndVerify(page, email, password);
  const verification = await verificationToken(email);
  await addPasskey(page, 'Lost laptop');
  await page.getByRole('button', { name: 'Continue to log in' }).click();
  await page.getByRole('button', { name: 'Log in with a passkey' }).click();
  await expect(page.getByText('You are logged in')).toBeVisible();

  // Another device of the person: it has no passkey and no recovery code.
  const other = await browser.newContext();
  try {
    const device = await other.newPage();
    await addVirtualAuthenticator(other, device);
    await device.goto('/');
    await device.getByRole('button', { name: 'Recover' }).click();
    await device.getByLabel('Email of the account').fill(email);
    await device.getByRole('button', { name: 'Ask for a recovery' }).click();
    await expect(device.getByText('If the account exists, we sent an email.')).toBeVisible();
    const cancel = await newestToken(email, [verification]);

    // The operator ends the waiting time and approves the request, then the person claims the grant token.
    await approveNewestRecovery();
    await device.getByRole('button', { name: 'Send me the grant token' }).click();
    await expect(device.getByText('If the account exists, we sent an email.')).toBeVisible();
    await device.getByLabel('Grant token').fill(await newestToken(email, [verification, cancel]));
    await device.getByRole('button', { name: 'Use the grant token' }).click();

    await addPasskey(device, 'New laptop');
    await expect(device.getByText('Your account is ready')).toBeVisible();
    await device.getByRole('button', { name: 'Continue to log in' }).click();
    await device.getByRole('button', { name: 'Log in with a passkey' }).click();
    await expect(device.getByText('You are logged in')).toBeVisible();
    await expect(device.getByText('New laptop')).toBeVisible();
  } finally {
    await other.close();
  }

  // The recovery revokes the older sessions of the account, so the first page is logged out after a reload.
  await page.reload();
  await expect(page.getByRole('button', { name: 'Log in with a passkey' })).toBeVisible();
  await expect(page.getByText('You are logged in')).toHaveCount(0);
});

test('two tabs of one browser keep their own sessions, and a logout in one leaves the other logged in', async ({
  page,
  context,
}) => {
  const first = await addVirtualAuthenticator(context, page);
  await registerWithPasskey(page, uniqueEmail(), password, 'Shared key');

  // The second tab has the same device key, and its authenticator holds the same passkey.
  const second = await context.newPage();
  await (await addVirtualAuthenticator(context, second)).add(await first.credentials());
  await second.goto('/');
  await second.getByRole('button', { name: 'Log in with a passkey' }).click();
  await expect(second.getByText('You are logged in')).toBeVisible();

  const stored = (tab: Page) => tab.evaluate(() => sessionStorage.getItem('vault-login.session'));
  expect(await stored(second)).not.toBe(await stored(page));

  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.getByRole('button', { name: 'Log in with a passkey' })).toBeVisible();

  await second.reload();
  await expect(second.getByText('You are logged in')).toBeVisible();
  await page.reload();
  await expect(page.getByRole('button', { name: 'Log in with a passkey' })).toBeVisible();
});

test('the devices list shows the other login, and removing it logs that browser out', async ({
  page,
  context,
  browser,
}) => {
  const first = await addVirtualAuthenticator(context, page);
  await registerWithPasskey(page, uniqueEmail(), password, 'Device test');

  // Another browser has its own device key. Its authenticator holds a copy of the passkey.
  const other = await browser.newContext();
  try {
    const device = await other.newPage();
    await (await addVirtualAuthenticator(other, device)).add(await first.credentials());
    await device.goto('/');
    await device.getByRole('button', { name: 'Log in with a passkey' }).click();
    await expect(device.getByText('You are logged in')).toBeVisible();

    await page.reload();
    const devices = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Devices' }) });
    await expect(devices.getByRole('listitem')).toHaveCount(2);
    await expect(devices.getByText('This device')).toHaveCount(1);
    await expect(devices.getByRole('listitem').filter({ hasText: 'This device' }).getByRole('button')).toHaveCount(0);

    await devices
      .getByRole('listitem')
      .filter({ hasNotText: 'This device' })
      .getByRole('button', { name: 'Remove' })
      .click();
    await expect(devices.getByRole('listitem')).toHaveCount(1);
    await expect(devices.getByText('This device')).toBeVisible();

    await device.reload();
    await expect(device.getByRole('button', { name: 'Log in with a passkey' })).toBeVisible();
    await expect(device.getByText('You are logged in')).toHaveCount(0);
  } finally {
    await other.close();
  }
});
