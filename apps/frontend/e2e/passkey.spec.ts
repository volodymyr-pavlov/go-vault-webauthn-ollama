/**
 * End-to-end tests of the flows that use a passkey. They need the virtual authenticator of the Chrome DevTools
 * Protocol, so only the chromium project runs this file (see `testIgnore` in playwright.config.ts).
 */
import { expect, type Page } from '@playwright/test';
import QRCode from 'qrcode';
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
  await expect(page.getByText('You are all set')).toBeVisible();
  await page.getByRole('button', { name: 'Continue to log in' }).click();

  // The passkey names the user, so the page sends no email and the person types none.
  await expect(page.getByLabel('Email')).toHaveValue('');
  const begin = page.waitForRequest('**/v1/auth/passkey');
  await page.getByRole('button', { name: 'Log in with a passkey' }).click();
  expect((await begin).postDataJSON()).toEqual({});

  await expect(page.getByText('You are logged in')).toBeVisible();
  await page.getByRole('tab', { name: 'Security' }).click();
  await expect(page.getByText('Test laptop')).toBeVisible();
  await page.getByRole('tab', { name: 'Data' }).click();
  await expect(page.getByText('Risk score')).toBeVisible();
});

test('a passkey user is refused an authenticator app and issues recovery codes', async ({ page, context }) => {
  await addVirtualAuthenticator(context, page);
  await registerWithPasskey(page, uniqueEmail(), password, 'Manage test');

  await page.getByRole('tab', { name: 'Security' }).click();
  await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  await expect(page.getByText('You use a passkey')).toBeVisible();

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
  await page.getByRole('tab', { name: 'Security' }).click();
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

  await page.getByRole('tab', { name: 'Security' }).click();
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

test('the person downloads their data and deletes the user with a passkey', async ({ page, context }) => {
  await addVirtualAuthenticator(context, page);
  const email = uniqueEmail();
  await registerWithPasskey(page, email, password, 'Erase me');

  await page.getByRole('tab', { name: 'Data' }).click();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download my data' }).click();
  expect((await download).suggestedFilename()).toBe('my-data.json');

  await page.getByRole('button', { name: 'Delete my data' }).click();
  await page.getByRole('button', { name: 'Yes, delete everything for good' }).click();

  await expect(page.getByText('You are logged in')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Log in with a passkey' })).toBeVisible();
});

test('the authenticator keeps typed, linked, scanned and imported accounts and shows their codes', async ({
  page,
  context,
}) => {
  await addVirtualAuthenticator(context, page);
  await registerWithPasskey(page, uniqueEmail(), password, 'Key');

  const codes = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Authenticator codes' }) });

  // A typed secret, with an issuer and a name.
  await codes.getByLabel(/Link or secret/).fill('jbsw y3dp ehpk 3pxp');
  await codes.getByLabel('Issuer').fill('GitHub');
  await codes.getByLabel('Account name').fill('alice@example.com');
  await codes.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(codes.getByLabel('Code for GitHub · alice@example.com', { exact: true })).toHaveText(/^\d{3} \d{3}$/);

  // A pasted otpauth link with eight digits.
  await codes
    .getByLabel(/Link or secret/)
    .fill('otpauth://totp/Example:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&issuer=Example');
  await codes.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(codes.getByLabel('Code for Example · bob', { exact: true })).toHaveText(/^\d{4} \d{4}$/);

  // A picture of a QR code.
  const picture = await QRCode.toBuffer('otpauth://totp/Scanned:carol?secret=JBSWY3DPEHPK3PXP&issuer=Scanned', {
    scale: 8,
  });
  await codes.getByLabel('QR image').setInputFiles({ name: 'qr.png', mimeType: 'image/png', buffer: picture });
  await expect(codes.getByLabel('Code for Scanned · carol', { exact: true })).toHaveText(/^\d{3} \d{3}$/);

  // A Google Authenticator export with one time-based and one counter-based account.
  const entry = (name: string, secret: string, kind: number) => {
    const body = Buffer.concat([
      Buffer.from([0x0a, secret.length]),
      Buffer.from(secret),
      Buffer.from([0x12, name.length]),
      Buffer.from(name),
      Buffer.from([0x30, kind]),
    ]);
    return Buffer.concat([Buffer.from([0x0a, body.length]), body]);
  };
  const payload = Buffer.concat([
    entry('google-one', 'google-secret-aaaa', 2),
    entry('google-two', 'google-secret-bbbb', 1),
  ]);
  await codes
    .getByLabel(/Link or secret/)
    .fill(`otpauth-migration://offline?data=${encodeURIComponent(payload.toString('base64'))}`);
  await codes.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(codes.getByLabel('Code for google-one', { exact: true })).toHaveText(/^\d{3} \d{3}$/);
  await expect(codes.getByText(/1 counter-based account was left out/)).toBeVisible();

  // The codes change when their step ends, and a removed account is gone.
  await codes.getByRole('button', { name: 'Remove Example · bob' }).click();
  await expect(codes.getByLabel('Code for Example · bob', { exact: true })).toHaveCount(0);
  await expect(codes.getByLabel('Code for GitHub · alice@example.com', { exact: true })).toBeVisible();
});

test('the page shows a wait message while the server checks the risk of a login', async ({ page, context }) => {
  await addVirtualAuthenticator(context, page);
  await registerWithPasskey(page, uniqueEmail(), password, 'Slow check');
  await page.getByRole('button', { name: 'Log out' }).click();

  // The server asks a local model for advice, which takes seconds. The test slows the answer down to show the wait.
  await page.route('**/v1/auth/passkey/complete', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 2_000));
    await route.continue();
  });

  await page.getByRole('button', { name: 'Log in with a passkey' }).click();

  await expect(page.getByRole('status').filter({ hasText: 'Checking your login for risks' })).toBeVisible();
  await expect(page.getByText('You are logged in')).toBeVisible();
  await expect(page.getByRole('status').filter({ hasText: 'Checking your login for risks' })).toHaveCount(0);
});

test.describe('the camera', () => {
  // The chromium project of playwright.config.ts makes a fake video stream. The page may use the camera.
  test.use({ permissions: ['camera'] });

  test('the page is allowed to use the camera, so the scan starts', async ({ page, context }) => {
    await addVirtualAuthenticator(context, page);
    await registerWithPasskey(page, uniqueEmail(), password, 'Camera key');

    await page.getByRole('button', { name: 'Scan with the camera' }).click();

    await expect(page.locator('video')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Stop the camera' })).toBeVisible();
    await expect(page.getByRole('alert')).toHaveCount(0);
  });
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
    await device.getByLabel('Your email').fill(email);
    await device.getByRole('button', { name: 'Ask for a recovery' }).click();
    await expect(device.getByText('If the address is registered, we sent an email.')).toBeVisible();
    const cancel = await newestToken(email, [verification]);

    // The operator ends the waiting time and approves the request, then the person claims the grant token.
    await approveNewestRecovery();
    await device.getByRole('button', { name: 'Send me the grant token' }).click();
    await expect(device.getByText('If the address is registered, we sent an email.')).toBeVisible();
    await device.getByLabel('Grant token').fill(await newestToken(email, [verification, cancel]));
    await device.getByRole('button', { name: 'Use the grant token' }).click();

    await addPasskey(device, 'New laptop');
    await expect(device.getByText('You are all set')).toBeVisible();
    await device.getByRole('button', { name: 'Continue to log in' }).click();
    await device.getByRole('button', { name: 'Log in with a passkey' }).click();
    await expect(device.getByText('You are logged in')).toBeVisible();
    await device.getByRole('tab', { name: 'Security' }).click();
    await expect(device.getByText('New laptop')).toBeVisible();
  } finally {
    await other.close();
  }

  // The recovery revokes the older sessions of the user, so the first page is logged out after a reload.
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
    await page.getByRole('tab', { name: 'Security' }).click();
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
