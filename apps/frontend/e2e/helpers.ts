import { execFile } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import { expect } from '@playwright/test';
import type { BrowserContext, Page } from '@playwright/test';

const mailUrl = process.env['E2E_MAIL_URL'] ?? 'http://127.0.0.1:8025';

/**
 * Makes an email address, so each test registers its own user.
 *
 * @returns An address that no other test run uses.
 */
export function uniqueEmail(): string {
  return `e2e-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
}

/** A virtual authenticator of a page, with the means to move its passkeys to another one. */
export interface Authenticator {
  /** Removes the authenticator and the passkeys on it. */
  remove: () => Promise<void>;
  /** Reads the passkeys that the authenticator holds, with their private keys. */
  credentials: () => Promise<Credential[]>;
  /** Adds passkeys that another authenticator held, so this one can log in to the same users. */
  add: (credentials: Credential[]) => Promise<void>;
}

/** A passkey as the WebAuthn domain of the Chrome DevTools Protocol describes it. The binary values are base64 text. */
export interface Credential {
  credentialId: string;
  isResidentCredential: boolean;
  rpId?: string;
  privateKey: string;
  userHandle?: string;
  signCount: number;
  largeBlob?: string;
  backupEligibility?: boolean;
  backupState?: boolean;
  userName?: string;
  userDisplayName?: string;
}

/**
 * Adds a virtual authenticator to the page, so the tests can create and use passkeys without a device.
 *
 * The authenticator verifies the user and stores discoverable credentials.
 *
 * @param context - The browser context of the test.
 * @param page - The page that gets the authenticator.
 * @returns The authenticator, for a test that moves its passkeys to another page.
 */
export async function addVirtualAuthenticator(context: BrowserContext, page: Page): Promise<Authenticator> {
  const session = await context.newCDPSession(page);
  await session.send('WebAuthn.enable');
  const { authenticatorId } = await session.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return {
    remove: async () => {
      await session.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    },
    credentials: async () => (await session.send('WebAuthn.getCredentials', { authenticatorId })).credentials,
    add: async (credentials) => {
      for (const credential of credentials) {
        await session.send('WebAuthn.addCredential', { authenticatorId, credential });
      }
    },
  };
}

/** The part of a Mailpit message that the tests read. */
interface MailMessage {
  ID: string;
  To: { Address: string }[];
}

/** The password that the tests register users with. */
export const testPassword = 'correct horse battery staple';

// Reads a JSON answer of Mailpit and fails with its status when Mailpit refuses.
async function mailJson<T>(path: string): Promise<T> {
  const response = await fetch(`${mailUrl}${path}`);
  if (!response.ok) {
    throw new Error(`Mailpit answered ${response.status} for ${path}.`);
  }

  return (await response.json()) as T;
}

// Waits half a second.
const pause = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 500));

/**
 * Reads the newest token of 64 hex digits from the mails that Mailpit received for an address.
 *
 * It checks every half second, up to 30 times. Use it for the verification mail, or, with `after`, when the user
 * already got an older mail and the test needs the token of a later one.
 *
 * @param email - The address that gets the mail.
 * @param after - The tokens to ignore, such as the ones the test read before.
 * @returns The newest token that is not in the ignore list.
 * @throws Error if no mail with a new token arrives.
 */
export async function newestToken(email: string, after: string[] = []): Promise<string> {
  for (let attempt = 0; attempt < 30; attempt++) {
    const list = await mailJson<{ messages: MailMessage[] }>('/api/v1/messages');
    // Mailpit lists the newest message first.
    for (const message of list.messages.filter((item) => item.To.some((to) => to.Address === email))) {
      const body = await mailJson<{ Text: string }>(`/api/v1/message/${message.ID}`);
      const token = /[0-9a-f]{64}/.exec(body.Text)?.[0];
      if (token && !after.includes(token)) {
        return token;
      }
    }

    await pause();
  }

  throw new Error(`No new token mail arrived for ${email}.`);
}

/**
 * Reads the verification token from the mail that Mailpit received for an address.
 *
 * @param email - The address that the user registered with.
 * @returns The verification token of 64 hex digits.
 * @throws Error if no mail with a verification token arrives.
 */
export function verificationToken(email: string): Promise<string> {
  return newestToken(email);
}

function base32(text: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of text.replace(/=+$/, '').toUpperCase()) {
    const value = alphabet.indexOf(char);
    if (value < 0) {
      throw new Error(`"${char}" is not a base32 character.`);
    }

    bits += value.toString(2).padStart(5, '0');
  }

  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(parseInt(bits.slice(index, index + 8), 2));
  }

  return Buffer.from(bytes);
}

/**
 * Computes the code that an authenticator app shows, as RFC 6238 describes.
 *
 * @param secret - The base32 secret that the page shows during the setup.
 * @param offset - The number of 30-second steps from now. The default is the current step.
 * @returns The code of six digits.
 */
export function totpCode(secret: string, offset = 0): string {
  const counter = Math.floor(Date.now() / 30_000) + offset;
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', base32(secret)).update(message).digest();
  const start = (digest[digest.length - 1] ?? 0) & 0x0f;
  const value = digest.readUInt32BE(start) & 0x7fffffff;
  return String(value % 1_000_000).padStart(6, '0');
}

/**
 * Registers a user with a password and verifies it with the verification token from the mail.
 *
 * @param page - The page of the test.
 * @param email - The address to register.
 * @param password - The password of the user.
 */
export async function registerAndVerify(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/');
  await page.getByRole('button', { name: 'Register' }).click();
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Register', exact: true }).last().click();

  await page.getByLabel('Verification token').fill(await verificationToken(email));
  await page.getByRole('button', { name: 'Verify' }).click();
}

/**
 * Enters a name and adds a passkey on a screen that offers it.
 *
 * @param page - The page of the test.
 * @param name - The name of the passkey.
 */
export async function addPasskey(page: Page, name: string): Promise<void> {
  await page.getByLabel('Name of the passkey').fill(name);
  await page.getByRole('button', { name: 'Add a passkey' }).click();
}

/**
 * Registers a user with a password, enrolls an authenticator app and returns to the login screen.
 *
 * The user has no passkey, so any browser can run it. The first code is spent, so a later login must use the
 * code of the next step.
 *
 * @param page - The page of the test.
 * @param email - The address to register.
 * @param password - The password of the user.
 * @returns The base32 secret of the authenticator app, for [totpCode].
 */
export async function registerWithTotp(page: Page, email: string, password: string): Promise<string> {
  await registerAndVerify(page, email, password);
  await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  const secret = (await page.locator('code').first().innerText()).trim();
  await page.getByLabel('The first code of the app').fill(totpCode(secret));
  await page.getByRole('button', { name: 'Confirm the app' }).click();
  await page.getByRole('button', { name: 'Continue to log in' }).click();
  // The click opens a new session first, and until it ends the enrollment screen is still on the page.
  await expect(page.getByRole('button', { name: 'Log in with a passkey' })).toBeVisible();
  return secret;
}

/**
 * Types the email and the password on the login screen and moves to the step that asks for the code.
 *
 * @param page - The page of the test, on the login screen.
 * @param email - The address of the user.
 * @param pass - The password to type.
 */
export async function submitPassword(page: Page, email: string, pass: string): Promise<void> {
  await page.getByLabel('Email').fill(email);
  await page.getByRole('button', { name: 'Use a password' }).click();
  await page.getByLabel('Password').fill(pass);
  await page.getByRole('button', { name: 'Continue' }).click();
}

/**
 * Types a code on the step that asks for it and sends it.
 *
 * @param page - The page of the test, on the code step of the login.
 * @param code - The code to type.
 */
export async function submitCode(page: Page, code: string): Promise<void> {
  await page.getByLabel('Code from your authenticator app').fill(code);
  await page.locator('form').getByRole('button', { name: 'Log in', exact: true }).click();
}

/**
 * Registers a user with a passkey and logs in with it.
 *
 * @param page - The page of the test. It needs a virtual authenticator.
 * @param email - The address to register.
 * @param password - The password of the user.
 * @param name - The name of the passkey.
 */
export async function registerWithPasskey(page: Page, email: string, password: string, name: string): Promise<void> {
  await registerAndVerify(page, email, password);
  await addPasskey(page, name);
  await page.getByRole('button', { name: 'Continue to log in' }).click();
  await page.getByRole('button', { name: 'Log in with a passkey' }).click();
  await expect(page.getByText('You are logged in')).toBeVisible();
}

const run = promisify(execFile);

// The compose files are in the root of the repository, so the commands run there as the Makefile does.
const root = resolve(import.meta.dirname, '../../..');

/**
 * Runs a command of the stand with Docker Compose from the root of the repository.
 *
 * Compose reads the environment files itself, so the tests never see the secrets in them.
 *
 * @param args - The arguments after `docker compose` and the environment files.
 * @returns The standard output of the command.
 */
async function compose(args: string[]): Promise<string> {
  const { stdout } = await run(
    'docker',
    ['compose', '--env-file', 'scripts/versions.env', '--env-file', '.env', ...args],
    { cwd: root },
  );
  return stdout;
}

/**
 * Runs an SQL statement in the database of the stand.
 *
 * @param statement - The statement to run.
 * @returns The rows as text, without column names, one line for each row.
 */
async function sql(statement: string): Promise<string> {
  return compose(['exec', '-T', 'mysql', 'sh', '-c', 'mysql -ulogin -p"$MYSQL_PASSWORD" login -N -e "$0"', statement]);
}

/**
 * Plays the operator for the newest recovery request: it ends the waiting time, then approves the request with the
 * real operator command.
 *
 * The waiting time of all open requests ends, which is harmless because only the approved request can be claimed.
 *
 * @returns The XID of the approved request.
 * @throws Error if the stand has no recovery request.
 */
export async function approveNewestRecovery(): Promise<string> {
  await sql('UPDATE recovery_requests SET ready_at = ready_at - INTERVAL 100 HOUR');
  const xid = (await sql('SELECT recovery_request_xid FROM recovery_requests ORDER BY id DESC LIMIT 1')).trim();
  if (!/^\d+$/.test(xid)) {
    throw new Error('The stand has no recovery request.');
  }

  await compose(['--profile', 'ops', 'run', '--rm', '--entrypoint', 'recovery', 'recovery', 'approve', xid]);
  return xid;
}

/**
 * Clears what the stand remembers about the address of the tests: the rate limit counters and the sessions of the
 * address. All tests come from one address. Without this, a long run reaches the limits and the page shows "Too many
 * tries". The failures and the many users of the earlier tests also raise the risk score of every later login, until
 * the risk check refuses it.
 */
export async function flushRateLimits(): Promise<void> {
  await compose(['exec', '-T', 'redis', 'redis-cli', 'FLUSHDB']);
  await sql('UPDATE sessions SET ip = NULL WHERE ip IS NOT NULL');
}
