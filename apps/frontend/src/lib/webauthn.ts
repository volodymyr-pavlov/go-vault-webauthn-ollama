/** Passkey steps of the browser, with the JSON forms that the API uses. */
import type { WebAuthnOptions } from '@/api/types';

/**
 * Reports whether this browser can run the passkey steps. It needs the JSON parsing methods of WebAuthn.
 *
 * @returns True when the browser supports them.
 */
export function supported(): boolean {
  return typeof PublicKeyCredential !== 'undefined' && 'parseCreationOptionsFromJSON' in PublicKeyCredential;
}

/**
 * Asks the browser to create a passkey with the options of the server.
 *
 * @param options - The options that the begin step of the server returned.
 * @returns The new credential as JSON, ready to send to the server.
 * @throws Error if the browser does not return a passkey.
 */
export async function createPasskey(options: WebAuthnOptions): Promise<unknown> {
  const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey);
  const credential = await navigator.credentials.create({ publicKey });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error('The browser made no passkey.');
  }

  return credential.toJSON();
}

/**
 * Asks the browser to sign in with a passkey, using the options of the server.
 *
 * @param options - The options that the begin step of the server returned.
 * @returns The assertion as JSON, ready to send to the server.
 * @throws Error if the browser does not return a passkey.
 */
export async function getPasskey(options: WebAuthnOptions): Promise<unknown> {
  const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey);
  const credential = await navigator.credentials.get({ publicKey });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error('The browser gave no passkey.');
  }

  return credential.toJSON();
}
