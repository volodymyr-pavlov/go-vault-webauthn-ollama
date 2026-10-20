/** Signing of requests with HTTP message signatures (RFC 9421) and the Content-Digest header (RFC 9530). */
import { base64url, deviceKey, keyId, now } from '@/lib/deviceKey';

const encoder = new TextEncoder();

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Builds the signature base of RFC 9421 section 2.5, the text that the key signs.
 *
 * The base has one line for each covered component and a last line for "@signature-params". It has no trailing newline.
 *
 * @param components - The names of the covered components, in order. They are derived names such as "@method" and
 *   "@path", or header names in lowercase.
 * @param params - The serialized value of "@signature-params", for example `("@method" "@path");created=1;keyid="k"`.
 * @param resolve - A function that returns the value of one component.
 * @returns The signature base.
 */
export function signatureBase(components: string[], params: string, resolve: (component: string) => string): string {
  const lines = components.map((component) => `"${component}": ${resolve(component)}`);
  lines.push(`"@signature-params": ${params}`);
  return lines.join('\n');
}

/**
 * Hashes a request body, so the signature also covers the body.
 *
 * @param body - The exact string that the request sends.
 * @returns The Content-Digest value of RFC 9530, in the form `sha-256=:<base64>:`.
 */
export async function contentDigest(body: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(body)));
  return `sha-256=:${base64(digest)}:`;
}

/** The three headers that authenticate a request. */
export interface SignedHeaders {
  /** The value of the Content-Digest header. */
  contentDigest: string;
  /** The value of the Signature-Input header. */
  signatureInput: string;
  /** The value of the Signature header. */
  signature: string;
}

const covered = ['@method', '@path', 'content-digest'];

/**
 * Signs a request with the device key, as RFC 9421 describes, and returns the headers to send.
 *
 * The signature covers "@method", "@path" and "content-digest". Its parameters hold the creation time, the key ID and a
 * random nonce, so no two signatures are the same and the server can refuse a replayed request. A request of an open
 * session also names the session in a last "tag" parameter.
 *
 * @param method - The HTTP method of the request.
 * @param path - The path of the request.
 * @param body - The exact string that the request sends, or an empty string if it sends none.
 * @param tag - The identifier of the session, or empty for the request that opens one.
 * @returns The Content-Digest, Signature-Input and Signature headers.
 */
export async function signRequest(method: string, path: string, body: string, tag = ''): Promise<SignedHeaders> {
  const digest = await contentDigest(body);
  const nonce = base64url(crypto.getRandomValues(new Uint8Array(16)));
  const list = `(${covered.map((component) => `"${component}"`).join(' ')})`;
  const params = `${list};created=${now()};keyid="${await keyId()}";alg="ed25519";nonce="${nonce}"${tag ? `;tag="${tag}"` : ''}`;
  const values: Record<string, string> = { '@method': method.toUpperCase(), '@path': path, 'content-digest': digest };
  const base = signatureBase(covered, params, (component) => values[component] ?? '');
  const pair = await deviceKey();
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, encoder.encode(base)));
  return { contentDigest: digest, signatureInput: `sig=${params}`, signature: `sig=:${base64(raw)}:` };
}
