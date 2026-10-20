/** The client of the Vault Login API. */
import { publicKey, setServerTime } from '@/lib/deviceKey';
import { signRequest } from '@/lib/httpsig';
import { sessionXid } from '@/lib/sessionId';
import { getPasskey } from '@/lib/webauthn';
import type {
  Authorized,
  DeviceView,
  ErrorBody,
  PasskeyView,
  RecoveryStatus,
  SessionOpened,
  SessionState,
  TOTPEnrollment,
  WebAuthnOptions,
} from '@/api/types';

/** An error that the API returns for a request. It carries the HTTP status and the number and code of the error. */
export class ApiError extends Error {
  /** The HTTP status of the response. */
  readonly status: number;
  /** The number of the error in the API. */
  readonly num: number;
  /** The name of the error in the API. */
  readonly code: string;
  /** Extra values for the error. It is empty when the API sends none. */
  readonly params: Record<string, unknown>;

  /** Creates the error from the error object of a response. */
  constructor(body: ErrorBody) {
    super(body.message);
    this.name = 'ApiError';
    this.status = body.status;
    this.num = body.num;
    this.code = body.code;
    this.params = body.params ?? {};
  }
}

/** The JSON body of every response: either data or an error. */
interface Envelope<T> {
  data?: T;
  error?: ErrorBody;
}

/** The optional parts of a request. */
interface Call {
  body?: unknown;
  /** If true, the request names no session. Only the request that opens a session sets it. */
  untagged?: boolean;
}

/**
 * Signs and sends one request with the device key, and reads the answer.
 *
 * @param method - The HTTP method.
 * @param path - The path of the request. The signature covers it.
 * @param call - The optional JSON body.
 * @returns The data of the response, or undefined for a 204 response.
 * @throws ApiError if the API returns an error or a status that is not a success.
 */
async function send<T>(method: string, path: string, call: Call): Promise<T> {
  const headers: Record<string, string> = {};
  if (call.body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  const body = call.body === undefined ? '' : JSON.stringify(call.body);
  const signed = await signRequest(method, path, body, call.untagged ? '' : sessionXid());
  headers['Content-Digest'] = signed.contentDigest;
  headers['Signature-Input'] = signed.signatureInput;
  headers['Signature'] = signed.signature;

  const response = await fetch(path, {
    method,
    headers,
    body: call.body === undefined ? null : body,
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const envelope = (await response.json().catch(() => ({}))) as Envelope<T>;

  if (envelope.error) {
    throw new ApiError(envelope.error);
  }

  if (!response.ok) {
    throw new ApiError({
      status: response.status,
      num: 0,
      code: 'HTTP',
      message: `The server answered ${response.status}.`,
    });
  }

  return envelope.data as T;
}

/**
 * Signs and sends one request. If the server says that the clock of the device is wrong, the request is sent once
 * more with the time of the server, a new nonce and a new signature.
 *
 * @param method - The HTTP method.
 * @param path - The path of the request. The signature covers it.
 * @param call - The optional JSON body.
 * @returns The data of the response, or undefined for a 204 response.
 * @throws ApiError if the API returns an error or a status that is not a success.
 */
async function request<T>(method: string, path: string, call: Call = {}): Promise<T> {
  try {
    return await send<T>(method, path, call);
  } catch (error) {
    const serverTime = error instanceof ApiError ? error.params['server_time'] : undefined;
    if (!(error instanceof ApiError) || error.code !== 'STALE_REQUEST_TIME' || typeof serverTime !== 'number') {
      throw error;
    }

    setServerTime(serverTime);
    return send<T>(method, path, call);
  }
}

/**
 * The call that starts a session. It sends the public key of the device and signs the request with the private key, so
 * the server can find the session by the key ID later.
 */
export const open = {
  session: async (deviceId: string) =>
    request<SessionOpened>('POST', '/v1/session', {
      body: { device_id: deviceId, device_key: await publicKey() },
      untagged: true,
    }),
};

/** The calls of a session. The device key signs each call, so no call carries a token. */
export const api = {
  session: () => request<SessionState>('GET', '/v1/session'),
  logout: () => request<void>('DELETE', '/v1/session'),

  register: (email: string, password: string) =>
    request<{ flags: number }>('POST', '/v1/register', { body: { email, password } }),
  verify: (verification: string) =>
    request<{ user_xid: string }>('POST', '/v1/register/complete', { body: { token: verification } }),

  beginPasskey: () => request<WebAuthnOptions>('POST', '/v1/enroll/passkey'),
  completePasskey: (name: string, response: unknown) =>
    request<{ passkey_xid: string }>('POST', '/v1/enroll/passkey/complete', { body: { name, response } }),
  beginTOTP: () => request<TOTPEnrollment>('POST', '/v1/enroll/totp'),
  completeTOTP: (code: string) => request<void>('POST', '/v1/enroll/totp/complete', { body: { code } }),
  issueRecoveryCodes: () => request<{ codes: string[] }>('POST', '/v1/enroll/recovery'),

  // Without an email the login is discoverable: the passkey names the account.
  beginLogin: (email?: string) =>
    request<WebAuthnOptions>('POST', '/v1/auth/passkey', { body: email ? { email } : {} }),
  completeLogin: (response: unknown) =>
    request<Authorized>('POST', '/v1/auth/passkey/complete', { body: { response } }),
  password: (email: string, password: string) =>
    request<{ flags: number }>('POST', '/v1/auth/password', { body: { email, password } }),
  totp: (code: string) => request<Authorized>('POST', '/v1/auth/totp', { body: { code } }),
  recovery: (email: string, code: string) =>
    request<{ flags: number }>('POST', '/v1/auth/recovery', { body: { email, code } }),

  requestRecovery: (email: string) => request<RecoveryStatus>('POST', '/v1/recover/request', { body: { email } }),
  cancelRecovery: (token: string) => request<void>('POST', '/v1/recover/cancel', { body: { token } }),
  claimRecovery: (email: string) => request<RecoveryStatus>('POST', '/v1/recover/claim', { body: { email } }),
  grantRecovery: (token: string) => request<{ flags: number }>('POST', '/v1/recover/grant', { body: { token } }),

  passkeys: () => request<{ passkeys: PasskeyView[] }>('GET', '/v1/passkeys'),
  /**
   * Removes a passkey after a fresh passkey assertion. The server returns options whose challenge is bound to this
   * removal. The browser signs them with a passkey of the account, and the server removes the passkey when the
   * assertion verifies.
   *
   * @param xid - The external ID of the passkey to remove.
   * @throws ApiError if a step is refused, for example when the passkey is the last factor.
   */
  removePasskey: async (xid: string): Promise<void> => {
    const options = await request<WebAuthnOptions>('POST', `/v1/passkeys/${xid}/removal`);
    const response = await getPasskey(options);
    await request<void>('POST', `/v1/passkeys/${xid}/removal/confirm`, { body: { response } });
  },
  /**
   * Reads the personal data that the service keeps about the account. It needs a fresh login.
   *
   * @returns The export as the server sends it.
   * @throws ApiError if the request is refused.
   */
  exportAccount: () => request<Record<string, unknown>>('GET', '/v1/account/export'),
  /**
   * Deletes the account. If the account has a passkey, the browser signs a challenge that is bound to the deletion. An
   * account without a passkey is deleted after the fresh login alone.
   *
   * @throws ApiError if a step is refused.
   */
  deleteAccount: async (): Promise<void> => {
    const begun = await request<{ method: string; options?: WebAuthnOptions }>('POST', '/v1/account/deletion');
    const body = begun.method === 'passkey' && begun.options ? { response: await getPasskey(begun.options) } : {};
    await request<void>('POST', '/v1/account/deletion/confirm', { body });
  },
  sessions: () => request<{ sessions: DeviceView[] }>('GET', '/v1/sessions'),
  removeSession: (xid: string) => request<void>('DELETE', `/v1/sessions/${xid}`),
  removeTOTP: () => request<void>('DELETE', '/v1/totp'),
};
