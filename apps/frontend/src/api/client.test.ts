/** Tests for the API client. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api, open } from '@/api/client';
import { setServerTime } from '@/lib/deviceKey';
import { contentDigest } from '@/lib/httpsig';
import { forgetSession, rememberSession } from '@/lib/sessionId';
import * as webauthn from '@/lib/webauthn';

function reply(status: number, body: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), { status });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  forgetSession();
  setServerTime(Math.floor(Date.now() / 1000));
});

function headersOf(fetchMock: ReturnType<typeof vi.fn>, call: number): Record<string, string> {
  return ((fetchMock.mock.calls[call] as [string, RequestInit])[1].headers ?? {}) as Record<string, string>;
}

const staleTime = (serverTime: number) =>
  reply(401, {
    error: {
      status: 401,
      num: 10040,
      code: 'STALE_REQUEST_TIME',
      message: 'The time is wrong.',
      params: { server_time: serverTime },
    },
  });

describe('the API client', () => {
  it('unwraps the data of the envelope and sends no token', async () => {
    const fetchMock = vi.fn().mockResolvedValue(reply(200, { data: { flags: 2, risk_score: 0 } }));
    vi.stubGlobal('fetch', fetchMock);

    const state = await api.session();

    expect(state.flags).toBe(2);
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/v1/session');
    expect((init.headers as Record<string, string>)['Authorization']).toBeUndefined();
  });

  it('throws an ApiError with the code of a refusal', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          reply(401, { error: { status: 401, num: 10021, code: 'AUTHENTICATION_FAILED', message: 'no' } }),
        ),
    );

    await expect(api.password('a@b.c', 'x')).rejects.toMatchObject({
      name: 'ApiError',
      code: 'AUTHENTICATION_FAILED',
      status: 401,
    });
    await expect(api.password('a@b.c', 'x')).rejects.toBeInstanceOf(ApiError);
  });

  it('returns nothing for a 204', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply(204, undefined)));

    await expect(api.removeTOTP()).resolves.toBeUndefined();
  });

  it('signs every request with the digest of the body that is sent', async () => {
    const fetchMock = vi.fn().mockResolvedValue(reply(200, { data: { flags: 18 } }));
    vi.stubGlobal('fetch', fetchMock);

    await api.password('a@b.c', 'x');
    await api.session();

    const [, post] = fetchMock.mock.calls[0] as [string, RequestInit];
    const [, get] = fetchMock.mock.calls[1] as [string, RequestInit];
    const postHeaders = post.headers as Record<string, string>;
    const getHeaders = get.headers as Record<string, string>;
    expect(postHeaders['Content-Digest']).toBe(await contentDigest(post.body as string));
    expect(getHeaders['Content-Digest']).toBe(await contentDigest(''));
    expect(postHeaders['Signature-Input']).toMatch(/^sig=\("@method" "@path" "content-digest"\);created=\d+;keyid=/);
    expect(postHeaders['Signature']).toMatch(/^sig=:[A-Za-z0-9+/]{86}==:$/);
  });

  it('sends the public key of the device when it opens a session', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(reply(201, { data: { session_xid: '1', expires_at: '2026-01-01T00:00:00Z' } }));
    vi.stubGlobal('fetch', fetchMock);

    await open.session('device-1');

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as { device_key: string };
    expect(atob(body.device_key)).toHaveLength(32);
  });

  it('sends each step of the delayed recovery to its own path with its own body', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(reply(202, { data: { flags: 2 } }))
      .mockResolvedValueOnce(reply(204, undefined))
      .mockResolvedValueOnce(reply(202, { data: { flags: 2 } }))
      .mockResolvedValueOnce(reply(200, { data: { flags: 130 } }));
    vi.stubGlobal('fetch', fetchMock);
    const token = 'ab'.repeat(32);

    await expect(api.requestRecovery('a@b.c')).resolves.toEqual({ flags: 2 });
    await expect(api.cancelRecovery(token)).resolves.toBeUndefined();
    await expect(api.claimRecovery('a@b.c')).resolves.toEqual({ flags: 2 });
    await expect(api.grantRecovery(token)).resolves.toEqual({ flags: 130 });

    const sent = fetchMock.mock.calls.map(([path, init]) => [
      path,
      (init as RequestInit).method,
      JSON.parse((init as RequestInit).body as string) as unknown,
    ]);
    expect(sent).toEqual([
      ['/v1/recover/request', 'POST', { email: 'a@b.c' }],
      ['/v1/recover/cancel', 'POST', { token }],
      ['/v1/recover/claim', 'POST', { email: 'a@b.c' }],
      ['/v1/recover/grant', 'POST', { token }],
    ]);
  });

  it('throws an ApiError for a wrong grant token', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          reply(401, { error: { status: 401, num: 10021, code: 'AUTHENTICATION_FAILED', message: 'no' } }),
        ),
    );

    await expect(api.grantRecovery('00')).rejects.toMatchObject({ code: 'AUTHENTICATION_FAILED', status: 401 });
  });
});

describe('the session tag', () => {
  it('names the session of the tab in the signature, and the request that opens one names none', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(reply(201, { data: { session_xid: '9', expires_at: '2026-01-01T00:00:00Z' } }))
      .mockResolvedValueOnce(reply(200, { data: { flags: 0, risk_score: 0 } }));
    vi.stubGlobal('fetch', fetchMock);

    await open.session('device-1');
    rememberSession('9');
    await api.session();

    expect(headersOf(fetchMock, 0)['Signature-Input']).not.toContain('tag=');
    expect(headersOf(fetchMock, 1)['Signature-Input']).toMatch(/;nonce="[\w-]{22}";tag="9"$/);
  });
});

describe('a wrong clock', () => {
  it('sends the request once more with the time of the server and a new nonce', async () => {
    const server = Math.floor(Date.now() / 1000) + 3600;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(staleTime(server))
      .mockResolvedValueOnce(reply(200, { data: { flags: 2, risk_score: 0 } }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(api.session()).resolves.toMatchObject({ flags: 2 });

    const created = (call: number) =>
      Number(/created=(\d+)/.exec(headersOf(fetchMock, call)['Signature-Input'] ?? '')?.[1]);
    const nonce = (call: number) => /nonce="([\w-]+)"/.exec(headersOf(fetchMock, call)['Signature-Input'] ?? '')?.[1];
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(Math.abs(created(1) - server)).toBeLessThanOrEqual(2);
    expect(nonce(1)).not.toBe(nonce(0));
  });

  it('keeps the correction for the next requests', async () => {
    const server = Math.floor(Date.now() / 1000) - 3600;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(staleTime(server))
      .mockResolvedValue(reply(200, { data: { flags: 2, risk_score: 0 } }));
    vi.stubGlobal('fetch', fetchMock);

    await api.session();
    await api.session();

    const created = Number(/created=(\d+)/.exec(headersOf(fetchMock, 2)['Signature-Input'] ?? '')?.[1]);
    expect(Math.abs(created - server)).toBeLessThanOrEqual(2);
  });

  it('gives up after one retry and throws the error', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(staleTime(Math.floor(Date.now() / 1000))));
    vi.stubGlobal('fetch', fetchMock);

    await expect(api.session()).rejects.toMatchObject({ code: 'STALE_REQUEST_TIME', status: 401 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not retry another refusal', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        reply(401, { error: { status: 401, num: 1, code: 'INVALID_REQUEST_SIGNATURE', message: 'no' } }),
      );
    vi.stubGlobal('fetch', fetchMock);

    await expect(api.session()).rejects.toMatchObject({ code: 'INVALID_REQUEST_SIGNATURE' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('the devices', () => {
  it('lists the sessions and removes one by its identifier', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(reply(200, { data: { sessions: [{ session_xid: '2', current: false }] } }))
      .mockResolvedValueOnce(reply(204, undefined));
    vi.stubGlobal('fetch', fetchMock);

    await expect(api.sessions()).resolves.toEqual({ sessions: [{ session_xid: '2', current: false }] });
    await expect(api.removeSession('2')).resolves.toBeUndefined();

    const sent = fetchMock.mock.calls.map(([path, init]) => [path, (init as RequestInit).method]);
    expect(sent).toEqual([
      ['/v1/sessions', 'GET'],
      ['/v1/sessions/2', 'DELETE'],
    ]);
  });

  it('removes a passkey in two steps with an assertion for the options of the server', async () => {
    rememberSession('77');
    const options = { publicKey: { challenge: 'abc' } };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(reply(200, { data: options }))
      .mockResolvedValueOnce(reply(204, undefined));
    vi.stubGlobal('fetch', fetchMock);
    const get = vi.spyOn(webauthn, 'getPasskey').mockResolvedValue({ id: 'credential' });

    await api.removePasskey('21');

    expect(get).toHaveBeenCalledWith(options);
    const first = fetchMock.mock.calls[0] as [string, RequestInit];
    const second = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(first[0]).toBe('/v1/passkeys/21/removal');
    expect(first[1].method).toBe('POST');
    expect(second[0]).toBe('/v1/passkeys/21/removal/confirm');
    expect(JSON.parse(second[1].body as string)).toEqual({ response: { id: 'credential' } });
    get.mockRestore();
  });

  it('deletes an account with a passkey in two steps and signs the challenge of the server', async () => {
    rememberSession('77');
    const options = { publicKey: { challenge: 'abc' } };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(reply(200, { data: { method: 'passkey', options } }))
      .mockResolvedValueOnce(reply(204, undefined));
    vi.stubGlobal('fetch', fetchMock);
    const get = vi.spyOn(webauthn, 'getPasskey').mockResolvedValue({ id: 'credential' });

    await api.deleteAccount();

    expect(get).toHaveBeenCalledWith(options);
    const first = fetchMock.mock.calls[0] as [string, RequestInit];
    const second = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(first[0]).toBe('/v1/account/deletion');
    expect(second[0]).toBe('/v1/account/deletion/confirm');
    expect(JSON.parse(second[1].body as string)).toEqual({ response: { id: 'credential' } });
    get.mockRestore();
  });

  it('deletes an account without a passkey after the fresh login and asks for no assertion', async () => {
    rememberSession('77');
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(reply(200, { data: { method: 'fresh_login' } }))
      .mockResolvedValueOnce(reply(204, undefined));
    vi.stubGlobal('fetch', fetchMock);
    const get = vi.spyOn(webauthn, 'getPasskey');

    await api.deleteAccount();

    expect(get).not.toHaveBeenCalled();
    const second = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(JSON.parse(second[1].body as string)).toEqual({});
    get.mockRestore();
  });
});
