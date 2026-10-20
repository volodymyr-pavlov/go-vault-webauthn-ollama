/** Tests for the HTTP message signature code, including the example from RFC 9421 appendix B.2.6. */
import { describe, expect, it } from 'vitest';
import { deviceKey, keyId } from '@/lib/deviceKey';
import { contentDigest, signRequest, signatureBase } from '@/lib/httpsig';

function bytes(text: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
}

function fromBase64url(text: string): Uint8Array<ArrayBuffer> {
  return bytes(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));
}

describe('RFC 9421 appendix B.2.6', () => {
  const components = ['date', '@method', '@path', '@authority', 'content-type', 'content-length'];
  const params =
    '("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"';
  const values: Record<string, string> = {
    date: 'Tue, 20 Apr 2021 02:07:55 GMT',
    '@method': 'POST',
    '@path': '/foo',
    '@authority': 'example.com',
    'content-type': 'application/json',
    'content-length': '18',
  };
  const expected = [
    '"date": Tue, 20 Apr 2021 02:07:55 GMT',
    '"@method": POST',
    '"@path": /foo',
    '"@authority": example.com',
    '"content-type": application/json',
    '"content-length": 18',
    `"@signature-params": ${params}`,
  ].join('\n');
  const signature = 'wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==';

  it('builds the expected signature base', () => {
    expect(signatureBase(components, params, (component) => values[component] ?? '')).toBe(expected);
  });

  it('verifies the official signature', async () => {
    const key = await crypto.subtle.importKey(
      'raw',
      fromBase64url('JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs'),
      { name: 'Ed25519' },
      false,
      ['verify'],
    );

    await expect(
      crypto.subtle.verify({ name: 'Ed25519' }, key, bytes(signature), new TextEncoder().encode(expected)),
    ).resolves.toBe(true);
  });
});

describe('contentDigest', () => {
  it('hashes the empty body', async () => {
    await expect(contentDigest('')).resolves.toBe('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:');
  });
});

describe('signRequest', () => {
  const pattern =
    /^sig=\("@method" "@path" "content-digest"\);created=(\d+);keyid="([\w-]+)";alg="ed25519";nonce="([\w-]{22})"$/;

  it('signs the base that the headers describe', async () => {
    const body = '{"a":1}';
    const signed = await signRequest('post', '/v1/x', body);
    const match = pattern.exec(signed.signatureInput);
    expect(match).not.toBeNull();

    const params = signed.signatureInput.slice('sig='.length);
    const base = [
      '"@method": POST',
      '"@path": /v1/x',
      `"content-digest": ${await contentDigest(body)}`,
      `"@signature-params": ${params}`,
    ].join('\n');
    const raw = /^sig=:([A-Za-z0-9+/]{86}==):$/.exec(signed.signature)?.[1] ?? '';
    const pair = await deviceKey();

    expect(signed.contentDigest).toBe(await contentDigest(body));
    await expect(
      crypto.subtle.verify({ name: 'Ed25519' }, pair.publicKey, bytes(raw), new TextEncoder().encode(base)),
    ).resolves.toBe(true);
  });

  it('names the session in a last tag parameter, and names none when it has no tag', async () => {
    const tagged = await signRequest('GET', '/v1/session', '', '123');
    const open = await signRequest('POST', '/v1/session', '{}');

    expect(tagged.signatureInput).toMatch(/;nonce="[\w-]{22}";tag="123"$/);
    expect(open.signatureInput).not.toContain('tag=');
  });

  it('names the key by the SHA-256 of its public key', async () => {
    const pair = await deviceKey();
    const digest = await crypto.subtle.digest('SHA-256', await crypto.subtle.exportKey('raw', pair.publicKey));
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const signed = await signRequest('GET', '/v1/session', '');

    expect(await keyId()).toBe(expected);
    expect(pattern.exec(signed.signatureInput)?.[2]).toBe(expected);
  });

  it('uses a new nonce for every call', async () => {
    const first = await signRequest('GET', '/v1/session', '');
    const second = await signRequest('GET', '/v1/session', '');

    expect(pattern.exec(first.signatureInput)?.[3]).not.toBe(pattern.exec(second.signatureInput)?.[3]);
  });
});
