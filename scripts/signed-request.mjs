// Sends one request to the API, signed the way the page signs it (RFC 9421 with the Content-Digest field of RFC 9530).
// The device key lives in .bin/device.pem and is made on the first run. The key signs every request, so there is no
// token to pass. A successful POST /v1/session saves the session_xid in .bin/session, and every later request names that
// session in the tag parameter of its signature. The SESSION_XID environment variable overrides the file. Usage:
//
//   node scripts/signed-request.mjs METHOD PATH [JSON-BODY]
//
// A POST /v1/session body gets the device_key of the device added. The API address is API_URL, http://127.0.0.1:8080
// by default.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const [method, path, rawBody = ''] = process.argv.slice(2);
if (!method || !path) {
  console.error('usage: node scripts/signed-request.mjs METHOD PATH [JSON-BODY]');
  process.exit(2);
}

const keyFile = '.bin/device.pem';
const sessionFile = '.bin/session';
const opensSession = method === 'POST' && path === '/v1/session';
if (!existsSync(keyFile)) {
  mkdirSync('.bin', { recursive: true });
  const { privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
}

const privateKey = createPrivateKey(readFileSync(keyFile));
const publicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).subarray(-32);

let body = rawBody;
if (opensSession && body) {
  body = JSON.stringify({ ...JSON.parse(body), device_key: publicKey.toString('base64') });
}

const contentDigest = `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
const keyId = createHash('sha256').update(publicKey).digest('base64url');
const nonce = randomBytes(16).toString('base64url');
const created = Math.floor(Date.now() / 1000);
const sessionXid = opensSession
  ? ''
  : (process.env.SESSION_XID ?? (existsSync(sessionFile) ? readFileSync(sessionFile, 'utf8').trim() : ''));
const tag = sessionXid ? `;tag="${sessionXid}"` : '';
const params = `("@method" "@path" "content-digest");created=${created};keyid="${keyId}";alg="ed25519";nonce="${nonce}"${tag}`;
const base = [
  `"@method": ${method}`,
  `"@path": ${path}`,
  `"content-digest": ${contentDigest}`,
  `"@signature-params": ${params}`,
].join('\n');

const response = await fetch((process.env.API_URL ?? 'http://127.0.0.1:8080') + path, {
  method,
  headers: {
    'Content-Type': 'application/json',
    'User-Agent': 'signed-request',
    'Content-Digest': contentDigest,
    'Signature-Input': `sig=${params}`,
    Signature: `sig=:${sign(null, Buffer.from(base), privateKey).toString('base64')}:`,
  },
  body: body === '' ? null : body,
});
const text = await response.text();
if (opensSession && response.status === 201) {
  const xid = JSON.parse(text).data?.session_xid;
  if (xid) {
    writeFileSync(sessionFile, `${xid}\n`);
  }
}
console.log(response.status, text);
process.exitCode = response.ok ? 0 : 1;
