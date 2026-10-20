// The device key: a non-exportable Ed25519 key pair in IndexedDB that signs every request of the page.
const databaseName = 'vault-login';
const storeName = 'keys';
const recordKey = 'device';

// Caches the pending or finished lookup of the key pair for the life of the page. Two callers that ask at the same time
// share one lookup, so they cannot create two key pairs. It also keeps the pair when IndexedDB is blocked.
let pending: Promise<CryptoKeyPair> | undefined;

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(storeName);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB did not open.'));
  });
}

async function load(): Promise<CryptoKeyPair | undefined> {
  const database = await openDatabase();
  try {
    return await new Promise<CryptoKeyPair | undefined>((resolve, reject) => {
      const request = database.transaction(storeName).objectStore(storeName).get(recordKey);
      request.onsuccess = () => resolve(request.result as CryptoKeyPair | undefined);
      request.onerror = () => reject(request.error ?? new Error('IndexedDB did not read.'));
    });
  } finally {
    database.close();
  }
}

async function save(pair: CryptoKeyPair): Promise<void> {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(storeName, 'readwrite');
      transaction.objectStore(storeName).put(pair, recordKey);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB did not write.'));
    });
  } finally {
    database.close();
  }
}

/**
 * Returns the Ed25519 key pair of this browser, and creates it on the first call.
 *
 * The private key is not exportable: a script can ask the browser to sign with it, but cannot read it. The pair is kept
 * in IndexedDB, so it outlives the tab. If IndexedDB is not available, the pair lives in memory for the current page
 * only.
 *
 * @returns The key pair that signs the requests of the page.
 */
export function deviceKey(): Promise<CryptoKeyPair> {
  pending ??= findOrCreateKey();
  return pending;
}

// Reads the stored pair, or creates and stores one when there is none.
async function findOrCreateKey(): Promise<CryptoKeyPair> {
  if (typeof indexedDB !== 'undefined') {
    try {
      const stored = await load();
      if (stored) {
        return stored;
      }
    } catch {
      // A browser that blocks IndexedDB keeps the key for this page only.
    }
  }

  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])) as CryptoKeyPair;
  if (typeof indexedDB !== 'undefined') {
    try {
      await save(pair);
    } catch {
      // The key still works until the page closes.
    }
  }

  return pair;
}

/**
 * Encodes bytes as base64url text without padding.
 *
 * @param bytes - The bytes to encode.
 * @returns The base64url text.
 */
export function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Returns the public key of the device, so the server can verify its signatures.
 *
 * @returns The 32 raw bytes of the public key as standard base64 text.
 */
export async function publicKey(): Promise<string> {
  const pair = await deviceKey();
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return btoa(String.fromCharCode(...raw));
}

/**
 * Returns the ID of the device key. The server uses it to find the session of a request.
 *
 * @returns The base64url text, without padding, of the SHA-256 hash of the 32 raw bytes of the public key.
 */
export async function keyId(): Promise<string> {
  const pair = await deviceKey();
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', await crypto.subtle.exportKey('raw', pair.publicKey)),
  );
  return base64url(digest);
}

// The difference in seconds between the clock of the server and the local clock.
let offsetSeconds = 0;

/**
 * Reads the time of the server from the Date header and stores the difference from the local clock.
 *
 * A signed request carries a creation time, and the server accepts only a time close to its own. [now] uses this
 * difference to stay close to the time of the server. If the request fails, the local clock is used as it is.
 */
export async function syncClock(): Promise<void> {
  try {
    const response = await fetch('./', { method: 'HEAD', cache: 'no-store' });
    const date = response.headers.get('Date');
    if (date) {
      offsetSeconds = Math.round((Date.parse(date) - Date.now()) / 1000);
    }
  } catch {
    // Without the header the local clock is used as it is.
  }
}

/**
 * Sets the difference from the clock of the server, from the time that the server reports in a refusal.
 *
 * @param serverTime - The time of the server in Unix seconds.
 */
export function setServerTime(serverTime: number): void {
  offsetSeconds = serverTime - Math.floor(Date.now() / 1000);
}

/**
 * Returns the creation time for a signed request.
 *
 * @returns The current time in Unix seconds, corrected by the difference that [syncClock] or [setServerTime] found.
 */
export function now(): number {
  return Math.floor(Date.now() / 1000) + offsetSeconds;
}
