const key = 'vault-login.device';

/**
 * Returns the identifier that this browser keeps for itself, and sends it when a session opens.
 *
 * It creates and stores a new identifier on the first call. If localStorage is not available, it returns a new
 * identifier on every call.
 *
 * @returns The device identifier.
 */
export function deviceId(): string {
  try {
    const stored = localStorage.getItem(key);
    if (stored) {
      return stored;
    }

    const fresh = crypto.randomUUID();
    localStorage.setItem(key, fresh);
    return fresh;
  } catch {
    return crypto.randomUUID();
  }
}
