// The identifier of the session of this tab. Tabs share the device key but not the session, so the identifier lives in
// sessionStorage, which each tab has for itself and which a reload keeps.
const key = 'vault-login.session';

// Holds the identifier when sessionStorage is not available, for the life of the page.
let memory = '';

/**
 * Returns the identifier of the session of this tab.
 *
 * @returns The session XID, or an empty string if the tab has no session yet.
 */
export function sessionXid(): string {
  try {
    return sessionStorage.getItem(key) ?? memory;
  } catch {
    return memory;
  }
}

/**
 * Stores the identifier of the session of this tab, so a reload of the tab continues the session.
 *
 * @param xid - The session XID that the server returned.
 */
export function rememberSession(xid: string): void {
  memory = xid;
  try {
    sessionStorage.setItem(key, xid);
  } catch {
    // Without sessionStorage the identifier lives in memory, until the tab reloads.
  }
}

/** Forgets the identifier of the session of this tab, for example after a logout. */
export function forgetSession(): void {
  memory = '';
  try {
    sessionStorage.removeItem(key);
  } catch {
    // Nothing is stored, so there is nothing to remove.
  }
}
