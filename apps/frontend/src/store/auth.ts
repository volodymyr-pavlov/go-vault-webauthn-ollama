import { create } from 'zustand';
import { ApiError, api, open } from '@/api/client';
import type { Decision } from '@/api/types';
import { deviceId } from '@/lib/device';
import { syncClock } from '@/lib/deviceKey';
import { forgetSession, rememberSession, sessionXid } from '@/lib/sessionId';

/** The state of the session of the device key, with the actions that change it. */
interface AuthState {
  /** True once the session of the device key is known. */
  ready: boolean;
  /** The set of session flag bits. See [Flag]. */
  flags: number;
  /** The identifier of the account, or empty. */
  userXid: string;
  /** The result of the last risk check, or empty. */
  decision: Decision | '';
  /** The risk score of the session. */
  riskScore: number;
  /** The time when the session ends, in RFC 3339 format. */
  expiresAt: string;
  /** True after the API said that a sensitive action needs a fresh login. */
  stale: boolean;

  /** Continues the session of this tab, or opens a new one when the tab has none or the server does not know it. */
  start: () => Promise<void>;
  /**
   * Runs a step of the API. It marks the state stale when the API asks for a fresh login, and passes on every error.
   *
   * @param step - The call to run.
   * @returns The result of the step.
   */
  call: <T>(step: () => Promise<T>) => Promise<T>;
  /** Reads the state of the session from the server. */
  sync: () => Promise<void>;
  /**
   * Stores the decision and the account from a login answer, and clears the stale mark.
   *
   * @param decision - The result of the risk check.
   * @param userXid - The identifier of the account.
   */
  note: (decision: Decision, userXid: string) => void;
  /**
   * Opens a new session.
   *
   * @param revoke - If true, the store first logs out of the current session and ignores a failure.
   */
  restart: (revoke: boolean) => Promise<void>;
}

// The error codes that mean the server has no session for the identifier of the tab.
const missingSession = new Set(['NOT_FOUND_SESSION', 'UNAUTHORIZED_SESSION']);

/**
 * The store of the session state. The store keeps no token: the device key signs each request, and the signature names
 * the session of the tab.
 */
export const useAuth = create<AuthState>()((set, get) => {
  // Opens a new session and resets the state.
  const fresh = async (): Promise<void> => {
    const opened = await open.session(deviceId());
    rememberSession(opened.session_xid);
    set({ flags: 0, userXid: '', decision: '', riskScore: 0, expiresAt: opened.expires_at, stale: false });
  };

  // The start that is running now. StrictMode runs the effect of the App twice, and both runs share one start, so
  // only one session opens.
  let starting: Promise<void> | undefined;

  const begin = async (): Promise<void> => {
    await syncClock();
    if (sessionXid() === '') {
      await fresh();
    } else {
      try {
        await get().sync();
      } catch (error) {
        if (!(error instanceof ApiError) || !(missingSession.has(error.code) || error.status === 404)) {
          throw error;
        }

        forgetSession();
        await fresh();
      }
    }

    set({ ready: true });
  };

  return {
    ready: false,
    flags: 0,
    userXid: '',
    decision: '',
    riskScore: 0,
    expiresAt: '',
    stale: false,

    start: () => {
      starting ??= begin().finally(() => {
        starting = undefined;
      });

      return starting;
    },

    call: async <T>(step: () => Promise<T>): Promise<T> => {
      try {
        return await step();
      } catch (error) {
        if (error instanceof ApiError && error.code === 'STALE_AUTHENTICATION') {
          set({ stale: true });
        }

        throw error;
      }
    },

    sync: async () => {
      const state = await get().call(() => api.session());
      set({
        flags: state.flags,
        userXid: state.user_xid ?? '',
        riskScore: state.risk_score,
        expiresAt: state.expires_at,
        stale: false,
      });
    },

    note: (decision, userXid) => set({ decision, userXid, stale: false }),

    restart: async (revoke) => {
      if (revoke) {
        try {
          await api.logout();
        } catch {
          // A session that is gone already needs no logout.
        }
      }

      forgetSession();

      await fresh();
    },
  };
});
