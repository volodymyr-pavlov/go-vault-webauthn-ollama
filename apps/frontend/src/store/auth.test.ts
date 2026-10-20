// @vitest-environment jsdom
/** Tests for the session store. */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const opened = vi.hoisted(() => vi.fn());

vi.mock('@/api/client', () => ({
  ApiError: class ApiError extends Error {},
  api: { session: vi.fn() },
  open: { session: opened },
}));
vi.mock('@/lib/deviceKey', () => ({ syncClock: vi.fn(async () => undefined) }));

import { forgetSession } from '@/lib/sessionId';
import { useAuth } from '@/store/auth';

beforeEach(() => {
  forgetSession();
  opened.mockReset();
  opened.mockResolvedValue({ session_xid: '77', expires_at: '2030-01-01T00:00:00Z' });
});

describe('start', () => {
  it('opens one session when it runs twice at the same time', async () => {
    const { start } = useAuth.getState();

    await Promise.all([start(), start()]);

    expect(opened).toHaveBeenCalledTimes(1);
    expect(useAuth.getState().ready).toBe(true);
  });
});
