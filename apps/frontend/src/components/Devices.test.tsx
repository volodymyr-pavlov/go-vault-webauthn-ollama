// @vitest-environment jsdom
/** Tests for the list of devices of a user. */
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/client';
import { Devices } from '@/components/Devices';
import { useAuth } from '@/store/auth';

const mocks = vi.hoisted(() => ({
  sessions: vi.fn(),
  removeSession: vi.fn(),
}));

vi.mock('@/api/client', async (original) => {
  const real = await original<typeof import('@/api/client')>();
  return { ...real, api: { sessions: mocks.sessions, removeSession: mocks.removeSession } };
});

const here = {
  session_xid: '1',
  country: 'DE',
  created_at: '2030-01-01T10:00:00Z',
  last_seen_at: '2030-01-02T10:00:00Z',
  current: true,
};

const elsewhere = {
  session_xid: '2',
  created_at: '2030-02-01T10:00:00Z',
  last_seen_at: '2030-02-02T10:00:00Z',
  current: false,
};

beforeEach(() => {
  vi.resetAllMocks();
  mocks.sessions.mockResolvedValue({ sessions: [here, elsewhere] });
  useAuth.setState({ stale: false });
});

afterEach(cleanup);

describe('Devices', () => {
  it('lists the sessions, marks this device and offers Remove for the others only', async () => {
    render(<Devices />);

    const current = (await screen.findByText(/This device/)).closest('li') as HTMLElement;
    expect(current.textContent).toContain('DE');
    expect(current.textContent).toContain(new Date(here.last_seen_at).toLocaleString());
    expect(within(current).queryByRole('button')).toBeNull();

    const other = screen.getByText(/Unknown country/).closest('li') as HTMLElement;
    expect(other.textContent).toContain(new Date(elsewhere.created_at).toLocaleString());
    expect(within(other).getByRole('button', { name: /Remove/ })).toBeTruthy();
  });

  it('removes another session and reads the list again', async () => {
    mocks.removeSession.mockResolvedValue(undefined);
    render(<Devices />);

    mocks.sessions.mockResolvedValue({ sessions: [here] });
    fireEvent.click(await screen.findByRole('button', { name: /Remove/ }));

    await waitFor(() => expect(screen.queryByText(/Unknown country/)).toBeNull());
    expect(mocks.removeSession).toHaveBeenCalledWith('2');
  });

  it('marks the state stale when the API asks for a fresh login', async () => {
    mocks.removeSession.mockRejectedValue(
      new ApiError({ status: 403, num: 10016, code: 'STALE_AUTHENTICATION', message: 'A fresh login is needed.' }),
    );
    render(<Devices />);

    fireEvent.click(await screen.findByRole('button', { name: /Remove/ }));

    expect((await screen.findByRole('alert')).textContent).toContain('Log in again to do this');
    expect(useAuth.getState().stale).toBe(true);
  });

  it('shows the failure of the list', async () => {
    mocks.sessions.mockRejectedValue(
      new ApiError({ status: 429, num: 10025, code: 'TOO_MANY_REQUESTS', message: 'Too many.' }),
    );
    render(<Devices />);

    expect((await screen.findByRole('alert')).textContent).toBe('Too many tries. Wait a moment and try again.');
  });
});
