// @vitest-environment jsdom
/** Tests for the fresh login prompt and the way the User screen shows it. */
import type { Decision } from '@/api/types';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/client';
import { StepUp } from '@/components/StepUp';
import { Flag } from '@/lib/flags';
import { User } from '@/screens/User';
import { useAuth } from '@/store/auth';

const mocks = vi.hoisted(() => ({
  beginLogin: vi.fn(),
  completeLogin: vi.fn(),
  session: vi.fn(),
  passkeys: vi.fn(),
  sessions: vi.fn(),
  removePasskey: vi.fn(),
  removeTOTP: vi.fn(),
  logout: vi.fn(),
  getPasskey: vi.fn(),
}));

vi.mock('@/api/client', async (original) => {
  const real = await original<typeof import('@/api/client')>();
  return {
    ...real,
    api: {
      beginLogin: mocks.beginLogin,
      completeLogin: mocks.completeLogin,
      session: mocks.session,
      passkeys: mocks.passkeys,
      sessions: mocks.sessions,
      removePasskey: mocks.removePasskey,
      removeTOTP: mocks.removeTOTP,
      logout: mocks.logout,
    },
  };
});

vi.mock('@/lib/webauthn', () => ({
  getPasskey: mocks.getPasskey,
  createPasskey: vi.fn(),
  supported: () => true,
}));

// The recovery codes and the authenticator app have their own tests. Here they only fill the screen.
vi.mock('@/components/RecoveryCodes', () => ({ RecoveryCodes: () => null }));
vi.mock('@/components/TotpSetup', () => ({ TotpSetup: () => null }));
vi.mock('@/components/PasskeyAdd', () => ({ PasskeyAdd: () => null }));
vi.mock('@/components/Authenticator', () => ({ Authenticator: () => null }));

const stale = new ApiError({
  status: 403,
  num: 10016,
  code: 'STALE_AUTHENTICATION',
  message: 'A fresh login is needed.',
});

const sessionState = {
  session_xid: '1',
  flags: Flag.Authorized,
  user_xid: '42',
  risk_score: 7,
  expires_at: '2030-01-01T00:00:00Z',
};

const passkey = {
  passkey_xid: '5',
  name: 'Laptop',
  transports: ['internal'],
  backed_up: false,
  disabled: false,
  created_at: '2030-01-01T00:00:00Z',
};

beforeEach(() => {
  vi.resetAllMocks();
  mocks.session.mockResolvedValue(sessionState);
  mocks.passkeys.mockResolvedValue({ passkeys: [passkey] });
  mocks.sessions.mockResolvedValue({ sessions: [] });
  useAuth.setState({ flags: Flag.Authorized, userXid: '42', decision: 'allow', riskScore: 7, stale: false });
});

afterEach(cleanup);

describe('StepUp', () => {
  it('logs in again with the passkey and clears the stale mark', async () => {
    mocks.beginLogin.mockResolvedValue({ publicKey: {} });
    mocks.getPasskey.mockResolvedValue({ id: 'assertion' });
    mocks.completeLogin.mockResolvedValue({ flags: Flag.Authorized, decision: 'allow', user_xid: '42' });
    useAuth.setState({ stale: true });

    render(<StepUp />);
    expect(screen.getByText(/This change needs a fresh login/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /Confirm with a passkey/ }));

    await waitFor(() => expect(useAuth.getState().stale).toBe(false));
    expect(mocks.completeLogin).toHaveBeenCalledWith({ id: 'assertion' });
    expect(mocks.session).toHaveBeenCalled();
  });

  it('shows the refusal and reads the session again when the login fails', async () => {
    mocks.beginLogin.mockResolvedValue({ publicKey: {} });
    mocks.getPasskey.mockResolvedValue({ id: 'assertion' });
    mocks.completeLogin.mockRejectedValue(
      new ApiError({ status: 401, num: 10017, code: 'AUTHENTICATION_FAILED', message: 'No.' }),
    );

    render(<StepUp />);
    fireEvent.click(screen.getByRole('button', { name: /Confirm with a passkey/ }));

    expect((await screen.findByRole('alert')).textContent).toContain('That did not work.');
    expect(mocks.session).toHaveBeenCalled();
  });

  it('explains a passkey step that the person cancelled', async () => {
    mocks.beginLogin.mockResolvedValue({ publicKey: {} });
    mocks.getPasskey.mockRejectedValue(new DOMException('cancelled', 'NotAllowedError'));

    render(<StepUp />);
    fireEvent.click(screen.getByRole('button', { name: /Confirm with a passkey/ }));

    expect((await screen.findByRole('alert')).textContent).toContain('cancelled or timed out');
    expect(mocks.completeLogin).not.toHaveBeenCalled();
  });
});

describe('User', () => {
  it('shows the prompt after the API asks for a fresh login', async () => {
    mocks.removePasskey.mockRejectedValue(stale);
    render(<User loggedOut={vi.fn()} />);
    fireEvent.click(await screen.findByRole('tab', { name: 'Security' }));
    expect(screen.queryByText(/This change needs a fresh login/)).toBeNull();

    fireEvent.click(await screen.findByRole('button', { name: /Remove$/ }));

    expect(await screen.findByText(/This change needs a fresh login/)).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toContain('Log in again to do this');
    expect(useAuth.getState().stale).toBe(true);
  });

  it('shows the prompt after removing the authenticator app needs a fresh login', async () => {
    mocks.removeTOTP.mockRejectedValue(stale);
    render(<User loggedOut={vi.fn()} />);
    fireEvent.click(await screen.findByRole('tab', { name: 'Security' }));

    fireEvent.click(await screen.findByRole('button', { name: 'Remove the authenticator app' }));

    expect(await screen.findByText(/This change needs a fresh login/)).toBeTruthy();
  });

  it('shows the last factor refusal', async () => {
    mocks.removePasskey.mockRejectedValue(
      new ApiError({ status: 409, num: 10021, code: 'LAST_FACTOR', message: 'Last factor.' }),
    );
    render(<User loggedOut={vi.fn()} />);
    fireEvent.click(await screen.findByRole('tab', { name: 'Security' }));

    fireEvent.click(await screen.findByRole('button', { name: /Remove$/ }));

    expect((await screen.findByRole('alert')).textContent).toBe(
      'The last factor cannot be removed. Add another one first.',
    );
  });

  it.each<[Decision, string]>([
    ['allow', 'The login was allowed.'],
    ['limit', 'The login was limited. A sensitive action needs a fresh login first.'],
    ['review', 'The login was flagged for review.'],
  ])('shows the sentence for the %s decision', async (decision, sentence) => {
    useAuth.setState({ decision });
    render(<User loggedOut={vi.fn()} />);

    expect(await screen.findByText(sentence)).toBeTruthy();
  });

  it('asks for a fresh login before a sensitive change when the session is limited', async () => {
    useAuth.setState({ flags: Flag.Authorized | Flag.Limited });
    render(<User loggedOut={vi.fn()} />);

    expect(await screen.findByText('Log in again before a sensitive change.')).toBeTruthy();
  });

  it('logs out and opens a new session', async () => {
    const loggedOut = vi.fn();
    const restart = vi.fn().mockResolvedValue(undefined);
    useAuth.setState({ restart });
    render(<User loggedOut={loggedOut} />);

    fireEvent.click(await screen.findByRole('button', { name: /Log out/ }));

    await waitFor(() => expect(loggedOut).toHaveBeenCalled());
    expect(restart).toHaveBeenCalledWith(true);
  });
});
