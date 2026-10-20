// @vitest-environment jsdom
/** Tests for the login screen and its wait for the risk check. */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Login } from '@/screens/Login';
import { useAuth } from '@/store/auth';

const mocks = vi.hoisted(() => ({
  beginLogin: vi.fn(),
  completeLogin: vi.fn(),
  password: vi.fn(),
  totp: vi.fn(),
  getPasskey: vi.fn(),
}));

vi.mock('@/api/client', async (original) => {
  const real = await original<typeof import('@/api/client')>();
  return {
    ...real,
    api: {
      beginLogin: mocks.beginLogin,
      completeLogin: mocks.completeLogin,
      password: mocks.password,
      totp: mocks.totp,
      session: vi.fn().mockResolvedValue({ session_xid: '1', flags: 0, risk_score: 0, expires_at: '' }),
    },
  };
});

vi.mock('@/lib/webauthn', () => ({
  getPasskey: mocks.getPasskey,
  createPasskey: vi.fn(),
  supported: () => true,
}));

beforeEach(() => {
  vi.resetAllMocks();
  mocks.beginLogin.mockResolvedValue({ publicKey: {} });
  mocks.getPasskey.mockResolvedValue({ id: 'assertion' });
  useAuth.setState({ flags: 0 });
});

afterEach(cleanup);

describe('Login', () => {
  it('says that the risk check takes seconds while the server answers a passkey login', async () => {
    let answer: (value: unknown) => void = () => undefined;
    mocks.completeLogin.mockReturnValue(
      new Promise((resolve) => {
        answer = resolve;
      }),
    );
    render(<Login notice="" />);

    expect(screen.queryByRole('status')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: /Log in with a passkey/ }));

    expect((await screen.findByRole('status')).textContent).toContain('Checking your login for risks');
    expect(screen.getByRole('button', { name: /Log in with a passkey/ }).getAttribute('aria-busy')).toBe('true');

    answer({ flags: 2, decision: 'allow', user_xid: '9' });

    await waitFor(() => expect(screen.queryByRole('status')).toBeNull());
  });

  it('does not show the wait while the browser asks for the passkey', async () => {
    mocks.getPasskey.mockReturnValue(new Promise(() => undefined));
    render(<Login notice="" />);

    fireEvent.click(screen.getByRole('button', { name: /Log in with a passkey/ }));

    await waitFor(() => expect(mocks.getPasskey).toHaveBeenCalled());
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('hides the wait again when the login fails', async () => {
    mocks.completeLogin.mockRejectedValue(new Error('No.'));
    render(<Login notice="" />);

    fireEvent.click(screen.getByRole('button', { name: /Log in with a passkey/ }));

    expect((await screen.findByRole('alert')).textContent).toContain('No.');
    expect(screen.queryByRole('status')).toBeNull();
  });
});
