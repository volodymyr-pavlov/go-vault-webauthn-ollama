// @vitest-environment jsdom
/** Tests for the authenticator of the account. */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/client';
import { Authenticator, cameraMessage, groupCode } from '@/components/Authenticator';
import { useAuth } from '@/store/auth';

const mocks = vi.hoisted(() => ({
  accounts: vi.fn(),
  addAccount: vi.fn(),
  removeAccount: vi.fn(),
}));

vi.mock('@/api/client', async (original) => {
  const real = await original<typeof import('@/api/client')>();
  return {
    ...real,
    api: {
      accounts: mocks.accounts,
      addAccount: mocks.addAccount,
      removeAccount: mocks.removeAccount,
    },
  };
});

vi.mock('@/lib/qr', () => ({ decodeFile: vi.fn(), decodeImage: vi.fn() }));

const github = {
  account_xid: '11',
  issuer: 'GitHub',
  label: 'alice@example.com',
  digits: 6,
  period: 30,
  code: '123456',
  valid_for: 25,
};

beforeEach(() => {
  vi.resetAllMocks();
  mocks.accounts.mockResolvedValue({ accounts: [github] });
  useAuth.setState({ stale: false });
});

afterEach(cleanup);

describe('groupCode', () => {
  it('splits a code in the middle', () => {
    expect(groupCode('123456')).toBe('123 456');
    expect(groupCode('12345678')).toBe('1234 5678');
    expect(groupCode('')).toBe('');
  });
});

describe('cameraMessage', () => {
  it('explains a refused camera in words about the camera, not about a passkey', () => {
    expect(cameraMessage(new DOMException('x', 'NotAllowedError'))).toContain('did not give this page the camera');
    expect(cameraMessage(new DOMException('x', 'NotFoundError'))).toBe('No camera was found on this device.');
    expect(cameraMessage(new DOMException('x', 'NotReadableError'))).toContain('in use by another app');
    expect(cameraMessage(new Error('x'))).toBe('The camera could not start.');
  });
});

describe('Authenticator', () => {
  it('shows the code of each account and the seconds that are left', async () => {
    render(<Authenticator />);

    expect((await screen.findByLabelText('Code for GitHub · alice@example.com')).textContent).toBe('123 456');
    expect(screen.getByText('25 s')).toBeTruthy();
  });

  it('adds a typed secret with its issuer and name', async () => {
    mocks.addAccount.mockResolvedValue({ accounts: [github], skipped: 0 });
    render(<Authenticator />);

    fireEvent.change(await screen.findByLabelText(/Link or secret/), { target: { value: 'JBSWY3DPEHPK3PXP' } });
    fireEvent.change(screen.getByLabelText('Issuer'), { target: { value: 'Example' } });
    fireEvent.change(screen.getByLabelText('Account name'), { target: { value: 'bob' } });
    fireEvent.click(screen.getByRole('button', { name: /Add$/ }));

    await waitFor(() =>
      expect(mocks.addAccount).toHaveBeenCalledWith({
        secret: 'JBSWY3DPEHPK3PXP',
        issuer: 'Example',
        label: 'bob',
      }),
    );
  });

  it('sends a pasted link as a link, and says how many accounts were left out', async () => {
    mocks.addAccount.mockResolvedValue({ accounts: [github], skipped: 2 });
    render(<Authenticator />);

    fireEvent.change(await screen.findByLabelText(/Link or secret/), {
      target: { value: 'otpauth-migration://offline?data=abc' },
    });
    expect(screen.queryByLabelText('Issuer')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /Add$/ }));

    await waitFor(() => expect(mocks.addAccount).toHaveBeenCalledWith({ uri: 'otpauth-migration://offline?data=abc' }));
    expect(await screen.findByText(/2 counter-based accounts were left out/)).toBeTruthy();
  });

  it('removes an account', async () => {
    mocks.removeAccount.mockResolvedValue(undefined);
    render(<Authenticator />);

    fireEvent.click(await screen.findByRole('button', { name: 'Remove GitHub · alice@example.com' }));

    await waitFor(() => expect(mocks.removeAccount).toHaveBeenCalledWith('11'));
  });

  it('marks the state stale when the API asks for a fresh login', async () => {
    mocks.addAccount.mockRejectedValue(
      new ApiError({ status: 401, num: 10016, code: 'STALE_AUTHENTICATION', message: 'A fresh login is needed.' }),
    );
    render(<Authenticator />);

    fireEvent.change(await screen.findByLabelText(/Link or secret/), {
      target: { value: 'otpauth://totp/x?secret=A' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Add$/ }));

    await waitFor(() => expect(useAuth.getState().stale).toBe(true));
  });

  it('shows an account whose secret is missing without a code', async () => {
    mocks.accounts.mockResolvedValue({ accounts: [{ ...github, code: '', unavailable: true }] });
    render(<Authenticator />);

    expect(await screen.findByText(/The secret is missing in Vault/)).toBeTruthy();
    expect(screen.queryByLabelText(/Code for/)).toBeNull();
  });

  it('shows the reason when the camera is refused', async () => {
    Object.defineProperty(navigator, 'mediaDevices', {
      configurable: true,
      value: { getUserMedia: vi.fn().mockRejectedValue(new DOMException('x', 'NotAllowedError')) },
    });
    render(<Authenticator />);

    fireEvent.click(await screen.findByRole('button', { name: /Scan with the camera/ }));

    expect((await screen.findByRole('alert')).textContent).toContain('did not give this page the camera');
  });
});
