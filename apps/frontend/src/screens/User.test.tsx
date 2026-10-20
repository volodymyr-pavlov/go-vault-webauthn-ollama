// @vitest-environment jsdom
/** Tests for the tabs of the screen of a logged-in user. */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { User } from '@/screens/User';
import { useAuth } from '@/store/auth';

// Each tab has its own tests. Here the parts only show which one is open.
vi.mock('@/components/Authenticator', () => ({ Authenticator: () => <p>codes tab</p> }));
vi.mock('@/screens/Security', () => ({ Security: () => <p>security tab</p> }));
vi.mock('@/screens/Data', () => ({
  Data: ({ deleted }: { deleted: () => void }) => (
    <button type="button" onClick={deleted}>
      data tab
    </button>
  ),
}));
vi.mock('@/components/StepUp', () => ({ StepUp: () => <p>fresh login prompt</p> }));

beforeEach(() => {
  useAuth.setState({ stale: false, decision: '', flags: 0 });
});

afterEach(cleanup);

describe('User', () => {
  it('opens the codes first and shows one tab at a time', () => {
    render(<User loggedOut={vi.fn()} />);

    expect(screen.getByRole('tab', { name: 'Codes' }).getAttribute('aria-selected')).toBe('true');
    expect(screen.getByText('codes tab')).toBeTruthy();
    expect(screen.queryByText('security tab')).toBeNull();

    fireEvent.click(screen.getByRole('tab', { name: 'Security' }));

    expect(screen.getByRole('tab', { name: 'Security' }).getAttribute('aria-selected')).toBe('true');
    expect(screen.getByText('security tab')).toBeTruthy();
    expect(screen.queryByText('codes tab')).toBeNull();

    fireEvent.click(screen.getByRole('tab', { name: 'Data' }));

    expect(screen.getByText('data tab')).toBeTruthy();
  });

  it('keeps the prompt for a fresh login above every tab', () => {
    useAuth.setState({ stale: true });
    render(<User loggedOut={vi.fn()} />);

    expect(screen.getByText('fresh login prompt')).toBeTruthy();

    fireEvent.click(screen.getByRole('tab', { name: 'Data' }));

    expect(screen.getByText('fresh login prompt')).toBeTruthy();
  });

  it('goes back to the login view after the data is deleted', async () => {
    const loggedOut = vi.fn();
    render(<User loggedOut={loggedOut} />);

    fireEvent.click(screen.getByRole('tab', { name: 'Data' }));
    fireEvent.click(screen.getByRole('button', { name: 'data tab' }));

    await waitFor(() => expect(loggedOut).toHaveBeenCalled());
  });
});
