// @vitest-environment jsdom
/** Tests for the identifier of the session of a tab. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { forgetSession, rememberSession, sessionXid } from '@/lib/sessionId';

afterEach(() => {
  forgetSession();
  vi.unstubAllGlobals();
});

describe('the session identifier of a tab', () => {
  it('is empty before a session opens', () => {
    expect(sessionXid()).toBe('');
  });

  it('is kept in sessionStorage and not in localStorage', () => {
    rememberSession('77');

    expect(sessionXid()).toBe('77');
    expect(sessionStorage.length).toBe(1);
    expect(localStorage.length).toBe(0);
  });

  it('is forgotten after a logout', () => {
    rememberSession('77');
    forgetSession();

    expect(sessionXid()).toBe('');
    expect(sessionStorage.length).toBe(0);
  });

  it('falls back to memory when sessionStorage is not available', () => {
    const blocked = {
      getItem: () => {
        throw new DOMException('blocked', 'SecurityError');
      },
      setItem: () => {
        throw new DOMException('blocked', 'SecurityError');
      },
      removeItem: () => {
        throw new DOMException('blocked', 'SecurityError');
      },
    };
    vi.stubGlobal('sessionStorage', blocked);

    rememberSession('88');
    expect(sessionXid()).toBe('88');
    forgetSession();
    expect(sessionXid()).toBe('');
  });
});
