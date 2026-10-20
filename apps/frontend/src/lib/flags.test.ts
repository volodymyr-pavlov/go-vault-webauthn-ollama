/** Tests for the session flag helpers. */
import { describe, expect, it } from 'vitest';
import { Flag, canEnroll, has } from '@/lib/flags';

describe('flags', () => {
  it('reads a bit', () => {
    expect(has(Flag.Started | Flag.Authorized, Flag.Authorized)).toBe(true);
    expect(has(Flag.Started, Flag.Authorized)).toBe(false);
  });

  it('lets a verified registration and a recovery enroll, and an authorized session not', () => {
    expect(canEnroll(Flag.Started | Flag.RegistryVerified)).toBe(true);
    expect(canEnroll(Flag.Started | Flag.RecoveryApproved)).toBe(true);
    expect(canEnroll(Flag.Started | Flag.RegistryVerified | Flag.Authorized)).toBe(false);
    expect(canEnroll(Flag.Started)).toBe(false);
  });
});
