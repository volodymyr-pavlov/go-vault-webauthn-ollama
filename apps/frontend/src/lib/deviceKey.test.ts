// @vitest-environment jsdom
/** Tests for the device key. */
import { describe, expect, it, vi } from 'vitest';
import { deviceKey } from '@/lib/deviceKey';

describe('deviceKey', () => {
  it('creates one key pair for callers that ask at the same time', async () => {
    const generateKey = vi.spyOn(crypto.subtle, 'generateKey');

    const [first, second] = await Promise.all([deviceKey(), deviceKey()]);

    expect(first).toBe(second);
    expect(generateKey).toHaveBeenCalledTimes(1);
  });
});
