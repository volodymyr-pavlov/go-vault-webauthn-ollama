/** Tests for [errorMessage]. */
import { describe, expect, it } from 'vitest';
import { ApiError } from '@/api/client';
import { errorMessage } from '@/lib/errorMessage';

function refusal(code: string, message: string): ApiError {
  return new ApiError({ status: 401, num: 1, code, message });
}

describe('errorMessage', () => {
  it('uses the text for a known code', () => {
    expect(errorMessage(refusal('AUTHENTICATION_FAILED', 'raw'))).toContain('Check what you typed');
  });

  it('tells the person to set the clock', () => {
    expect(errorMessage(refusal('STALE_REQUEST_TIME', 'raw'))).toBe(
      'The clock of this device is wrong. Set the clock and try again.',
    );
  });

  it('falls back to the message of the server', () => {
    expect(errorMessage(refusal('SOMETHING_NEW', 'The server says no.'))).toBe('The server says no.');
  });

  it('explains a cancelled passkey step', () => {
    expect(errorMessage(new DOMException('x', 'NotAllowedError'))).toContain('cancelled');
  });

  it('copes with a value that is not an error', () => {
    expect(errorMessage('boom')).toBe('Something went wrong. Try again.');
  });
});
