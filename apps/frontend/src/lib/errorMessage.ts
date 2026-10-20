/** Texts for the errors that the page shows. */
import { ApiError } from '@/api/client';

const messages: Record<string, string> = {
  AUTHENTICATION_FAILED: 'That did not work. Check what you typed and try again.',
  PASSKEY_USER: 'You use a passkey. Log in with it instead.',
  RISK_DENIED: 'The login was refused. Contact support if this is you.',
  STALE_AUTHENTICATION: 'Log in again to do this. A sensitive action needs a fresh login.',
  LAST_FACTOR: 'The last factor cannot be removed. Add another one first.',
  STALE_REQUEST_TIME: 'The clock of this device is wrong. Set the clock and try again.',
  TOO_MANY_REQUESTS: 'Too many tries. Wait a moment and try again.',
  MIN_LEN_BODY_PASSWORD: 'The password needs at least 10 characters.',
  MALFORMED_BODY_EMAIL: 'That does not look like an email address.',
  MALFORMED_BODY_CODE: 'A code has the wrong shape. Check it and try again.',
  MALFORMED_BODY_TOKEN: 'The token has 64 hex digits. Check it and try again.',
  FORBIDDEN_ORIGIN: 'This page is not allowed to call the service.',
};

/**
 * Turns any thrown value into a sentence for the person at the screen.
 *
 * An [ApiError] with a known code gets the text from a fixed list, and any other [ApiError] keeps its own message. A
 * passkey step that the person cancelled gets a short explanation. A value that is not an error gets a general
 * sentence.
 *
 * @param error - The value that was thrown.
 * @returns The text to show.
 */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return messages[error.code] ?? error.message;
  }

  if (error instanceof DOMException) {
    if (error.name === 'NotAllowedError') {
      return 'The passkey step was cancelled or timed out.';
    }

    if (error.name === 'InvalidStateError') {
      return 'This device already has a passkey for you.';
    }

    return error.message || 'The passkey step failed.';
  }

  if (error instanceof Error) {
    return error.message;
  }

  return 'Something went wrong. Try again.';
}
