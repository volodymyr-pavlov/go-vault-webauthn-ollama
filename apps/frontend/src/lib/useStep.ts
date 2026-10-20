/** A hook that tracks one action of a form. */
import { useCallback, useState } from 'react';
import { ApiError } from '@/api/client';
import { errorMessage } from '@/lib/errorMessage';

/** The state of one action of a form, with the functions to run and reset it. */
export interface Step {
  /** True while the action runs. */
  busy: boolean;
  /** The message for the person after a failure, or an empty string. */
  error: string;
  /** The code of the API refusal behind the error, or an empty string. */
  code: string;
  /**
   * Calls work and stores its failure as a message.
   *
   * @param work - The action to run.
   * @returns True when work passes and false when it fails.
   */
  run: (work: () => Promise<void>) => Promise<boolean>;
  /** Removes the error and its code. */
  clear: () => void;
}

/**
 * Tracks one action of a form, so the form can disable its button while the action runs and show why it failed.
 *
 * @returns The [Step] state of the action.
 */
export function useStep(): Step {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [code, setCode] = useState('');

  const run = useCallback(async (work: () => Promise<void>): Promise<boolean> => {
    setBusy(true);
    setError('');
    setCode('');
    try {
      await work();
      return true;
    } catch (failure) {
      setError(errorMessage(failure));
      setCode(failure instanceof ApiError ? failure.code : '');
      return false;
    } finally {
      setBusy(false);
    }
  }, []);

  const clear = useCallback(() => {
    setError('');
    setCode('');
  }, []);

  return { busy, error, code, run, clear };
}
