import { KeyRound } from 'lucide-react';
import { api } from '@/api/client';
import { Button, Notice } from '@/components/ui';
import { useStep } from '@/lib/useStep';
import { getPasskey } from '@/lib/webauthn';
import { useAuth } from '@/store/auth';

/**
 * Asks the person to confirm with a passkey, because the API wants a fresh login for the action.
 *
 * The login runs on the same session, so the session is fresh again when it ends. If the login fails, the component
 * reads the session from the server again, because an unfinished login attempt ends the logged-in state.
 */
export function StepUp() {
  const { call, note, sync } = useAuth.getState();
  const step = useStep();

  const confirm = (): Promise<boolean> =>
    step.run(async () => {
      try {
        const options = await call(() => api.beginLogin());
        const assertion = await getPasskey(options);
        const result = await call(() => api.completeLogin(assertion));
        note(result.decision, result.user_xid);
        await sync();
      } catch (failure) {
        await sync().catch(() => undefined);
        throw failure;
      }
    });

  return (
    <div className="space-y-3">
      <Notice kind="warning">This change needs a fresh login. Confirm it with your passkey.</Notice>
      {step.error ? <Notice kind="error">{step.error}</Notice> : null}
      <Button disabled={step.busy} onClick={() => void confirm()}>
        <KeyRound size={16} /> Confirm with a passkey
      </Button>
    </div>
  );
}
