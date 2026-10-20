import { useState } from 'react';
import { KeyRound } from 'lucide-react';
import { api } from '@/api/client';
import { Button, Field, Notice } from '@/components/ui';
import { useStep } from '@/lib/useStep';
import { createPasskey, supported } from '@/lib/webauthn';
import { useAuth } from '@/store/auth';

/** The props of [PasskeyAdd]. */
interface PasskeyAddProps {
  /** Called when the server stores the passkey. */
  done: () => void;
}

/** Registers a passkey for the user of the session. It warns when the browser cannot make passkeys. */
export function PasskeyAdd({ done }: PasskeyAddProps) {
  const call = useAuth((state) => state.call);
  const [name, setName] = useState('');
  const step = useStep();

  if (!supported()) {
    return <Notice kind="warning">This browser cannot make passkeys. Use an authenticator app instead.</Notice>;
  }

  const submit = async (): Promise<void> => {
    const passed = await step.run(async () => {
      const options = await call(() => api.beginPasskey());
      const credential = await createPasskey(options);
      await call(() => api.completePasskey(name.trim(), credential));
    });
    if (passed) {
      setName('');
      done();
    }
  };

  return (
    <form
      className="space-y-3"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <Field
        label="Name of the passkey"
        hint="For example the name of this device."
        value={name}
        maxLength={64}
        required
        onChange={(event) => setName(event.target.value)}
      />
      {step.error ? <Notice kind="error">{step.error}</Notice> : null}
      <Button type="submit" disabled={step.busy || name.trim() === ''}>
        <KeyRound size={16} /> Add a passkey
      </Button>
    </form>
  );
}
