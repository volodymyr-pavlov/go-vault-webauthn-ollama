import { useState } from 'react';
import { Card, Button, Notice } from '@/components/ui';
import { PasskeyAdd } from '@/components/PasskeyAdd';
import { RecoveryCodes } from '@/components/RecoveryCodes';
import { TotpSetup } from '@/components/TotpSetup';
import { useAuth } from '@/store/auth';

/** The props of [Enroll]. */
interface EnrollProps {
  /** Called with a message for the log in screen when the person continues to log in. */
  finished: (message: string) => void;
}

/** Lets the person add a first factor after a verified registration or a recovery code. */
export function Enroll({ finished }: EnrollProps) {
  const restart = useAuth((state) => state.restart);
  const [added, setAdded] = useState(false);

  if (added) {
    return (
      <Card title="You are all set">
        <Notice kind="info">A factor was added. Save recovery codes if you wish, then log in with it.</Notice>
        <RecoveryCodes />
        <Button onClick={() => void restart(true).then(() => finished('Your factor was added. Log in with it now.'))}>
          Continue to log in
        </Button>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <Card title="Add a passkey">
        <PasskeyAdd done={() => setAdded(true)} />
      </Card>
      <Card title="Or use an authenticator app">
        <TotpSetup done={() => setAdded(true)} />
      </Card>
    </div>
  );
}
