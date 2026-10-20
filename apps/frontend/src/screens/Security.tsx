import { useCallback, useEffect, useState } from 'react';
import { Trash2 } from 'lucide-react';
import { api } from '@/api/client';
import type { PasskeyView } from '@/api/types';
import { Devices } from '@/components/Devices';
import { PasskeyAdd } from '@/components/PasskeyAdd';
import { RecoveryCodes } from '@/components/RecoveryCodes';
import { TotpSetup } from '@/components/TotpSetup';
import { Button, Card, Notice } from '@/components/ui';
import { useStep } from '@/lib/useStep';
import { useAuth } from '@/store/auth';

/**
 * Shows the ways to log in and the places where the user is logged in: the passkeys, the authenticator app for the
 * login, the recovery codes and the devices. Removing a factor needs a fresh login. The user screen shows the prompt for
 * it, because the store marks the state stale when the API asks.
 */
export function Security() {
  const { call } = useAuth();
  const [passkeys, setPasskeys] = useState<PasskeyView[]>([]);
  const list = useStep();
  const change = useStep();

  const load = useCallback(
    () =>
      list.run(async () => {
        setPasskeys((await call(() => api.passkeys())).passkeys);
      }),
    [call],
  );

  useEffect(() => {
    void load();
  }, [load]);

  const remove = (xid: string): Promise<boolean> =>
    change.run(async () => {
      await call(() => api.removePasskey(xid));
      await load();
    });

  return (
    <div className="space-y-6">
      <Card title="Passkeys">
        {list.error ? <Notice kind="error">{list.error}</Notice> : null}
        {change.error ? <Notice kind="error">{change.error}</Notice> : null}
        {passkeys.length === 0 ? <p className="text-sm text-slate-500">No passkeys yet.</p> : null}
        <ul className="divide-y divide-slate-200 dark:divide-slate-800">
          {passkeys.map((passkey) => (
            <li key={passkey.passkey_xid} className="flex items-center justify-between gap-3 py-2">
              <div>
                <div className="text-sm font-medium">{passkey.name}</div>
                <div className="text-xs text-slate-500">
                  Added {new Date(passkey.created_at).toLocaleDateString()}
                  {passkey.backed_up ? ' · synced' : ''}
                  {passkey.disabled ? ' · disabled' : ''}
                </div>
              </div>
              <Button tone="danger" disabled={change.busy} onClick={() => void remove(passkey.passkey_xid)}>
                <Trash2 size={16} /> Remove
              </Button>
            </li>
          ))}
        </ul>
        <PasskeyAdd done={() => void load()} />
      </Card>

      <Card title="Authenticator app">
        <TotpSetup done={() => void load()} />
        <Button
          tone="danger"
          disabled={change.busy}
          onClick={() =>
            void change.run(async () => {
              await call(() => api.removeTOTP());
            })
          }
        >
          Remove the authenticator app
        </Button>
      </Card>

      <Card title="Recovery codes">
        <RecoveryCodes />
      </Card>

      <Devices />
    </div>
  );
}
