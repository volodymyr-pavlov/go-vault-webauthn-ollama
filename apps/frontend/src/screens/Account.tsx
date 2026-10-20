import { useCallback, useEffect, useState } from 'react';
import { Download, LogOut, Trash2 } from 'lucide-react';
import { api } from '@/api/client';
import type { Decision, PasskeyView } from '@/api/types';
import { PasskeyAdd } from '@/components/PasskeyAdd';
import { Devices } from '@/components/Devices';
import { StepUp } from '@/components/StepUp';
import { RecoveryCodes } from '@/components/RecoveryCodes';
import { TotpSetup } from '@/components/TotpSetup';
import { Button, Card, Notice } from '@/components/ui';
import { Flag, has } from '@/lib/flags';
import { useStep } from '@/lib/useStep';
import { useAuth } from '@/store/auth';

// The sentence shown for each risk decision.
const decisions: Record<Decision, string> = {
  allow: 'The login was allowed.',
  limit: 'The login was limited. A sensitive action needs a fresh login first.',
  review: 'The login was flagged for review.',
};

/** The props of [Account]. */
interface AccountProps {
  /** Called after the person logs out and a new session is open. */
  loggedOut: () => void;
}

/**
 * Shows the account of a logged-in session. The person manages the passkeys, the devices, the authenticator app and
 * the recovery codes here.
 */
export function Account({ loggedOut }: AccountProps) {
  const { call, flags, decision, userXid, restart, riskScore, expiresAt, stale } = useAuth();
  const [passkeys, setPasskeys] = useState<PasskeyView[]>([]);
  const list = useStep();
  const change = useStep();
  const data = useStep();
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const download = (): Promise<boolean> =>
    data.run(async () => {
      const exported = await call(() => api.exportAccount());
      const url = URL.createObjectURL(new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = 'my-data.json';
      link.click();
      URL.revokeObjectURL(url);
    });

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
      <Card title="You are logged in">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt className="text-slate-500">Account</dt>
          <dd>{userXid}</dd>
          <dt className="text-slate-500">Risk score</dt>
          <dd>{riskScore} of 100</dd>
          <dt className="text-slate-500">Session ends</dt>
          <dd>{expiresAt ? new Date(expiresAt).toLocaleString() : ''}</dd>
        </dl>
        {decision ? (
          <Notice kind={decision === 'allow' ? 'info' : 'warning'}>{decisions[decision] ?? decision}</Notice>
        ) : null}
        {has(flags, Flag.Limited) ? <Notice kind="warning">Log in again before a sensitive change.</Notice> : null}
        {stale ? <StepUp /> : null}
        <Button tone="plain" onClick={() => void restart(true).then(loggedOut)}>
          <LogOut size={16} /> Log out
        </Button>
      </Card>

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

      <Devices />

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

      <Card title="Your data">
        <p className="text-sm text-slate-500">
          You can download the personal data that the service keeps about you, or delete your account. Deleting removes
          your passkeys, devices and recovery codes for good, and it cannot be undone.
        </p>
        {data.error ? <Notice kind="error">{data.error}</Notice> : null}
        <div className="flex flex-wrap gap-2">
          <Button tone="plain" disabled={data.busy} onClick={() => void download()}>
            <Download size={16} /> Download my data
          </Button>
          {confirmingDelete ? (
            <Button
              tone="danger"
              disabled={data.busy}
              onClick={() =>
                void data.run(async () => {
                  await call(() => api.deleteAccount());
                  await restart(false);
                  loggedOut();
                })
              }
            >
              <Trash2 size={16} /> Yes, delete my account for good
            </Button>
          ) : (
            <Button tone="danger" disabled={data.busy} onClick={() => setConfirmingDelete(true)}>
              <Trash2 size={16} /> Delete my account
            </Button>
          )}
        </div>
      </Card>

      <Card title="Recovery codes">
        <RecoveryCodes />
      </Card>
    </div>
  );
}
