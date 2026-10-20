import { useState } from 'react';
import { Download, Trash2 } from 'lucide-react';
import { api } from '@/api/client';
import { Button, Card, Notice } from '@/components/ui';
import { useStep } from '@/lib/useStep';
import { useAuth } from '@/store/auth';

/** The props of [Data]. */
interface DataProps {
  /** Called after the person deleted their data and a new session is open. */
  deleted: () => void;
}

/**
 * Shows the data that the service keeps about the user. The person downloads it, or deletes all of it. Both need a fresh
 * login, and the user screen shows the prompt for it.
 */
export function Data({ deleted }: DataProps) {
  const { call, restart, userXid, riskScore, expiresAt } = useAuth();
  const data = useStep();
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const download = (): Promise<boolean> =>
    data.run(async () => {
      const exported = await call(() => api.exportUser());
      const url = URL.createObjectURL(new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = 'my-data.json';
      link.click();
      URL.revokeObjectURL(url);
    });

  return (
    <div className="space-y-6">
      <Card title="This session">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt className="text-slate-500">User</dt>
          <dd>{userXid}</dd>
          <dt className="text-slate-500">Risk score</dt>
          <dd>{riskScore} of 100</dd>
          <dt className="text-slate-500">Session ends</dt>
          <dd>{expiresAt ? new Date(expiresAt).toLocaleString() : ''}</dd>
        </dl>
      </Card>

      <Card title="Your data">
        <p className="text-sm text-slate-500">
          You can download the personal data that the service keeps about you, or delete all of it. Deleting removes
          your passkeys, devices, authenticator accounts and recovery codes for good, and it cannot be undone.
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
                  await call(() => api.deleteUser());
                  await restart(false);
                  deleted();
                })
              }
            >
              <Trash2 size={16} /> Yes, delete everything for good
            </Button>
          ) : (
            <Button tone="danger" disabled={data.busy} onClick={() => setConfirmingDelete(true)}>
              <Trash2 size={16} /> Delete my data
            </Button>
          )}
        </div>
      </Card>
    </div>
  );
}
