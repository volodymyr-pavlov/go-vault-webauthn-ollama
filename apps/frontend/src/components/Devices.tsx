import { useCallback, useEffect, useState } from 'react';
import { Trash2 } from 'lucide-react';
import { api } from '@/api/client';
import type { DeviceView } from '@/api/types';
import { Button, Card, Notice } from '@/components/ui';
import { useStep } from '@/lib/useStep';
import { useAuth } from '@/store/auth';

/**
 * Lists the sessions of the user, so the person sees where it is in use, and ends the ones that are not theirs.
 *
 * Removing a session needs a fresh login. The user screen shows the prompt for it, because the store marks the
 * state stale when the API asks.
 */
export function Devices() {
  const { call } = useAuth();
  const [devices, setDevices] = useState<DeviceView[]>([]);
  const list = useStep();
  const change = useStep();

  const load = useCallback(
    () =>
      list.run(async () => {
        setDevices((await call(() => api.sessions())).sessions);
      }),
    [call],
  );

  useEffect(() => {
    void load();
  }, [load]);

  const remove = (xid: string): Promise<boolean> =>
    change.run(async () => {
      await call(() => api.removeSession(xid));
      await load();
    });

  return (
    <Card title="Devices">
      {list.error ? <Notice kind="error">{list.error}</Notice> : null}
      {change.error ? <Notice kind="error">{change.error}</Notice> : null}
      <ul className="divide-y divide-slate-200 dark:divide-slate-800">
        {devices.map((device) => (
          <li key={device.session_xid} className="flex items-center justify-between gap-3 py-2">
            <div>
              <div className="text-sm font-medium">
                {device.country || 'Unknown country'}
                {device.current ? ' · This device' : ''}
              </div>
              <div className="text-xs text-slate-500">
                Opened {new Date(device.created_at).toLocaleString()} · last seen{' '}
                {new Date(device.last_seen_at).toLocaleString()}
              </div>
            </div>
            {device.current ? null : (
              <Button tone="danger" disabled={change.busy} onClick={() => void remove(device.session_xid)}>
                <Trash2 size={16} /> Remove
              </Button>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}
