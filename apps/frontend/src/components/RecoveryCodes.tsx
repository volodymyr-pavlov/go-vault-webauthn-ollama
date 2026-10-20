import { useState } from 'react';
import { Copy } from 'lucide-react';
import { api } from '@/api/client';
import { Button, Notice } from '@/components/ui';
import { useStep } from '@/lib/useStep';
import { useAuth } from '@/store/auth';

/** Issues a new set of recovery codes and shows it once. A new set replaces the previous one. */
export function RecoveryCodes() {
  const call = useAuth((state) => state.call);
  const [codes, setCodes] = useState<string[]>([]);
  const step = useStep();

  return (
    <div className="space-y-3">
      <p className="text-sm text-slate-600 dark:text-slate-400">
        A recovery code lets you add a new factor when you lose the others. Each code works once. A new set replaces the
        previous one.
      </p>
      {step.error ? <Notice kind="error">{step.error}</Notice> : null}
      {codes.length > 0 ? (
        <div className="space-y-2">
          <Notice kind="warning">Save these codes now. They are not shown again.</Notice>
          <ul className="grid grid-cols-2 gap-2 font-mono text-sm">
            {codes.map((code) => (
              <li key={code} className="rounded border border-slate-200 px-2 py-1 dark:border-slate-700">
                {code}
              </li>
            ))}
          </ul>
          <Button tone="plain" onClick={() => void step.run(() => navigator.clipboard.writeText(codes.join('\n')))}>
            <Copy size={16} /> Copy the codes
          </Button>
        </div>
      ) : null}
      <Button
        tone="plain"
        disabled={step.busy}
        onClick={() =>
          void step.run(async () => {
            setCodes((await call(() => api.issueRecoveryCodes())).codes);
          })
        }
      >
        {codes.length > 0 ? 'Issue a new set' : 'Issue recovery codes'}
      </Button>
    </div>
  );
}
