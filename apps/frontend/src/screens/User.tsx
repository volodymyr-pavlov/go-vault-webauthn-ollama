import { useState } from 'react';
import { LogOut } from 'lucide-react';
import type { Decision } from '@/api/types';
import { Authenticator } from '@/components/Authenticator';
import { StepUp } from '@/components/StepUp';
import { Button, Card, Notice, Tabs } from '@/components/ui';
import { Flag, has } from '@/lib/flags';
import { Data } from '@/screens/Data';
import { Security } from '@/screens/Security';
import { useAuth } from '@/store/auth';

// The sentence shown for each risk decision.
const decisions: Record<Decision, string> = {
  allow: 'The login was allowed.',
  limit: 'The login was limited. A sensitive action needs a fresh login first.',
  review: 'The login was flagged for review.',
};

/** The tabs of the screen of a logged-in user. */
type Tab = 'codes' | 'security' | 'data';

const tabs: { id: Tab; label: string }[] = [
  { id: 'codes', label: 'Codes' },
  { id: 'security', label: 'Security' },
  { id: 'data', label: 'Data' },
];

/** The props of [User]. */
interface UserProps {
  /** Called after the person logs out or deletes their data and a new session is open. */
  loggedOut: () => void;
}

/**
 * Shows the screen of a logged-in user. A header with the login state and the prompt for a fresh login stays above
 * three tabs. Codes holds the one-time codes of the person's other accounts and opens first, because it is the part that
 * the person uses most often. Security holds the ways to log in and the devices. Data holds the data that the service
 * keeps and the way to delete it.
 */
export function User({ loggedOut }: UserProps) {
  const { flags, decision, restart, stale } = useAuth();
  const [tab, setTab] = useState<Tab>('codes');

  return (
    <div className="space-y-6">
      <Card title="You are logged in">
        {decision ? (
          <Notice kind={decision === 'allow' ? 'info' : 'warning'}>{decisions[decision] ?? decision}</Notice>
        ) : null}
        {has(flags, Flag.Limited) ? <Notice kind="warning">Log in again before a sensitive change.</Notice> : null}
        {stale ? <StepUp /> : null}
        <Button tone="plain" onClick={() => void restart(true).then(loggedOut)}>
          <LogOut size={16} /> Log out
        </Button>
      </Card>

      <Tabs label="Choose a part of your page" items={tabs} active={tab} onChange={setTab} />

      <div role="tabpanel" aria-label={tabs.find((item) => item.id === tab)?.label}>
        {tab === 'codes' ? <Authenticator /> : null}
        {tab === 'security' ? <Security /> : null}
        {tab === 'data' ? <Data deleted={loggedOut} /> : null}
      </div>
    </div>
  );
}
