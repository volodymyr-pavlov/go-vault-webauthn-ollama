import { useEffect, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { Notice } from '@/components/ui';
import { Flag, canEnroll, has } from '@/lib/flags';
import { errorMessage } from '@/lib/errorMessage';
import { Account } from '@/screens/Account';
import { Enroll } from '@/screens/Enroll';
import { Login } from '@/screens/Login';
import { Recover } from '@/screens/Recover';
import { Register } from '@/screens/Register';
import { useAuth } from '@/store/auth';

type Tab = 'login' | 'register' | 'recover';

const tabs: { id: Tab; label: string }[] = [
  { id: 'login', label: 'Log in' },
  { id: 'register', label: 'Register' },
  { id: 'recover', label: 'Recover' },
];

/**
 * Opens the session of the device key and shows the screen that fits the session flags.
 *
 * The screen is the account, the enrollment of a first factor, or the log in, register and recover views. The page
 * holds no token: the device key signs every request, and the server finds the session by the key ID.
 */
export function App() {
  const { ready, flags, start } = useAuth();
  const [failure, setFailure] = useState('');
  const [tab, setTab] = useState<Tab>('login');
  const [notice, setNotice] = useState('');

  useEffect(() => {
    start().catch((error: unknown) => setFailure(errorMessage(error)));
  }, [start]);

  let screen;
  if (failure) {
    screen = <Notice kind="error">The service is not reachable. {failure}</Notice>;
  } else if (!ready) {
    screen = <p className="text-sm text-slate-500">Opening a session…</p>;
  } else if (has(flags, Flag.Authorized)) {
    screen = <Account loggedOut={() => setTab('login')} />;
  } else if (canEnroll(flags)) {
    screen = (
      <Enroll
        finished={(message) => {
          setNotice(message);
          setTab('login');
        }}
      />
    );
  } else {
    screen = (
      <div className="space-y-4">
        <nav className="flex gap-1 rounded-xl bg-slate-200 p-1 dark:bg-slate-800" aria-label="Choose what to do">
          {tabs.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-current={tab === item.id}
              onClick={() => {
                setNotice('');
                setTab(item.id);
              }}
              className={`flex-1 rounded-lg px-3 py-1.5 text-sm font-medium ${
                tab === item.id ? 'bg-white shadow-sm dark:bg-slate-900' : 'text-slate-600 dark:text-slate-400'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>
        {tab === 'login' ? <Login notice={notice} /> : null}
        {tab === 'register' ? <Register /> : null}
        {tab === 'recover' ? <Recover /> : null}
      </div>
    );
  }

  return (
    <main className="mx-auto max-w-xl space-y-6 px-4 py-10">
      <header className="flex items-center gap-3">
        <ShieldCheck className="text-indigo-600" size={28} />
        <h1 className="text-2xl font-semibold">Vault Login</h1>
      </header>
      {screen}
    </main>
  );
}
