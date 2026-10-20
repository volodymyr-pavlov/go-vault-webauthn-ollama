import { useState } from 'react';
import { KeyRound } from 'lucide-react';
import { api } from '@/api/client';
import type { Decision } from '@/api/types';
import { Button, Card, Field, Notice } from '@/components/ui';
import { useStep } from '@/lib/useStep';
import { getPasskey, supported } from '@/lib/webauthn';
import { useAuth } from '@/store/auth';

/** The step of the password login: the email, the password, or the code of the authenticator app. */
type Stage = 'email' | 'password' | 'code';

/** The props of [Login]. */
interface LoginProps {
  /** A message to show above the form, for example after an enrollment. It is empty when there is none. */
  notice: string;
}

/** Logs the person in with a passkey, or with a password and then a code from an authenticator app. */
export function Login({ notice }: LoginProps) {
  const { call, note, sync } = useAuth.getState();
  const [stage, setStage] = useState<Stage>('email');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const step = useStep();

  const finish = async (decision: Decision, userXid: string): Promise<void> => {
    note(decision, userXid);
    await sync();
  };

  const withPasskey = (): Promise<boolean> =>
    step.run(async () => {
      const options = await call(() => api.beginLogin());
      const assertion = await getPasskey(options);
      const result = await call(() => api.completeLogin(assertion));
      await finish(result.decision, result.user_xid);
    });

  const withPassword = (): Promise<boolean> =>
    step.run(async () => {
      await call(() => api.password(email.trim(), password));
      setPassword('');
      setStage('code');
    });

  const withCode = (): Promise<boolean> =>
    step.run(async () => {
      const result = await call(() => api.totp(code.trim()));
      await finish(result.decision, result.user_xid);
    });

  return (
    <Card title="Log in">
      {notice ? <Notice kind="info">{notice}</Notice> : null}
      {step.error ? <Notice kind="error">{step.error}</Notice> : null}

      {stage === 'email' ? (
        <EmailStage
          busy={step.busy}
          email={email}
          setEmail={setEmail}
          onPasskey={() => void withPasskey()}
          onPassword={() => setStage('password')}
        />
      ) : null}

      {stage === 'password' ? (
        <PasswordStage
          busy={step.busy}
          email={email}
          password={password}
          setPassword={setPassword}
          onSubmit={() => void withPassword()}
          onBack={() => setStage('email')}
        />
      ) : null}

      {stage === 'code' ? (
        <CodeStage busy={step.busy} code={code} setCode={setCode} onSubmit={() => void withCode()} />
      ) : null}
    </Card>
  );
}

/** Asks for the email of a password login, or starts a passkey login that needs no email. */
function EmailStage({
  busy,
  email,
  setEmail,
  onPasskey,
  onPassword,
}: {
  busy: boolean;
  email: string;
  setEmail: (email: string) => void;
  onPasskey: () => void;
  onPassword: () => void;
}) {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Button disabled={busy || !supported()} onClick={onPasskey}>
          <KeyRound size={16} /> Log in with a passkey
        </Button>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Your device offers the passkeys it holds for this site. You need not type your email.
        </p>
      </div>
      <form
        className="space-y-3 border-t border-slate-200 pt-4 dark:border-slate-800"
        onSubmit={(event) => {
          event.preventDefault();
          onPassword();
        }}
      >
        <Field
          label="Email"
          type="email"
          autoComplete="username"
          hint="Only for an account that has a password and an authenticator app, not a passkey."
          value={email}
          required
          onChange={(event) => setEmail(event.target.value)}
        />
        <Button tone="plain" type="submit" disabled={email.trim() === ''}>
          Use a password
        </Button>
      </form>
    </div>
  );
}

/** Asks for the password of the email from the first stage. */
function PasswordStage({
  busy,
  email,
  password,
  setPassword,
  onSubmit,
  onBack,
}: {
  busy: boolean;
  email: string;
  password: string;
  setPassword: (password: string) => void;
  onSubmit: () => void;
  onBack: () => void;
}) {
  return (
    <form
      className="space-y-3"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <Field label="Email" type="email" value={email} readOnly />
      <Field
        label="Password"
        type="password"
        autoComplete="current-password"
        value={password}
        required
        onChange={(event) => setPassword(event.target.value)}
      />
      <div className="flex gap-2">
        <Button type="submit" disabled={busy || password === ''}>
          Continue
        </Button>
        <Button tone="plain" type="button" onClick={onBack}>
          Back
        </Button>
      </div>
    </form>
  );
}

/** Asks for the code of the authenticator app after the password. */
function CodeStage({
  busy,
  code,
  setCode,
  onSubmit,
}: {
  busy: boolean;
  code: string;
  setCode: (code: string) => void;
  onSubmit: () => void;
}) {
  return (
    <form
      className="space-y-3"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <Field
        label="Code from your authenticator app"
        inputMode="numeric"
        pattern="[0-9]{6}"
        maxLength={6}
        autoComplete="one-time-code"
        value={code}
        required
        onChange={(event) => setCode(event.target.value)}
      />
      <Button type="submit" disabled={busy || code.trim().length !== 6}>
        Log in
      </Button>
    </form>
  );
}
