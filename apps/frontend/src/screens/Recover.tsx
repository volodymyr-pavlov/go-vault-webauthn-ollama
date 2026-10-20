import { type ReactNode, useState } from 'react';
import { api } from '@/api/client';
import { Button, Card, Field, Notice } from '@/components/ui';
import { type Step, useStep } from '@/lib/useStep';
import { useAuth } from '@/store/auth';

/** The answer to a request or a claim. It is the same for every address, so it never shows if the user exists. */
const neutral = 'If the address is registered, we sent an email.';

/** The waiting time of a delayed recovery, the life of a grant token and the shape of the tokens in the emails. */
const recoveryDelay = '72 hours';
const grantLife = '1 hour';
const tokenShape = '64 hex digits, from the email.';

const mutedText = 'text-sm text-slate-600 dark:text-slate-400';

/**
 * Recovers a login in two ways. A recovery code works at once. A person who lost the codes too can ask for a
 * delayed recovery: the owner can cancel it by email during the waiting time, and an operator must approve it.
 *
 * Both ways end the same: the session may add a new passkey or authenticator app, and the person then logs in with it.
 */
export function Recover() {
  return (
    <div className="space-y-6">
      <WithCode />
      <WithoutCodes />
    </div>
  );
}

/** Sends a recovery code so the session can add a new factor. The code does not log the person in. */
function WithCode() {
  const { call, sync } = useAuth.getState();
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const step = useStep();

  return (
    <Card title="Recover your login">
      <p className="text-sm text-slate-600 dark:text-slate-400">
        A recovery code does not log you in. It lets you add a new passkey or authenticator app, and then you log in
        with it.
      </p>
      {step.error ? <Notice kind="error">{step.error}</Notice> : null}
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          void step.run(async () => {
            await call(() => api.recovery(email.trim(), code.trim()));
            await sync();
          });
        }}
      >
        <Field label="Email" type="email" value={email} required onChange={(event) => setEmail(event.target.value)} />
        <Field
          label="Recovery code"
          hint="16 characters. Dashes and case do not matter."
          value={code}
          autoComplete="off"
          required
          onChange={(event) => setCode(event.target.value)}
        />
        <Button type="submit" disabled={step.busy}>
          Use the code
        </Button>
      </form>
    </Card>
  );
}

/** Walks a person who lost the recovery codes too through the request, the cancel, the claim and the grant. */
function WithoutCodes() {
  const [email, setEmail] = useState('');
  const [notice, setNotice] = useState('');
  const request = useStep();
  const cancel = useStep();
  const claim = useStep();
  const grant = useStep();
  const busy = request.busy || cancel.busy || claim.busy || grant.busy;
  const shared = { busy, setNotice };

  return (
    <Card title="I lost my recovery codes too">
      <p className={mutedText}>
        If you have no passkey, no authenticator app, and no recovery codes, you can ask for a delayed recovery. It
        takes time on purpose: the owner gets an email and can cancel the request during the waiting time. Use the same
        email address in steps 1 and 3.
      </p>
      {notice ? <Notice kind="info">{notice}</Notice> : null}

      <AskStep {...shared} step={request} email={email} setEmail={setEmail} />
      <CancelStep {...shared} step={cancel} />
      <ClaimStep {...shared} claim={claim} grant={grant} email={email} />
    </Card>
  );
}

/** What each step of the delayed recovery shares with the others. */
interface StepProps {
  /** True while any step of the recovery runs, so the buttons of the others wait. */
  busy: boolean;
  /** Shows a message above the steps. */
  setNotice: (notice: string) => void;
}

/** Gives a step of the delayed recovery its heading and, from the second step on, a rule above it. */
function RecoveryStep({
  title,
  first = false,
  error,
  children,
}: {
  title: string;
  first?: boolean;
  error: string;
  children: ReactNode;
}) {
  const rule = first ? '' : ' border-t border-slate-200 pt-4 dark:border-slate-800';

  return (
    <div className={`space-y-3${rule}`}>
      <h3 className="text-sm font-semibold">{title}</h3>
      {error ? <Notice kind="error">{error}</Notice> : null}
      {children}
    </div>
  );
}

/** Step 1: starts the waiting time. */
function AskStep({
  busy,
  setNotice,
  step,
  email,
  setEmail,
}: StepProps & { step: Step; email: string; setEmail: (email: string) => void }) {
  const { call } = useAuth.getState();

  return (
    <RecoveryStep title="Step 1. Ask for a recovery" first error={step.error}>
      <p className={mutedText}>The waiting time starts now. It is {recoveryDelay} by default.</p>
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          setNotice('');
          void step.run(async () => {
            await call(() => api.requestRecovery(email.trim()));
            setNotice(neutral);
          });
        }}
      >
        <Field
          label="Your email"
          type="email"
          value={email}
          required
          onChange={(event) => setEmail(event.target.value)}
        />
        <Button type="submit" disabled={busy}>
          Ask for a recovery
        </Button>
      </form>
    </RecoveryStep>
  );
}

/** Step 2: lets the owner stop a request that is not theirs. */
function CancelStep({ busy, setNotice, step }: StepProps & { step: Step }) {
  const { call } = useAuth.getState();
  const [token, setToken] = useState('');

  return (
    <RecoveryStep title="Step 2. Cancel a request that is not yours" error={step.error}>
      <p className={mutedText}>If this is your login and you did not ask, paste the cancel token from the email.</p>
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          setNotice('');
          void step.run(async () => {
            await call(() => api.cancelRecovery(token.trim()));
            setToken('');
            setNotice('The recovery request is cancelled.');
          });
        }}
      >
        <Field
          label="Cancel token"
          hint={tokenShape}
          value={token}
          autoComplete="off"
          required
          onChange={(event) => setToken(event.target.value)}
        />
        <Button type="submit" tone="danger" disabled={busy}>
          Cancel the recovery
        </Button>
      </form>
    </RecoveryStep>
  );
}

/** Step 3: asks for the grant token of an approved request and uses it. */
function ClaimStep({ busy, setNotice, claim, grant, email }: StepProps & { claim: Step; grant: Step; email: string }) {
  const { call, sync } = useAuth.getState();
  const [token, setToken] = useState('');

  return (
    <RecoveryStep title="Step 3. Claim the approved recovery" error={claim.error}>
      <p className={mutedText}>
        After the waiting time, an operator must approve the request. Then ask for the grant token. Without an approval,
        no email is sent.
      </p>
      <Button
        type="button"
        tone="plain"
        disabled={busy || email.trim() === ''}
        onClick={() => {
          setNotice('');
          void claim.run(async () => {
            await call(() => api.claimRecovery(email.trim()));
            setNotice(neutral);
          });
        }}
      >
        Send me the grant token
      </Button>
      {grant.error ? <Notice kind="error">{grant.error}</Notice> : null}
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          setNotice('');
          void grant.run(async () => {
            await call(() => api.grantRecovery(token.trim()));
            await sync();
          });
        }}
      >
        <Field
          label="Grant token"
          hint={`${tokenShape} It works for ${grantLife}.`}
          value={token}
          autoComplete="off"
          required
          onChange={(event) => setToken(event.target.value)}
        />
        <Button type="submit" disabled={busy}>
          Use the grant token
        </Button>
      </form>
    </RecoveryStep>
  );
}
