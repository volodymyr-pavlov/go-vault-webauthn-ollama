import { useState } from 'react';
import { api } from '@/api/client';
import { Button, Card, Field, Notice } from '@/components/ui';
import { useStep } from '@/lib/useStep';
import { useAuth } from '@/store/auth';

// The address of the test mail inbox. It is undefined when VITE_MAIL_URL is not set.
const mailUrl = import.meta.env['VITE_MAIL_URL'] as string | undefined;

/** Creates an account with an email and a password, then asks for the verification token that arrives by mail. */
export function Register() {
  const { call, sync } = useAuth.getState();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [sent, setSent] = useState(false);
  const step = useStep();

  if (sent) {
    return (
      <Card title="Check your mail">
        <Notice kind="info">
          If the address can be registered, a token is on its way. Paste the 64 characters here.
          {mailUrl ? (
            <>
              {' '}
              In this stand the mail is in{' '}
              <a className="underline" href={mailUrl} target="_blank" rel="noreferrer">
                Mailpit
              </a>
              .
            </>
          ) : null}
        </Notice>
        {step.error ? <Notice kind="error">{step.error}</Notice> : null}
        <form
          className="space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            void step.run(async () => {
              await call(() => api.verify(token.trim()));
              await sync();
            });
          }}
        >
          <Field
            label="Verification token"
            value={token}
            maxLength={64}
            autoComplete="off"
            required
            onChange={(event) => setToken(event.target.value)}
          />
          <Button type="submit" disabled={step.busy || token.trim().length !== 64}>
            Verify
          </Button>
        </form>
      </Card>
    );
  }

  return (
    <Card title="Register">
      {step.error ? <Notice kind="error">{step.error}</Notice> : null}
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          void step
            .run(async () => {
              await call(() => api.register(email.trim(), password));
            })
            .then((passed) => setSent(passed));
        }}
      >
        <Field
          label="Email"
          type="email"
          autoComplete="email"
          value={email}
          required
          onChange={(event) => setEmail(event.target.value)}
        />
        <Field
          label="Password"
          type="password"
          autoComplete="new-password"
          hint="At least 10 characters. It is used until you add a passkey."
          value={password}
          minLength={10}
          required
          onChange={(event) => setPassword(event.target.value)}
        />
        <Button type="submit" disabled={step.busy}>
          Register
        </Button>
      </form>
    </Card>
  );
}
