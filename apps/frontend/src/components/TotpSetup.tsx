import { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { api } from '@/api/client';
import type { TOTPEnrollment } from '@/api/types';
import { Button, Field, Notice } from '@/components/ui';
import { useStep } from '@/lib/useStep';
import { useAuth } from '@/store/auth';

/** The props of [TotpSetup]. */
interface TotpSetupProps {
  /** Called when the server accepts the first code of the app. */
  done: () => void;
}

/** Enrolls an authenticator app. It shows the secret and a QR code, then asks for the first code. */
export function TotpSetup({ done }: TotpSetupProps) {
  const call = useAuth((state) => state.call);
  const [secret, setSecret] = useState<TOTPEnrollment | null>(null);
  const [code, setCode] = useState('');
  const [qr, setQr] = useState('');
  const step = useStep();

  useEffect(() => {
    if (!secret) {
      setQr('');
      return;
    }

    let current = true;
    // Without the picture the person types the secret, which the form shows too.
    void QRCode.toDataURL(secret.uri, { margin: 1, width: 192 })
      .then((url) => {
        if (current) {
          setQr(url);
        }
      })
      .catch(() => {
        if (current) {
          setQr('');
        }
      });

    return () => {
      current = false;
    };
  }, [secret]);

  if (!secret) {
    return (
      <div className="space-y-3">
        {step.error ? <Notice kind="error">{step.error}</Notice> : null}
        <Button
          disabled={step.busy}
          onClick={() =>
            void step.run(async () => {
              setSecret(await call(() => api.beginTOTP()));
            })
          }
        >
          Set up an authenticator app
        </Button>
      </div>
    );
  }

  return (
    <form
      className="space-y-3"
      onSubmit={(event) => {
        event.preventDefault();
        void step
          .run(async () => {
            await call(() => api.completeTOTP(code.trim()));
          })
          .then((passed) => {
            if (passed) {
              setSecret(null);
              setCode('');
              done();
            }
          });
      }}
    >
      <Notice kind="info">
        Scan the code with your authenticator app, or type the secret. It is shown once.
        {qr ? (
          <img src={qr} alt="QR code of the secret" className="mt-2 rounded bg-white" width={192} height={192} />
        ) : null}
        <code className="mt-2 block break-all rounded bg-white/60 p-2 font-mono text-xs dark:bg-black/30">
          {secret.secret}
        </code>
        <a className="mt-2 inline-block underline" href={secret.uri}>
          Open it in an app on this device
        </a>
      </Notice>
      <Field
        label="The first code of the app"
        inputMode="numeric"
        pattern="[0-9]{6}"
        maxLength={6}
        autoComplete="one-time-code"
        value={code}
        required
        onChange={(event) => setCode(event.target.value)}
      />
      {step.error ? <Notice kind="error">{step.error}</Notice> : null}
      <Button type="submit" disabled={step.busy || code.trim().length !== 6}>
        Confirm the app
      </Button>
    </form>
  );
}
