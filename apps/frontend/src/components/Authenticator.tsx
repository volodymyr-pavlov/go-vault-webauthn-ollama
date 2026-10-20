import { useCallback, useEffect, useRef, useState } from 'react';
import { Camera, Copy, ImageUp, Plus, Trash2 } from 'lucide-react';
import { api } from '@/api/client';
import type { Account } from '@/api/types';
import { Button, Card, Field, Notice } from '@/components/ui';
import { decodeFile, decodeImage } from '@/lib/qr';
import { useStep } from '@/lib/useStep';
import { useAuth } from '@/store/auth';

/** How often the camera is read for a QR code, in milliseconds. */
const scanInterval = 250;

/**
 * Explains why the camera did not start, in words for the person. The general error text of the page is about passkeys,
 * and a refused camera raises the same error name as a cancelled passkey, so the camera has its own text.
 *
 * @param error - The value that the browser threw.
 * @returns The text to show.
 */
export function cameraMessage(error: unknown): string {
  if (error instanceof DOMException) {
    switch (error.name) {
      case 'NotAllowedError':
      case 'SecurityError':
        return 'The browser did not give this page the camera. Allow the camera in the address bar and try again.';
      case 'NotFoundError':
      case 'OverconstrainedError':
        return 'No camera was found on this device.';
      case 'NotReadableError':
        return 'The camera is in use by another app. Close the other app and try again.';
    }
  }

  return 'The camera could not start.';
}

/**
 * Groups the digits of a code for reading: "123456" becomes "123 456" and "12345678" becomes "1234 5678".
 *
 * @param code - The code.
 * @returns The code with a space in the middle.
 */
export function groupCode(code: string): string {
  if (code.length < 2) {
    return code;
  }

  const middle = Math.ceil(code.length / 2);
  return `${code.slice(0, middle)} ${code.slice(middle)}`;
}

/**
 * Keeps the TOTP accounts of the person, in place of an authenticator app. Vault keeps each secret and makes the codes,
 * so the page never sees a secret after the person adds it. The page shows the codes and asks for new ones when they run
 * out.
 *
 * The person adds an account by pasting an otpauth link or a Google Authenticator export link, by typing a secret, by
 * choosing a picture with a QR code, or by pointing the camera at one. Adding and removing need a fresh login. The
 * account screen shows the prompt for it, because the store marks the state stale when the API asks.
 */
export function Authenticator() {
  const { call } = useAuth();
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [fetchedAt, setFetchedAt] = useState(() => Date.now());
  const [now, setNow] = useState(() => Date.now());
  const [text, setText] = useState('');
  const [issuer, setIssuer] = useState('');
  const [label, setLabel] = useState('');
  const [skipped, setSkipped] = useState(0);
  const [scanning, setScanning] = useState(false);
  const video = useRef<HTMLVideoElement>(null);
  const stream = useRef<MediaStream | null>(null);
  const list = useStep();
  const change = useStep();

  const load = useCallback(
    () =>
      list.run(async () => {
        const answer = await call(() => api.accounts());
        setAccounts(answer.accounts);
        setFetchedAt(Date.now());
        setNow(Date.now());
      }),
    [call],
  );

  useEffect(() => {
    void load();
  }, [load]);

  // The clock of the page counts the seconds that are left. It asks for new codes when one has run out.
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const elapsed = Math.floor((now - fetchedAt) / 1000);
  const expired = accounts.some((account) => !account.unavailable && account.valid_for - elapsed <= 0);

  useEffect(() => {
    if (expired && !list.busy) {
      void load();
    }
  }, [expired, list.busy, load]);

  const stopCamera = useCallback(() => {
    stream.current?.getTracks().forEach((track) => track.stop());
    stream.current = null;
    setScanning(false);
  }, []);

  useEffect(() => stopCamera, [stopCamera]);

  // add sends what the person gave. A link goes as it is, and anything else counts as a secret.
  const add = (value: string): Promise<boolean> =>
    change.run(async () => {
      const trimmed = value.trim();
      const body = trimmed.toLowerCase().startsWith('otpauth')
        ? { uri: trimmed }
        : { secret: trimmed, issuer: issuer.trim(), label: label.trim() };
      const answer = await call(() => api.addAccount(body));
      setSkipped(answer.skipped);
      setText('');
      setIssuer('');
      setLabel('');
      await load();
    });

  const remove = (xid: string): Promise<boolean> =>
    change.run(async () => {
      await call(() => api.removeAccount(xid));
      await load();
    });

  const startCamera = (): Promise<boolean> =>
    change.run(async () => {
      // A browser offers the camera only on a secure page: HTTPS, or localhost.
      if (!navigator.mediaDevices) {
        throw new Error('The camera needs a secure page (HTTPS or localhost).');
      }

      try {
        stream.current = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      } catch (error) {
        throw new Error(cameraMessage(error));
      }

      setScanning(true);
    });

  // While the camera runs, every frame is read until a QR code appears. The code goes to the same path as a pasted link.
  useEffect(() => {
    const element = video.current;
    if (!scanning || !element || !stream.current) {
      return;
    }

    element.srcObject = stream.current;
    void element.play();

    const timer = setInterval(() => {
      if (element.videoWidth === 0) {
        return;
      }

      const found = decodeImage(element, element.videoWidth, element.videoHeight);
      if (found) {
        stopCamera();
        void add(found);
      }
    }, scanInterval);

    return () => clearInterval(timer);
    // add depends on the form fields only for a secret, and a scan sends a link.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanning, stopCamera]);

  return (
    <Card title="Authenticator codes">
      <p className="text-sm text-slate-600 dark:text-slate-400">
        Keep the one-time codes of your other accounts here, as in an authenticator app. Vault stores the secrets and
        makes the codes. The page never shows a secret again.
      </p>
      {list.error ? <Notice kind="error">{list.error}</Notice> : null}
      {change.error ? <Notice kind="error">{change.error}</Notice> : null}
      {skipped > 0 ? (
        <Notice kind="info">
          {skipped} counter-based {skipped === 1 ? 'account was' : 'accounts were'} left out, because only time-based
          accounts can be imported.
        </Notice>
      ) : null}
      {accounts.length === 0 ? <p className="text-sm text-slate-500">No accounts yet.</p> : null}
      <ul className="divide-y divide-slate-200 dark:divide-slate-800">
        {accounts.map((account) => {
          const left = Math.max(account.valid_for - elapsed, 0);
          const name = [account.issuer, account.label].filter(Boolean).join(' · ') || 'Account';
          return (
            <li key={account.account_xid} className="flex items-center justify-between gap-3 py-3">
              <div className="min-w-0">
                <div className="truncate text-sm font-medium">{name}</div>
                {account.unavailable ? (
                  <div className="text-xs text-red-600">The secret is missing in Vault. Remove this account.</div>
                ) : (
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-2xl tracking-wider" aria-label={`Code for ${name}`}>
                      {groupCode(account.code)}
                    </span>
                    <span className="text-xs text-slate-500">{left} s</span>
                  </div>
                )}
              </div>
              <div className="flex gap-2">
                {account.unavailable ? null : (
                  <Button
                    tone="plain"
                    aria-label={`Copy the code for ${name}`}
                    onClick={() => void change.run(() => navigator.clipboard.writeText(account.code))}
                  >
                    <Copy size={16} />
                  </Button>
                )}
                <Button
                  tone="danger"
                  aria-label={`Remove ${name}`}
                  disabled={change.busy}
                  onClick={() => void remove(account.account_xid)}
                >
                  <Trash2 size={16} />
                </Button>
              </div>
            </li>
          );
        })}
      </ul>

      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          void add(text);
        }}
      >
        <Field
          label="Link or secret"
          hint="Paste an otpauth:// link, a Google Authenticator export link, or type the secret."
          value={text}
          onChange={(event) => setText(event.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
        {text.trim() !== '' && !text.trim().toLowerCase().startsWith('otpauth') ? (
          <div className="grid grid-cols-2 gap-3">
            <Field label="Issuer" value={issuer} onChange={(event) => setIssuer(event.target.value)} />
            <Field label="Account name" value={label} onChange={(event) => setLabel(event.target.value)} />
          </div>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Button type="submit" disabled={change.busy || text.trim() === ''}>
            <Plus size={16} /> Add
          </Button>
          <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800">
            <ImageUp size={16} /> QR image
            <input
              type="file"
              accept="image/*"
              aria-label="QR image"
              className="sr-only"
              onChange={(event) => {
                const file = event.target.files?.[0];
                event.target.value = '';
                if (file) {
                  void change.run(async () => {
                    await add(await decodeFile(file));
                  });
                }
              }}
            />
          </label>
          {scanning ? (
            <Button tone="plain" type="button" onClick={stopCamera}>
              Stop the camera
            </Button>
          ) : (
            <Button tone="plain" type="button" disabled={change.busy} onClick={() => void startCamera()}>
              <Camera size={16} /> Scan with the camera
            </Button>
          )}
        </div>
        {scanning ? (
          <video ref={video} muted playsInline className="w-full max-w-sm rounded-lg border border-slate-300" />
        ) : null}
      </form>
    </Card>
  );
}
