import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';

/** The props of [Card]. */
interface CardProps {
  /** The heading of the section. */
  title: string;
  /** The content of the section. */
  children: ReactNode;
}

/** Shows a titled section that wraps its children. */
export function Card({ title, children }: CardProps) {
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <h2 className="mb-4 text-lg font-semibold">{title}</h2>
      <div className="space-y-4">{children}</div>
    </section>
  );
}

/** The props of [Field]. It accepts every prop of an input element, and passes the other props to it. */
interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  /** The text of the label. */
  label: string;
  /** A short help text below the input. */
  hint?: string;
}

/** Shows a text input with a label and an optional hint below it. */
export function Field({ label, hint, ...input }: FieldProps) {
  return (
    <label className="block space-y-1">
      <span className="text-sm font-medium">{label}</span>
      <input
        className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 dark:border-slate-700 dark:bg-slate-950 dark:focus:ring-indigo-900"
        {...input}
      />
      {hint ? <span className="block text-xs text-slate-500 dark:text-slate-400">{hint}</span> : null}
    </label>
  );
}

/** The look of a [Button]. */
type Tone = 'primary' | 'plain' | 'danger';

const tones: Record<Tone, string> = {
  primary: 'bg-indigo-600 text-white hover:bg-indigo-500 disabled:bg-indigo-300',
  plain: 'border border-slate-300 hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800',
  danger:
    'border border-red-300 text-red-700 hover:bg-red-50 dark:border-red-900 dark:text-red-300 dark:hover:bg-red-950',
};

/** The props of [Button]. It accepts every prop of a button element, and passes the other props to it. */
interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** The look of the button. The default is primary. */
  tone?: Tone;
}

/** Shows a button in the given tone. */
export function Button({ tone = 'primary', ...button }: ButtonProps) {
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60 ${tones[tone]}`}
      {...button}
    />
  );
}

/** The props of [Notice]. */
interface NoticeProps {
  /** The kind of the message. It sets the color and the ARIA role: an error is an alert, the others are a status. */
  kind: 'error' | 'info' | 'warning';
  /** The text of the message. */
  children: ReactNode;
}

/** Shows a message in a colored box, so the person sees what happened. */
export function Notice({ kind, children }: NoticeProps) {
  const styles = {
    error: 'border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-200',
    info: 'border-sky-200 bg-sky-50 text-sky-800 dark:border-sky-900 dark:bg-sky-950 dark:text-sky-200',
    warning: 'border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200',
  };

  return (
    <div role={kind === 'error' ? 'alert' : 'status'} className={`rounded-lg border px-3 py-2 text-sm ${styles[kind]}`}>
      {children}
    </div>
  );
}
