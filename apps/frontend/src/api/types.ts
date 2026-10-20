// The shapes of the Vault Login API. The identifiers are decimal strings, as the API sends them.

/** The answer to a request that opens a session. */
export interface SessionOpened {
  /** The identifier of the session. */
  session_xid: string;
  /** The time when the session ends, in RFC 3339 format. */
  expires_at: string;
}

/** The current state of the session of the device key. */
export interface SessionState {
  /** The identifier of the session. */
  session_xid: string;
  /** The set of session flag bits. See [Flag]. */
  flags: number;
  /** The identifier of the account. It is missing until the session knows the account. */
  user_xid?: string;
  /** The risk score of the session, from 0 to 100. */
  risk_score: number;
  /** The time when the session ends, in RFC 3339 format. */
  expires_at: string;
}

/** Describes one logged-in session of an account, which stands for one browser tab. */
export interface DeviceView {
  /** The identifier of the session. */
  session_xid: string;
  /** The country the session was opened from. It is missing when the server did not find one. */
  country?: string;
  /** The time when the session was opened, in RFC 3339 format. */
  created_at: string;
  /** The time of the last request of the session, in RFC 3339 format. */
  last_seen_at: string;
  /** True for the session that made the request. */
  current: boolean;
}

/** The answer to a login that finished. */
export interface Authorized {
  /** The set of session flag bits after the login. See [Flag]. */
  flags: number;
  /** The result of the risk check: allow, limit or review. */
  decision: Decision;
  /** The identifier of the account. */
  user_xid: string;
}

/** The answer to a delayed recovery request or claim. It is the same whether or not the account exists. */
export interface RecoveryStatus {
  /** The flag bits of the session, which the call leaves as they are. */
  flags: number;
}

/** Describes one passkey of an account. */
export interface PasskeyView {
  /** The identifier of the passkey. */
  passkey_xid: string;
  /** The name that the person gave to the passkey. */
  name: string;
  /** The ways the passkey can connect to the device. */
  transports: string[];
  /** True when the passkey is synced to other devices. */
  backed_up: boolean;
  /** True when the passkey cannot be used to log in. */
  disabled: boolean;
  /** The time when the passkey was added, in RFC 3339 format. */
  created_at: string;
}

/** Holds what an authenticator app needs to add an account. */
export interface TOTPEnrollment {
  /** The shared secret in base32 text. */
  secret: string;
  /** The otpauth URI that holds the secret, for a QR code. */
  uri: string;
}

/** The error object of a response from the API. */
export interface ErrorBody {
  /** The HTTP status of the response. */
  status: number;
  /** The number of the error. */
  num: number;
  /** The name of the error. */
  code: string;
  /** The text of the error. */
  message: string;
  /** Extra values for the error. */
  params?: Record<string, unknown>;
}

/** The options that a begin step returns. The browser takes the inner publicKey object. */
export interface WebAuthnOptions {
  publicKey: PublicKeyCredentialCreationOptionsJSON & PublicKeyCredentialRequestOptionsJSON;
}

/** The result of the risk check of a login. */
export type Decision = 'allow' | 'limit' | 'review';
