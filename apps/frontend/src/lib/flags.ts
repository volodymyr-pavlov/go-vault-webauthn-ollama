/** The bits of the flags of a session, in the same order as the flags of the server. */
export const Flag = {
  Authorized: 1 << 0,
  Started: 1 << 1,
  RegistryBegun: 1 << 2,
  RegistryVerified: 1 << 3,
  PasswordApproved: 1 << 4,
  TOTPApproved: 1 << 5,
  PasskeyApproved: 1 << 6,
  RecoveryApproved: 1 << 7,
  Limited: 1 << 8,
  Review: 1 << 9,
  Revoked: 1 << 10,
} as const;

/**
 * Reports whether every bit of a mask is set in the flags.
 *
 * @param flags - The flags of a session.
 * @param mask - The bits to test.
 * @returns True when all bits of mask are set.
 */
export function has(flags: number, mask: number): boolean {
  return (flags & mask) === mask;
}

/**
 * Reports whether the session may add a first factor.
 *
 * This is true when the session is not logged in and has either a verified registration or an approved recovery code.
 *
 * @param flags - The flags of a session.
 * @returns True when the person may enroll a factor.
 */
export function canEnroll(flags: number): boolean {
  return !has(flags, Flag.Authorized) && (has(flags, Flag.RegistryVerified) || has(flags, Flag.RecoveryApproved));
}
