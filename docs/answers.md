# Questions and answers

## (a) Why WebAuthn resists phishing and TOTP does not

A passkey signs a challenge together with the origin of the page. The browser also lets the authenticator use a
credential only for the site that it was made for. A fake site has a different origin, so the signature that it collects
is worth nothing, and the service checks the origin and the RP ID. A TOTP code is only six digits that the user types.
It says nothing about where the user typed it, so a fake site can pass it to the real site within its time step.

## (b) What a stolen database gives, and what changes with the Vault token

The database gives an attacker the emails, the Argon2id hashes, the public keys of the passkeys, the TOTP ciphertexts
and the keyed hashes of the recovery codes. The attacker can only grind the Argon2id hashes one by one. The public keys
cannot sign anything. The ciphertexts are bound to their users and open only through Vault. Nobody can guess the keyed
hashes offline.

If the attacker also has the Vault token, they can decrypt the TOTP secrets through Transit for as long as the token
lives. The token lives for fifteen minutes, and the policy never returns key material. The audit log of Vault shows
every call.

## (c) How replay and brute force of a six-digit code are stopped

The service stores the last time step that it accepted for each user. It refuses a code from that step or an earlier
one, so a code works only once. The accepted window is one step in either direction, and the comparison takes the same
time for every input. Each user has a budget of twenty tries a minute in Redis, with a delay that grows. Each
address and the whole service have budgets too. Opening a session has its own budget of 20 a minute for each address.
The service never locks a user, so an attacker cannot keep the real owner out.

## (d) How a stolen or replayed request is stopped, and how the TOTP key rotates

The device signs every request with its Ed25519 key. The signature covers the method, the path and the digest of the
body, so nobody can change a request or move it to another endpoint. The signature also names its session in a `tag`
parameter, so one browser key can hold a session in each tab. The time of the request must be within one minute of the
server time. If the clock is wrong, the service answers 401 STALE_REQUEST_TIME with the server time, and the page tries
once more. A nonce works only once (Redis keeps it for two minutes), so nobody can send a captured request again. The
browser keeps the private key and does not let a script export it. Revoking a session sets its Revoked flag, and every
request checks the flag. There is no token to steal.

Vault now holds only the `totp` and `mac` keys, and the check of a request does not call Vault. `make rewrap-totp`
rotates the TOTP key and rewraps every stored secret inside Vault, so nobody is logged out.

## (e) What an attacker targets when recovery or enrollment is weak

The attacker adds a factor of their own, or resets the user through a channel that is weaker than the factors. In
this service, adding or removing a factor needs an existing factor within the last five minutes. A recovery code is
single-use, has 80 bits and is stored as a keyed hash. It lets the session enroll one factor, and it does not log the
user in. Every change sends a notice to the user. The service has no reset by email alone.

## (f) Why a synced passkey may report a counter of zero

A passkey that a platform syncs between devices has no single hardware counter, so it reports zero every time. The
service skips the counter check only when the stored counter and the received counter are both zero. In every other
case, a counter that does not grow disables the passkey, refuses the login and sends a notice to the user.

## (g) Why the model is only advisory

A model can be pushed to say anything, and it gives different answers on different days. So the model may only add
verification. It can never remove verification, and the service never allows a login because the model said so.

The model gets a keyed pseudonym, a country, a four-hour bucket of the day, the factor, the names of the signals and two
counts. It gets nothing that a user typed and nothing personal. A local model keeps even this data on the same machine,
costs nothing for each call and has no account that can leak.

Each call has a timeout, and at most two calls run at the same time. After three failures, a breaker stops the calls for
thirty seconds. The service treats a late or bad answer as no advice. The temperature is zero, so the same summary
usually gives the same answer. A strict check refuses any answer outside the closed set of levels and reasons.

## A recovery flow for a user who lost everything

An email alone cannot let in a user who has no factor and no recovery code. A phisher, or a thief who holds the phone,
often controls the email account. With an email-only reset, every passkey would be worth only one email.

The flow runs in the backend:

1. The user asks for recovery with the email (`POST /v1/recover/request`). The answer is always 202, so it does not show
   whether the user exists. If the user is verified and enabled and has no open request, the service stores a
   request and emails the owner a notice with a single-use cancel token.
2. The request waits for the delay, which is 72 hours by default (`-recovery-delay`). The owner can cancel the request at
   any time with the token (`POST /v1/recover/cancel`). A login with any factor, or with a recovery code, cancels it
   too.
3. An operator checks the owner outside the service and approves the request with `make recovery-list` and
   `make recovery-approve XID=n`. The command refuses to approve before the delay ends. For a financial product, the
   check can be a phone call or a video call.
4. The owner claims the approved request (`POST /v1/recover/claim`). The answer is always 202. Only for an approved
   request, the service emails a single-use grant token that works for one hour.
5. The owner sends the grant (`POST /v1/recover/grant`). The service revokes every other session of the user, puts
   the current session in the recovery-approved state, and sends a notice to the owner. This session can enroll a new
   factor and do nothing else.

The delay gives the real owner time to notice the request and cancel it. The approval stops a thief who controls the
mailbox, because the thief also receives the notice.

Some parts stay manual or weak. The human check happens outside the code. The service only records that an operator
approved, and it cannot tell whether the check was good. Email is the only channel, so a thief who controls the mailbox
sees the notice and can cancel the request. The stand sends no notice through a second channel, such as an SMS or a
push message to a device that is still logged in. A real deployment needs a second channel and a written procedure for
the operator check. The tests are `TestRecoveryOfLostFactors`, `TestRecoveryGrantExpires` and
`TestLoginCancelsRecovery`.
