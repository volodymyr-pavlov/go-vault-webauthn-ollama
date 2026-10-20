# How the service is built

This page explains the parts of the service, how they work together, and why the team shaped them this way.

## The path of a login

A client opens a session for its device. It sends the public key of the device, an Ed25519 key, in the body. The service
creates a row that holds the key and its key ID, and returns the session identifier and the time when the session
expires. There is no token. The row says what the session may do, and the service reads the row on every request.

The device signs every request with its private key under RFC 9421. Each request also carries the digest of its body
under RFC 9530. Three fields carry this data: `Content-Digest`, `Signature-Input` and `Signature`. The signature covers
the method, the path and the digest. Its parameters are the time, the key ID, the algorithm, a nonce and a final `tag`
with the identifier of the session. Only `POST /v1/session` is signed without the tag, because no session exists yet.

The middleware reads the session by the tag, checks that the key ID belongs to the session, and checks the signature
with the key of the session. It refuses these requests:

- A request whose time is more than one minute from the server time. The answer is 401 `STALE_REQUEST_TIME` with
  `server_time` in Unix seconds, so the page can compute an offset and try once more.
- A request with a nonce that was used before. Redis remembers each nonce of a key for two minutes (`SETNX`).
- A request with a query string.

One browser key can hold many sessions, one for each tab. The page keeps the session identifier in `sessionStorage`.

Each step that succeeds sets a bit on the row. A verified registration, a password, a code, a passkey assertion and a
recovery code each have a bit. When the last factor of the policy passes and the risk is acceptable, the session gets
the Authorized bit.

## The life of a session

A session ends when someone revokes it, after the idle timeout (`-session-idle`, 7 days by default) or after the
absolute lifetime of 30 days. The session middleware records `last_seen_at` at most every 5 minutes.

`GET /v1/sessions` lists the logged-in sessions of the account. Each entry has an identifier, a country, a creation time,
a last-use time and a `current` mark. `DELETE /v1/sessions/{session_xid}` ends another session. It needs a fresh login,
and it answers 404 `NOT_FOUND_DEVICE` for a session of another account. The Account screen shows this list as the
Devices panel.

An hourly job deletes the sessions that expired more than `-session-retention` ago (90 days by default). This period is
longer than the 30-day window of the risk history.

Every endpoint has a permission. The permission lists the bits that a session must have, and sometimes the bits that it
must not have. A middleware checks the permission before the handler runs, so a handler never decides who may call it.

## The policy

- An account without a passkey logs in with a password and then a TOTP code. It needs both.
- An account with at least one passkey logs in with a passkey only. User verification is required. The service refuses
  the password and the code for this account, so a phished password cannot downgrade the login. A disabled passkey still
  counts as a passkey.
- Adding or removing a factor needs the last factor within five minutes. The last factor cannot be removed.
- Removing a passkey also needs a fresh passkey assertion. The challenge is the SHA-256 hash of a domain string, 32
  random bytes, the action and the passkey. It works once, for two minutes, and for this passkey only.
- A registration is finished with a single-use token that arrives outside the service. Until then, the account cannot
  log in.

## The parts

| Part               | What it does                                                                                                   |
| ------------------ | -------------------------------------------------------------------------------------------------------------- |
| `frontend`         | The page: a React app on nginx. It shares one origin with the API, so a passkey is bound to it.                |
| `es`               | The data contract: the six tables, their flags, the small store interfaces and the permissions.               |
| `mysql`            | The only backend of the stores. The static statements are SQL files that are embedded in the binary.           |
| `vault`            | The Transit client and the AppRole login that renews its token.                                                |
| `vaulttest`        | A stand-in Transit server for the tests.                                                                       |
| `auth`             | Passkeys over go-webauthn, Argon2id passwords and the check of the request signature.                          |
| `authtest`         | A software authenticator for the tests.                                                                        |
| `smtp`             | The mail client and the sender that writes each message from an embedded template.                             |
| `totp`             | RFC 6238, with the test vectors of the RFC.                                                                    |
| `ai`               | The risk rules, the decision, the strict check of an advice, and the Ollama client, which uses langchaingo.                            |
| `api`              | The handlers, the middleware, the permission table and every error.                                            |
| `web`              | The HTTP plumbing on fasthttp: the mux, the error envelope, the JSON decoding and the RFC 9421 fields.         |
| `validate`         | The checks of the strings that a client sends.                                                                 |
| `geo`              | The address behind the trusted proxy, and a mock geo-IP table.                                                 |
| `config`, `server` | The composition root, and the routes.                                                                          |
| `cmd/recovery`     | The command of the operator. It lists the open recovery requests and approves one.                             |
| `metrics`          | The Prometheus series, and the wrapper that counts the requests, the limits and the decisions.                 |

## Six tables

A user row holds the password hash and the TOTP ciphertext. A passkey row is one credential. A recovery code row is the
keyed hash of one single-use code. A recovery request (`recovery_requests`) is one attempt of a user without any factor
to get back in. It holds the SHA-256 of the cancel token, the SHA-256 and the expiry of the grant token, and the time
when the delay ends. A session row is the sign-in of one device. The sixth table, `http_requests`, is the request log; see below.

Each table has one `flags bigint unsigned` column for all of its state. Each row has an internal key that never leaves
the service, and an external snowflake identifier that the API and the logs carry.

The session row also holds the state of the step in progress: the hash of the verification token and the WebAuthn
challenge. The sessions of a user are also the login history that the risk engine reads.

## The request log

After each handler finishes, the request log middleware writes one row into the `http_requests` table. The row holds the
endpoint, the method, the status, the error number, the duration, the external IDs of the session and the user, the
address, the path, the request ID, the host, the user agent and the version of the service. Handlers can also add a
named event, such as `login` or `passkey_removed`, with a few safe attributes.

The row holds no body, no query and no credential, because the bodies of this service carry passwords, codes and
tokens. For a request that failed in an unexpected way, it holds the first part of the error text. If the service
cannot save the row, it logs the problem and does not change the answer. Nothing in the service reads the log back. The
log is a trail for support. Because the rows hold the address and the user agent, an hourly job deletes the rows that
are older than `-request-log-retention` (30 days by default). The log lines on the standard output show only the
network of the address: the first 24 bits of an IPv4 address and the first 48 bits of an IPv6 address.

## Metrics

`-metrics=:9090` (off by default) serves `GET /metrics` on a separate listener. The stand turns it on and does not
publish the port. The series are:

- `login_http_requests_total{resource,status}`
- `login_http_request_duration_seconds{resource}`
- `login_rate_limited_total{scope}`
- `login_login_decisions_total{decision}`
- `login_advisor_outcomes_total{outcome}`
- `login_recovery_events_total{event}`
- `login_session_events_total{event}`
- `login_auth_failures_total{factor}`

The Go and process collectors are included. The label values are limited: they never hold an email, an address or an
identifier. A 429 from the global limit is counted only in `login_rate_limited_total`. To read the metrics in the
stand, run `docker compose exec backend wget -qO- http://127.0.0.1:9090/metrics`. Dashboards, alert rules and tracing are
not built.

## One step is one statement

A challenge must be accepted only once. A lock is the wrong tool for this job. The `WHERE` clause is the right tool.

The update that uses up a recovery code matches only an unused code of the user, so a code works only once. The update
that clears a challenge matches only a session that still holds the challenge. The first request clears it. The second
request matches nothing and gets the same plain refusal as a bad signature.

The handler checks the WebAuthn response after it has used up the challenge. A bad response costs the client a new
challenge. This order makes a replay impossible, not only unlikely.

## Recovery of a lost account

An email alone cannot let in a user who lost every factor and every recovery code. The flow adds a delay and a person.

1. `POST /v1/recover/request` creates a row in `recovery_requests`, with `ready_at` set to the end of the delay (72
   hours by default, `-recovery-delay`). It emails a cancel token to the owner. The answer is always 202. Only a
   verified, enabled account with no open request gets a row.
2. `POST /v1/recover/cancel` closes the open request that has the token. The token works once. A login with a passkey,
   with a password and a code, or with a recovery code also closes the open request of the account.
3. The operator runs `recovery list` and `recovery approve XID` (`make recovery-list`, `make recovery-approve XID=n`).
   The update that approves matches only an open request whose `ready_at` has passed, so it fails before the delay
   ends. The `recovery` command talks to MySQL directly and has no API.
4. `POST /v1/recover/claim` always answers 202. Only for an approved request, it stores the hash of a new grant token and
   emails the token. The grant works for one hour.
5. `POST /v1/recover/grant` uses up the grant in one statement, so it works only once. It revokes every other session of
   the account, puts the session in the recovery-approved state and sends a notice to the owner. The session can enroll
   a factor and do nothing else, as after a recovery code. A wrong, used or expired grant gives 401 and counts as a
   failure of the session.

The four endpoints need only a started session. The request and the claim have a rate limit for each account, like
registration.

## Vault

The service logs in with AppRole. The init job gives it a wrapped secret ID, which is a token that can be unwrapped only
once. The backend unwraps it at start-up, so no secret stays in a file.

Vault holds two keys, `totp` and `mac`, and the policy has four paths. The service can encrypt, decrypt and rewrap with
the TOTP key, and it can make an HMAC with the MAC key. It cannot export, back up, rotate, configure or read any key.
Vault is not on the path of a request signature, because the check uses the public key of the device from the session
row.

If the token cannot be renewed and the new login fails, the service does not stop. It tries again with a delay that grows from 1 to 30 seconds. Until a login succeeds, the operations that need Vault fail.

The TOTP key is derived. Each call uses the ID of the user as the context, so a ciphertext that someone copies into
another row does not decrypt.

## Decisions and trade-offs

- **MySQL.** The other projects of the series use it, and the data layer has the same shape as the author's production
  code.
- **Redis for rate limits.** Several instances of the service share the budgets, and a restart forgets nothing.
- **A session row, not claims in a token.** A claim says what was true when the service made the token. A flag says what
  is true now. Revocation, risk decisions and fresh authentication become bits, and nothing needs to be invalidated.
  Revoking a session sets its Revoked flag, and every request checks the flag.
- **A signed request, not a secret that is sent.** A leaked token works for whoever holds it. A signature works only with
  the private key, and it covers one method, one path and one body. The browser keeps the key and does not let a script
  export it.
- **Ed25519 for the device key.** The key is small, the signature is 64 raw bytes, and WebCrypto in current browsers can
  make it. The key ID is the base64url SHA-256 of the 32 key bytes.
- **No attestation check.** The service stores the attestation format and nothing else. An allowlist of certified
  authenticators would refuse the synced passkeys that most users have.
- **The rules decide.** The model can add verification and nothing else.

## The habits of the code

- States are bit flags in one column. Identifiers are unsigned.
- Every error is declared in the `errors.go` file of its package.
- A composite literal gives each field its own line. `make check-style` checks this.
- A store method reads its own statement, scans its own columns and checks its own rows. No helper hides a step.
- A client of an outside service, such as Vault or Ollama, is a concrete type. The tests run it against a small HTTP
  server.
- A JSON body is a typed struct that gjson decodes. The service refuses a field that the endpoint does not know.

## The cluster

`make cluster-up` starts `compose.cluster.yaml`, a second compose project for local tests of high availability. It runs:

- **Two backends** (`-instance` 0 and 1) behind an nginx load balancer, and the page on `http://localhost:3100`. Each
  backend gets its own Vault wrapping token, because a wrapping token works once.
- **Vault with Raft**, three nodes behind one nginx address. The `vault-cluster` job initializes the first node, joins
  the others and unseals all three. It keeps the single unseal key and the root token in a volume, which is only for
  local use. A node that restarts is sealed, and `make cluster-up` unseals it again.
- **MySQL** with a primary and a replica on GTID replication. The backends write to the primary. The failover is manual:
  `make cluster-promote` stops the replication, makes the replica writable and points the backends at it.
- **Redis** with a master, a replica and three Sentinels. The backends follow the master that the Sentinels name
  (`-redis-sentinels`, `-redis-master`). A failover can lose the nonces and the rate limit counters of the last moments.

The backends apply the migrations under a MySQL lock (`GET_LOCK`), so two backends that start together do not run the
same migration twice. If the login to Vault fails, a backend keeps running and tries again.

`make cluster-status` shows the Raft peers, the state of the replication and the Redis master. Ollama, Mailpit and the
page are single containers. The load balancer, the Sentinels and the failover of MySQL are not tested in CI.

## Exposure

The backend (8080), the page (3000), Mailpit (8025) and the dev-mode Vault (8200) have a published port, and only on loopback. Ollama has no published port, because it runs
on an internal network. Vault in the stand runs in dev mode. It keeps its keys in memory, so a restart of Vault loses
every stored ciphertext. The stand treats this as a lost key, and `make stand-reset` wipes the database too.

In production, Vault runs with TLS, sealed storage that several key holders unseal, an audit device and a policy that
an operator applies. The keys then survive a restart, and nothing is wiped.

## Limits

- The stand has one MySQL, one Redis and one Vault node. The service itself keeps no state, so more instances can run.
  Each running instance needs its own `-instance` number, from 0 to 63, because the number is part of every external
  identifier.
- The geo-IP table is a mock with eight prefixes. The travel and hour signals are only as good as this table.
- The page keeps the device key in IndexedDB as a key that cannot be exported. A script on the page cannot read it, but
  the script can still ask the browser to sign while the page is open.
- A session ends after 7 days without use (`-session-idle`) or after 30 days, and there is no refresh. Then the device
  opens a new session with a login.
- Rate limits: 60 requests a minute for each address, 20 a minute for each account, 500 a second for the whole service,
  and 20 new sessions a minute for each address.
- By default, the mail client sends plain SMTP, which is only for local stands. `-smtp-starttls` or `-smtp-implicit-tls`
  (not both) turns on TLS, together with `-smtp-user`, `-smtp-password-file` and `-smtp-tls-server-name`. The client
  never sends AUTH PLAIN without TLS. It uses TLS 1.2 or newer with the system roots, and it never skips certificate
  checks. The operator must choose a real mail provider.
- Nothing protects the request log from a person with write access to the database, and nothing reads it back.
- If Redis is down, the service cannot check the nonce, so requests fail instead of passing.
