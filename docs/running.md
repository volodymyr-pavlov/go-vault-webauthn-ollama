# Running, settings and the API

This page is the reference for running the service. It covers the requirements, the commands, the settings, the stand,
the Vault notes, the API and the tests.

## Requirements

- Go 1.27.
- Docker, for the stand and for the integration tests.
- `make`.

## Commands

| Command                 | What it does                                                                              |
| ----------------------- | ----------------------------------------------------------------------------------------- |
| `make stand-up`         | Builds and starts Vault (dev mode, local only), MySQL, Redis, Mailpit, Ollama and the backend on `:8080`. The first start pulls the model. |
| `make stand-logs`       | Follows the backend: one line for each request.                                           |
| `make stand-mail`       | Opens Mailpit, where the verification tokens and the notices land.                        |
| `make stand-down`       | Stops the stand. The MySQL data stays.                                                    |
| `make stand-reset`      | Stops the stand and wipes MySQL. It is needed after Vault restarted.                      |
| `make cluster-up`       | Builds and starts the cluster (two backends, Vault Raft, MySQL with a replica, Redis with Sentinel). The page is on `:3100`, the API on `:8180`. Run `make stand-up` once first, so that the model volume exists. |
| `make cluster-status`   | Shows the Vault Raft peers, the MySQL replication and the Redis master.                   |
| `make cluster-promote`  | Makes `mysql-replica` the primary and points the backends at it. It is a manual failover. |
| `make cluster-down`, `make cluster-reset` | Stops the cluster, or stops it and wipes its data.                      |
| `make rewrap-totp`      | Rotates the TOTP key and rewraps every stored secret.                                     |
| `make recovery-list`    | Lists the open recovery requests: the XID, the user, the state and the time the delay ends. |
| `make recovery-approve XID=n` | Approves the recovery request `n` after the operator checked the owner. It works only after the delay ends. |
| `make evaluate`         | Evaluates the risk engine on the synthetic dataset. It writes `out/evaluation.md`. With a model it needs a warm Ollama; the target passes `-timeout 3m`, and `EVALUATE_ARGS` replaces that. The flags `-per` and `-timeout` exist. |
| `make test`             | The unit tests. No Docker needed.                                                         |
| `make test-race`        | The same, with the race detector.                                                         |
| `make test-integration` | The stores on MySQL, the API end to end and the Transit client on a real Vault.           |
| `make frontend-dev`     | The Vite dev server of the page on `:3000`, with `/v1` passed to the backend on `:8080`.  |
| `make frontend-check`   | The type check, the unit tests and the Prettier check of the page.                        |
| `make frontend-e2e`     | The Playwright tests of the page against the running stand, on Chromium, Firefox and WebKit. Run `make stand-up` first. |
| `make fuzz`             | The two fuzz tests, twenty seconds each.                                                  |
| `make verify`           | `gofmt`, `go vet`, the style checks, `golangci-lint`, `staticcheck`, `govulncheck`, `gosec`, `gitleaks` and `go mod verify`. |

`make stand-up` writes the secrets of the stand into `.env` once: the root token of the dev-mode Vault and the password
of the MySQL user. Git ignores `.env`. `.env.example` lists every setting. The repository holds no secret, and
`make gitleaks` checks this.

## Vault in the stand

Vault in dev mode keeps its keys in memory. When the container restarts, the keys are gone, and every TOTP secret in
MySQL becomes a ciphertext that nothing can decrypt. The stand treats this as a lost key. `make stand-reset` wipes
MySQL, and the users register again.

The `vault-init` job runs on every `up`. It enables Transit and the TOTP engine, creates the two keys, writes the policy and the AppRole,
and leaves the role ID and a wrapped secret ID in a volume. The backend unwraps the secret ID when it starts, which
uses up the token.

## The API

Every response is an envelope with `data` or `error`. An error has a stable number and code. The contract is in
[openapi.yaml](openapi.yaml).

A device signs every request with a key that it keeps, and the service issues no token. `POST /v1/session` carries the
public key of the device, and the session keeps it. Every request carries three fields: `Content-Digest` (RFC 9530),
`Signature-Input` and `Signature` (RFC 9421). The signature covers the method, the path and the digest of the body. It
also covers the time, the key ID, the algorithm `ed25519`, a nonce and a final `;tag="<session_xid>"` parameter.
`POST /v1/session` signs without the tag.

The tag names the session. The server reads that session, checks that the key ID belongs to it, and checks the signature
against the key of the session. It refuses a request in these cases:

- The time of the request is more than a minute from the server time. The server answers 401 `STALE_REQUEST_TIME` with
  `params.server_time` in Unix seconds, and the page computes an offset and tries once more.
- The server has seen the nonce before.
- The request has a query string, because the signature does not cover it.

One browser key can hold many sessions, one for each tab, and the page keeps the identifier in `sessionStorage`. The page
signs with a WebCrypto key that cannot be exported. `curl` cannot sign, so `scripts/signed-request.mjs` signs for a
shell. It saves the session identifier in `.bin/session` and adds the tag to every later request:

```shell
# Open a session for the device. Every flow starts here.
node scripts/signed-request.mjs POST /v1/session '{"device_id":"my-laptop"}'
# 201 {"data":{"session_xid":"104...","expires_at":"2026-11-17T10:00:00Z"}}

# Register. The response is the same for a new address and for a taken one.
# The verification token goes to Mailpit: see `make stand-mail`.
node scripts/signed-request.mjs POST /v1/register '{"email":"a@example.com","password":"correct horse battery staple"}'
# 202 {"data":{"flags":6}}

node scripts/signed-request.mjs POST /v1/register/complete '{"token":"<64 hex digits from the mail>"}'
# 200 {"data":{"user_xid":"104..."}}

# Enroll a passkey. The options go to navigator.credentials.create.
node scripts/signed-request.mjs POST /v1/enroll/passkey
```

| Path                                | What it does                                                             |
| ----------------------------------- | ------------------------------------------------------------------------ |
| `POST /v1/session`                  | Opens a session.                                                         |
| `GET /v1/session`                   | Shows the flags of the session.                                          |
| `DELETE /v1/session`                | Logs out.                                                                |
| `POST /v1/register`, `/complete`    | Registers a user and verifies it.                                    |
| `POST /v1/enroll/passkey`, `/complete` | Enrolls a passkey.                                                    |
| `POST /v1/enroll/totp`, `/complete` | Enrolls a code generator. The secret is shown once.                      |
| `POST /v1/enroll/recovery`          | Issues recovery codes. They are shown once.                              |
| `POST /v1/auth/passkey`, `/complete`| Logs in with a passkey. Without an email the login is discoverable: the passkey names the user. |
| `POST /v1/auth/password`, `/v1/auth/totp` | Logs in with a password and a code.                                |
| `POST /v1/auth/recovery`            | Uses a recovery code. The session may then enroll a factor and do nothing else. |
| `POST /v1/recover/request`          | Starts a recovery with an email. Always 202. A delay starts and the owner receives a cancel token. |
| `POST /v1/recover/cancel`           | Cancels the open request with the cancel token. 204.                     |
| `POST /v1/recover/claim`            | Emails the grant token for an approved request. Always 202.              |
| `POST /v1/recover/grant`            | Uses the grant token. The session may then enroll a factor and do nothing else. |
| `GET /v1/sessions`                  | Lists the logged-in sessions of the user: `session_xid`, `country`, `created_at`, `last_seen_at` and `current`. |
| `DELETE /v1/sessions/{session_xid}` | Ends another session of the user. Needs a fresh login. 404 `NOT_FOUND_DEVICE` for a session of another user, 400 `NO_PARAM_SESSION_XID` without an identifier. |
| `POST /v1/accounts`            | Adds one account (a link or a secret) or all the accounts of a Google Authenticator export. Needs a fresh login. |
| `GET /v1/accounts`             | Lists the accounts with their current codes.                             |
| `DELETE /v1/accounts/{account_xid}` | Removes an account and its secret. Needs a fresh login.   |
| `GET /v1/passkeys`                  | Lists the passkeys, without key material.                                |
| `POST /v1/passkeys/{passkey_xid}/removal`, `/confirm` | Removes a passkey after a fresh passkey assertion whose challenge is bound to the removal. The last factor cannot be removed. |
| `GET /v1/user/export`            | Exports the personal data of the user. Needs a fresh login.           |
| `POST /v1/user/deletion`, `/confirm` | Deletes the user and its data. Needs a fresh login and, for a user with a passkey, a passkey assertion bound to the deletion. |
| `DELETE /v1/totp`                   | Removes the code generator.                                              |

Recovering access for a user who lost every factor and every code needs a person. The delay is `-recovery-delay`, 72 hours by
default, and the stand uses the default:

```shell
# The owner starts the request. The cancel token goes to Mailpit.
node scripts/signed-request.mjs POST /v1/recover/request '{"email":"a@example.com"}'
# 202 {"data":{"flags":2}}

# The owner can cancel with the token from the notice.
node scripts/signed-request.mjs POST /v1/recover/cancel '{"token":"<64 hex digits from the mail>"}'
# 204

# The operator checks the owner outside the service. After the delay ends:
make recovery-list
make recovery-approve XID=104...

# The owner claims the approved request. The grant token goes to Mailpit and works for one hour.
node scripts/signed-request.mjs POST /v1/recover/claim '{"email":"a@example.com"}'
# 202 {"data":{"flags":2}}

node scripts/signed-request.mjs POST /v1/recover/grant '{"token":"<64 hex digits from the mail>"}'
# 200 {"data":{"flags":130}}
```

Each call is signed on a started session. `make recovery-approve` refuses a request whose delay has not ended.

The integration tests in `apps/backend/server` run every flow from start to end with a software authenticator. They are
the best worked examples.

## Settings

The server takes flags. Run `server -help` to see the list. The stand sets them in `compose.yaml`, and `.env` fills the
ones that change.

| Flag                    | What it does                                                                              |
| ----------------------- | ----------------------------------------------------------------------------------------- |
| `-session-idle`         | The idle timeout of a session. The default is 168h. A session also ends after 30 days.    |
| `-session-retention`    | How long an expired session stays before an hourly job deletes it. The default is 90 days. |
| `-request-log-retention` | How long the rows of the request log stay before an hourly job deletes them. The default is 30 days. |
| `-recovery-delay`       | The delay of a recovery request. The default is 72h.                                      |
| `-metrics`              | The address of the metrics listener, such as `:9090`. The default is off.                 |
| `-smtp-starttls`        | Upgrades the mail connection with STARTTLS. Off by default.                               |
| `-smtp-implicit-tls`    | Uses TLS from the first byte. Off by default. It excludes `-smtp-starttls`.               |
| `-smtp-user`            | The user name for AUTH PLAIN. The service never sends AUTH PLAIN without TLS.             |
| `-smtp-password-file`   | The file that holds the SMTP password.                                                    |
| `-smtp-tls-server-name` | The name to check in the certificate of the mail server.                                  |

The mail client uses TLS 1.2 or newer with the system roots, and it never skips the certificate check. Plain SMTP is
only for local stands such as Mailpit. The operator must choose a real mail provider.

The server counts requests for each address (60 a minute), for each user (20 a minute) and for the whole service (500
a second). Opening sessions has its own limit of 20 a minute for each address.

With `-metrics=:9090`, the server serves `GET /metrics` on a separate listener. The stand turns it on and does not
publish the port:

```shell
docker compose exec backend wget -qO- http://127.0.0.1:9090/metrics
```

## Tests

- `make test` runs the unit tests: forged and replayed requests, the RFC 6238 vectors, the ceremonies with a software
  authenticator, hostile model outputs, the rate limits, the metrics, the signal bitset, the bound confirmation of an
  action, the named events of the request log and the `recovery` command.
- `make test-integration` starts MySQL and Vault containers. It runs the stores (including the recovery requests and the
  request log), every API flow and the Transit client.
- The fault tests stop Vault, Redis or MySQL, use a slow or hostile Ollama, send a replayed nonce 20 times at once and
  run parallel logins. Run them with `go test -tags integration -race -run Fault ./server` in `apps/backend`.
- `make frontend-e2e` drives the page against the stand on Chromium, Firefox and WebKit, with Mailpit for the
  verification token. The passkey specs run only on Chromium, because they need its virtual authenticator. The specs
  cover registration, logins, sessions and devices, and refusals.
- `make recovery-list` and `make recovery-approve XID=n` are the commands of the operator.
- `make fuzz` fuzzes the parser of the model response and the parser of the Vault `vault:vN:` form.
- Run the tests with `-race`. `make test-race` does this.

## The page

The page is in `apps/frontend`. It uses React, TypeScript, Tailwind and Zustand, and Vite builds it. `make stand-up`
serves it at `http://localhost:3000` through nginx, which also passes `/v1/` to the backend. The page and the API share
one origin, so the browser needs no CORS and a passkey is bound to that origin. The backend lists the origin in
`ORIGINS`. It trusts the Docker networks in `TRUSTED_PROXIES`, so it can read the real address of the browser from
nginx.

WebCrypto creates the key of the device with `extractable: false`, and the page keeps it in IndexedDB. The page signs
every request with this key. A tab keeps its session identifier in `sessionStorage` and names it in every signature.
So a reload finds the session again, and several tabs that use one key hold several sessions. When a session has ended,
the page opens a new one with the same key.

The screen of a logged-in user has a header and three tabs. The header shows the login decision and the prompt for a
fresh login, and it has the Log out button. The **Codes** tab opens first and holds the authenticator: the one-time codes
of the accounts of other services. The **Security** tab holds the passkeys, the authenticator app for the login, the
recovery codes and the Devices panel, which lists the sessions and ends another one. The **Data** tab shows the session
and has the download and the deletion of the data.

A login without an email uses a passkey that the browser finds by itself. A sensitive action that needs a fresh login
asks for the passkey again on the same session. Removing a passkey asks for a passkey assertion that is bound to that
removal.

The screens follow the flags of the session. A guest can log in, register or recover. A verified registration or a
recovery code can add the first factor. A logged-in session shows its codes and manages its passkeys, its authenticator app, its
recovery codes and its data.

`make frontend-dev` runs the Vite server on `:3000` and passes `/v1` to a backend on `:8080`. Its origin,
`http://localhost:3000`, is in the default `ORIGINS` of the stand.
