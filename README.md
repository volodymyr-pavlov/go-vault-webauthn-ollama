# Go Vault WebAuthn Ollama

<div>
<a href="https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/actions/workflows/ci.yml"><img src="https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
<a href="https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/releases"><img src="https://img.shields.io/github/v/release/volodymyr-pavlov/go-vault-webauthn-ollama" alt="Latest release"></a>
<a href="apps/backend/go.mod"><img src="https://img.shields.io/badge/go-1.27-00ADD8.svg?logo=go&amp;logoColor=white" alt="Go 1.27"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</div>

This is a login service in Go. A user signs in with a passkey (WebAuthn). A password and a TOTP code are the fallback.
HashiCorp Vault keeps the keys. A local language model, run by Ollama, reviews each login for fraud.

```shell
make stand-up
make stand-mail
make stand-down
```

`make stand-up` builds and starts Vault, MySQL, Redis, Mailpit, Ollama, the backend and the page. The page is then on
`http://localhost:3000`, and the API is on `http://localhost:8080`. `make stand-mail` opens Mailpit, where the
verification tokens land. `make stand-down` stops the stand.

## What is this?

A login has to do two jobs that pull in different directions.

The first job is to be strict. A stolen database, a phished user or a stolen device must not be enough to get in.

The second job is to let the real user in, even after they lost a phone.

The service keeps the two jobs apart. The strict part is plain code: a signature on every request, a passkey that is
bound to the origin, Argon2id hashes, and TOTP secrets that only Vault can decrypt. The flexible part is a risk score
from fixed rules, which an Ollama model may argue to make stricter, and never looser. A user who lost every factor goes
through a recovery flow with a delay and a human operator.

The project is an exercise. It asks how much of this a small service can do with a few libraries, and how to prove it.

## What it does

- **Sign in with a passkey.** The browser signs a challenge together with the origin, so a fake site gets nothing.
- **Fall back to a password and a TOTP code.** Argon2id hashes the password. Vault Transit encrypts the TOTP secret.
- **Sign every request.** The device keeps an Ed25519 key and signs each request under RFC 9421. The service issues no
  token.
- **Score each login.** Rules turn the signals (a new device, an odd hour, an impossible trip) into a score from 0 to
    100. The model can only raise the level of the decision.
- **Recover access.** Recovery codes come first. After that, a request with a delay and the approval of an operator.
- **Replace an authenticator app.** Keep the TOTP accounts of other services in the service. Paste an otpauth link, scan
  a QR code or import a Google Authenticator export. Vault stores the secrets and makes the codes, so a secret never
  leaves Vault.
- **Run as a cluster.** Two backends, Vault on Raft, MySQL with a replica, and Redis with Sentinel.

## How it is built

| Part    | What it does                                                                                               |
|---------|------------------------------------------------------------------------------------------------------------|
| Backend | Go on fasthttp. The handlers, the middleware, the permission table of each endpoint and every error.       |
| Auth    | go-webauthn for passkeys, Argon2id for passwords, RFC 6238 for TOTP, RFC 9421 for request signatures.      |
| Vault   | Transit encrypts the TOTP secrets. The backend logs in with AppRole and renews its token.                  |
| MySQL   | Six tables. Each has one `flags` column for its state. Static statements are embedded SQL files.           |
| Redis   | The nonces of the signed requests and the rate limits.                                                     |
| Ollama  | A local model reviews a login. A strict check rejects any answer that is not in the allowed shape.         |
| Page    | React and Vite on nginx. It shares one origin with the API. WebCrypto holds a key that cannot be exported. |
| Tests   | Unit, fuzz, integration against real MySQL and Vault, and Playwright tests in three browsers.              |

Each state change is one SQL statement with a `WHERE` clause that matches only the state it expects. A challenge or a
recovery code therefore works once, without a lock. [docs/architecture.md](docs/architecture.md) has the details and the
decisions.

## Running it

It needs Go 1.27, Docker and `make`. The page needs Node.js to build outside Docker.

| Command                 | What it does                                                                       |
|-------------------------|------------------------------------------------------------------------------------|
| `make stand-up`         | Starts the stand. The first start pulls the model.                                 |
| `make cluster-up`       | Starts the cluster. The page is on `:3100`.                                        |
| `make test`             | The unit tests. No Docker needed.                                                  |
| `make test-integration` | The stores on MySQL, the API end to end and Transit on a real Vault.               |
| `make frontend-e2e`     | The Playwright tests against the running stand.                                    |
| `make evaluate`         | Evaluates the risk engine on the synthetic dataset and writes `out/evaluation.md`. |
| `make verify`           | Every check that needs no container: format, vet, lint, security scanners.         |

`make stand-up` writes the secrets of the stand into `.env` once. Git ignores that file, and the repository holds no
secret.

## More in docs

- [docs/running.md](docs/running.md): the requirements, every command, the settings, the stand, the API and the tests.
- [docs/architecture.md](docs/architecture.md): the path of a login, the sessions, the tables and the recovery flow.
- [docs/risk.md](docs/risk.md): the signals, the score, the decision, the model and the evaluation.
- [docs/evaluation.md](docs/evaluation.md): the results of the evaluation on the dataset.
- [docs/threat-model.md](docs/threat-model.md): each threat, what the service does about it and what risk remains.
- [docs/answers.md](docs/answers.md): the answers to the questions of the task.
- [docs/openapi.yaml](docs/openapi.yaml): the contract of the API.

## Where things are

```
.
├── apps/
│   ├── backend/           the Go service, and its style checks in tools/
│   └── frontend/          the page, its Dockerfile and nginx config
├── docs/                  the pages listed above, and the synthetic dataset
├── scripts/               Vault and cluster setup, the request signer, lint
├── release/               semantic-release and its plugins, pinned for the release job
├── compose.yaml           the stand
├── compose.cluster.yaml   the cluster
├── lefthook.yml           the git hooks that make hooks installs
├── .github/workflows/     ci.yml: the checks, and the release job
├── .golangci.yml          the rules of the linter
├── .releaserc.yml         the plugins of semantic-release, in the order they run
└── Makefile
```

Vault in the stand runs in dev mode and keeps its keys in memory. It is for local use only.

Fixes are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

MIT licensed. See [LICENSE](LICENSE).
