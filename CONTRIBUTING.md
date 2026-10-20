# Contributing

The project welcomes bug fixes at any time. A bigger change starts with an issue, so that the maintainers and the
contributor agree on the approach before the work begins.

## How to send a change

1. The contributor makes the change on a branch of a fork of the project on GitHub.
2. The change passes the checks of the workflow: `make verify`, and `make test-integration` with Docker running.
3. The commit message follows the [Conventional Commits](https://www.conventionalcommits.org/) style. `fix:` makes a
   patch release, `feat:` makes a minor release, and `feat!:` or a `BREAKING CHANGE:` footer makes a major release. The
   messages decide the next version number.
4. The pull request against `main` says what changed and why.

## How the code is written

- A doc comment follows the godoc style. It starts with the name that it documents, uses whole sentences and wraps at 120
  columns. Comments inside functions are rare and explain why, not what.
- States are bitwise flags in one `flags` column for each table, never strings or booleans. Identifiers are `uint64`.
  The internal key of a row never leaves the service, and the external key is a snowflake from `snowid`.
- The data layer follows the `es` pattern. Small generic store interfaces live in `es`. One backend in `mysql` keeps the
  static statements as embedded SQL files in `mysql/expr`. The business rules live in the handlers, and a backend
  returns rows and decides nothing. Every store method reads its own statement, scans its own columns and checks its own
  rows, so no shared helper hides a step.
- Every dependency of a handler is an exported field with an interface type. `config.NewEnv` and `server.NewServer`
  fill these fields, and no other code does. The code uses no embedding. It uses a constructor only when a value needs a
  setup that a literal cannot express.
- JSON bodies are typed structs that gjson decodes into pooled arguments. The service refuses a field that the endpoint
  does not know. The code never uses a map.
- Everything that arrives from the network, the database or the model is hostile. The code limits sizes, checks values
  before it uses them, and says as little as possible in a refusal.
- A variable never takes the name of a type, a function or a method of its package. `make check-style` checks this.
- A composite literal gives each field its own line. In a test, this rule applies to literals with keyed fields, so that
  tables of test data stay compact. `make check-style` finds the literals that break the rule, and `make fix-style`
  rewrites them.
- Every error is declared in the `errors.go` file of its package, each with its own `var`. `make check-style` checks
  this.
- An empty line separates the logical blocks of a function. A block is an operation and the check of its result.
  Statements that need no check stay together. A declaration, the loop or switch that fills it, and the return of it
  also stay together. A control statement is a block of its own. `make check-style` finds the missing lines, and
  `make fix-style` adds them.
- Each package-level `var` stands on its own, never in a `var ( ... )` group.
- The linters are the rules of the project. A `//nolint` comment never silences them. The code changes, or
  `.golangci.yml` changes in a separate pull request.

## Git hooks

`make hooks` installs the hooks from `lefthook.yml`. Before a commit, the hooks run `gofmt`, `make check-style`,
`make lint`, `make gitleaks` and `shellcheck` on the staged files, in parallel. They also check that the first line of
the commit message starts with a type, such as `feat(api): ...`, because semantic-release reads it. `lefthook` is built
from the `tools` module, so nothing else needs to be installed. The workflow runs the same checks again, so it also
finds a hook that someone skipped with `--no-verify`. `make verify` runs the same checks except `shellcheck`, which
needs the `shellcheck` binary on the PATH; run `make shellcheck` for it.

## The workflow

The workflow in `.github/workflows/ci.yml` runs on every pull request and on `main`. It builds and deploys nothing.

| Job                | Command                                                                                                   | What it checks                                                                       |
| ------------------ | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `checks`           | `make fmt vet check-style lint staticcheck vulncheck gosec gitleaks mod-verify shellcheck`                | Format, vet, the style checks, the linters, known vulnerabilities, secrets, go.sum, the shell scripts. |
| `test`             | `make test-race fuzz`                                                                                     | The tests with the race detector and the fuzz tests for a few seconds.               |
| `test-integration` | `make test-integration`                                                                                   | The stores on MySQL, the API end to end and the Transit client on Vault, in Docker.  |
| `frontend-check`   | `make frontend-check frontend-build`                                                                      | Types, unit tests, Prettier and the production build of the page.                    |
| `docker`           | `make compose-config docker-build`                                                                        | Both compose files parse and both images build. Nothing is pushed or started.        |
| `release`          | `semantic-release`                                                                                        | On `main` only. See below.                                                           |

`golangci-lint`, `staticcheck`, `gosec`, `gitleaks`, `govulncheck`, `lefthook` and the project's own checks
(`apps/backend/tools/check`, a set of analyzers that run as one program) live in a separate Go module,
`apps/backend/tools`. This way they do not change the `go.sum` of the backend. The Makefile runs them from there with
`go tool -modfile`. To update one of them, run `go get -modfile=tools/go.mod <module>@<version>` in `apps/backend`.

## Releases

A merge to `main` is all that a release needs. The `release` job runs semantic-release. It writes the release notes into
`CHANGELOG.md`, commits that file to `main` as `chore(release): X.Y.Z`, creates the `vX.Y.Z` tag on that commit, and
creates a GitHub Release with the same notes. The release commit starts no workflow of its own. The job deploys nothing
and publishes no image.

The job uses the own `GITHUB_TOKEN` of the workflow, which can push the commit and create the release. Nobody edits
`CHANGELOG.md` by hand, because the commit messages generate it.

`.releaserc.yml` lists the plugins in the order in which they run. The commit analyzer decides the version. The notes
generator writes the notes. The changelog plugin puts them in `CHANGELOG.md`. The git plugin commits that file. The
GitHub plugin makes the release. `release/package.json` pins semantic-release and every plugin to an exact version, and
`release/package-lock.json` locks the rest. To bump a version, change it in `release/package.json`, run
`npm install --prefix release --package-lock-only`, and commit both files.

## Pinned container images

Every base image is pinned to an exact digest, not only to a tag. The images of the stand are listed in
`scripts/versions.env`. To update an image, take the tag and the digest from
`docker buildx imagetools inspect <image>:<tag>` and replace both together. The actions in `.github/workflows/ci.yml`
are pinned to a commit in the same way.

## Licensing

Every contribution is published under the MIT License in `LICENSE`.
