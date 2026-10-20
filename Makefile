include scripts/versions.env

BACKEND := apps/backend
FRONTEND := apps/frontend
GO ?= go
CLUSTER_PROJECT ?= go-vault-webauthn-ollama-cluster
BACKEND_IMAGE ?= go-vault-webauthn-ollama-backend
FRONTEND_IMAGE ?= go-vault-webauthn-ollama-frontend
SOURCE_URL ?= https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama

VERSION ?= $(shell git describe --tags --match 'v[0-9]*' --dirty 2>/dev/null | sed 's/^v//')
ifeq ($(VERSION),)
VERSION := 0.0.0-dev
endif

.PHONY: frontend-install frontend-dev frontend-check frontend-build frontend-e2e docker-build-backend docker-build-frontend help build test test-race test-integration fuzz vet fmt check lint staticcheck check-binary check-style fix-style \
	vulncheck gosec gitleaks mod-verify verify hooks shellcheck docker-build compose-config \
	stand-secrets stand-mail stand-up stand-down stand-reset stand-logs cluster-up cluster-down cluster-reset cluster-status cluster-promote rewrap-totp recovery-list recovery-approve evaluate version clean

help: ## list the targets
	@awk -F':.*## ' '/^[a-z0-9-]+:.*##/ { printf "%-20s %s\n", $$1, $$2 }' $(firstword $(MAKEFILE_LIST))

build: ## the server and the tools into .bin/
	cd $(BACKEND) && CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o ../../.bin/server ./cmd/server
	cd $(BACKEND) && CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o ../../.bin/evaluate ./cmd/evaluate
	cd $(BACKEND) && CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o ../../.bin/recovery ./cmd/recovery

test: ## go test ./... (no Docker needed)
	cd $(BACKEND) && $(GO) test ./...

test-race: ## the tests with the race detector
	cd $(BACKEND) && $(GO) test -race -count=1 ./...

test-integration: ## the tests that need Docker: the stores on MySQL, the API end to end, Vault Transit
	cd $(BACKEND) && $(GO) test -race -count=1 -tags integration ./mysql ./server ./vault

fuzz: ## the fuzz tests for a few seconds each
	cd $(BACKEND) && $(GO) test -run='^$$' -fuzz=FuzzParseAdvice -fuzztime=20s ./ai
	cd $(BACKEND) && $(GO) test -run='^$$' -fuzz=FuzzSplit -fuzztime=20s ./vault

vet: ## go vet ./...
	cd $(BACKEND) && $(GO) vet -tags integration ./...

fmt: ## fail if a Go file is not gofmt-formatted
	@test -z "$$(cd $(BACKEND) && gofmt -l .)" || (cd $(BACKEND) && gofmt -l . && exit 1)

check: fmt vet test-race ## fmt, vet and the race tests

lint: ## golangci-lint, from the module apps/backend/tools
	sh scripts/lint.sh golangci

staticcheck: ## staticcheck only
	sh scripts/lint.sh staticcheck

check-binary: ## build the style checks of apps/backend/tools/check into .bin/check
	cd $(BACKEND)/tools && $(GO) build -o ../../../.bin/check ./check

check-style: check-binary ## the style checks: a line for each field of a literal, no var groups, every error in errors.go, an empty line between logical blocks
	cd $(BACKEND) && ../../.bin/check ./...

fix-style: check-binary ## rewrite what the style checks can fix
	cd $(BACKEND) && for pass in 1 2 3 4 5 6; do ../../.bin/check -fix ./... >/dev/null 2>&1 && break; done
	cd $(BACKEND) && gofmt -w .
	$(MAKE) check-style

vulncheck: ## govulncheck: known vulnerabilities in the code the backend calls
	cd $(BACKEND) && $(GO) tool -modfile=tools/go.mod govulncheck ./...

gosec: ## gosec, the Go security linter, alone, with the exclusions of .golangci.yml (lint runs it too)
	cd $(BACKEND) && $(GO) tool -modfile=tools/go.mod golangci-lint run --config ../../.golangci.yml --enable-only gosec ./...

gitleaks: ## gitleaks: secrets in the repository
	cd $(BACKEND) && $(GO) tool -modfile=tools/go.mod gitleaks git --no-banner --redact ../..

mod-verify: ## go mod verify on both modules
	cd $(BACKEND) && $(GO) mod verify
	cd $(BACKEND)/tools && $(GO) mod verify

verify: check check-style lint staticcheck vulncheck gosec gitleaks mod-verify frontend-check frontend-build ## every check that needs no container

hooks: ## install the git hooks of lefthook.yml into .git/hooks
	cd $(BACKEND)/tools && $(GO) build -o ../../../.bin/lefthook github.com/evilmartians/lefthook/v2
	LEFTHOOK_BIN=$(CURDIR)/.bin/lefthook .bin/lefthook install

shellcheck: ## shellcheck on the scripts, which needs shellcheck on the PATH
	shellcheck -x -e SC3045 scripts/*.sh

compose-config: ## check that the stand and the cluster compose files parse, with the pinned images
	$(COMPOSE) config --quiet
	$(CLUSTER) config --quiet

docker-build: docker-build-backend docker-build-frontend ## both images

docker-build-backend: ## the backend image BACKEND_IMAGE:VERSION
	docker build -f $(BACKEND)/Dockerfile \
		--build-arg GO_ALPINE_IMAGE=$(GO_ALPINE_IMAGE) --build-arg ALPINE_IMAGE=$(ALPINE_IMAGE) \
		--build-arg VERSION=$(VERSION) --build-arg SOURCE_URL=$(SOURCE_URL) \
		-t $(BACKEND_IMAGE):$(VERSION) -t $(BACKEND_IMAGE):latest .

# Compose stops reading the project .env as soon as an --env-file is given, so it is passed here as well, when it
# exists. The Vault dev root token is written into .env once, by stand-secrets.
export COMPOSE = docker compose --env-file scripts/versions.env $(if $(wildcard .env),--env-file .env)

# The operator commands run inside the Vault container with its dev root token, which the container holds in its
# environment. A production operator uses an admin policy instead.
VAULT_EXEC = $(COMPOSE) exec vault sh -c 'VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=$$VAULT_DEV_ROOT_TOKEN_ID vault "$$@"' vault

stand-secrets: ## write the local-only secrets of the stand into .env, once
	@grep -qs '^VAULT_DEV_ROOT_TOKEN_ID=' .env || { printf 'VAULT_DEV_ROOT_TOKEN_ID=%s\n' "$$(openssl rand -hex 16)" >> .env; echo 'wrote VAULT_DEV_ROOT_TOKEN_ID to .env'; }
	@grep -qs '^MYSQL_PASSWORD=' .env || { printf 'MYSQL_PASSWORD=%s\n' "$$(openssl rand -hex 16)" >> .env; echo 'wrote MYSQL_PASSWORD to .env'; }

stand-up: stand-secrets ## build and start the stand: Vault (dev mode, local only), MySQL, Redis, Mailpit, Ollama, the backend on :8080 and the page on http://localhost:3000
	$(COMPOSE) up --build --detach --wait

stand-down: ## stop the stand; the data of MySQL stays in its volume
	$(COMPOSE) --profile ops down

stand-reset: ## stop the stand and wipe MySQL: needed after Vault restarted, because its dev-mode keys are gone
	$(COMPOSE) --profile ops down --volumes

# The cluster is a second compose project. It needs the same .env as the stand.
export CLUSTER = docker compose -p $(CLUSTER_PROJECT) -f compose.cluster.yaml --env-file scripts/versions.env $(if $(wildcard .env),--env-file .env)

cluster-up: stand-secrets ## build and start the cluster: two backends, Vault Raft with 3 nodes, MySQL with a replica, Redis with Sentinel; the page is on http://localhost:3100
	$(CLUSTER) up --build --detach --wait

cluster-down: ## stop the cluster; its data stays in the volumes
	$(CLUSTER) down

cluster-reset: ## stop the cluster and wipe all its data
	$(CLUSTER) down --volumes

cluster-status: ## show the Vault leader, the MySQL replication and the Redis master
	@$(CLUSTER) exec -T vault-lb true >/dev/null 2>&1 || { echo 'the cluster is not running'; exit 1; }
	@echo '== vault raft peers'; $(CLUSTER) run --rm --no-deps -e VAULT_ADDR=http://vault-lb:8200 -v $(CLUSTER_PROJECT)_vault-cluster-keys:/cluster:ro --entrypoint sh vault-cluster -c 'VAULT_TOKEN=$$(cat /cluster/root_token) vault operator raft list-peers' 2>/dev/null
	@echo '== mysql replica'; $(CLUSTER) exec -T mysql-replica sh -c 'mysql -uroot -p"$$MYSQL_ROOT_PASSWORD" -e "SHOW REPLICA STATUS\\G" 2>/dev/null' | grep -E 'Replica_(IO|SQL)_Running:|Seconds_Behind_Source' || echo 'mysql-replica reports no replication: it was promoted, or it is down'
	@echo '== redis master seen by the sentinels'; $(CLUSTER) exec -T sentinel-1 redis-cli -p 26379 sentinel get-master-addr-by-name main

cluster-promote: ## fail over by hand: make mysql-replica the primary and point the backends at it
	$(CLUSTER) exec -T mysql-replica sh -c 'mysql -uroot -p"$$MYSQL_ROOT_PASSWORD" -e "STOP REPLICA; RESET REPLICA ALL; SET PERSIST super_read_only=OFF; SET PERSIST read_only=OFF;"'
	MYSQL_HOST=mysql-replica $(CLUSTER) up --detach --no-deps --force-recreate backend-1 backend-2

stand-logs: ## follow the logs of the backend: one line for each request
	$(COMPOSE) logs --follow backend

stand-mail: ## open Mailpit, the mail catcher, where the verification tokens and the notices land
	@echo http://127.0.0.1:8025

recovery-list: ## list the open recovery requests
	$(COMPOSE) --profile ops run --rm --entrypoint recovery recovery list

recovery-approve: ## approve a recovery request after you checked the owner (XID=n)
	$(COMPOSE) --profile ops run --rm --entrypoint recovery recovery approve $(XID)

rewrap-totp: ## rotate the TOTP key and rewrap every stored secret (a fresh wrapped secret ID is made for the one-shot run)
	$(VAULT_EXEC) write -f transit/keys/totp/rotate
	$(COMPOSE) run --rm vault-init >/dev/null
	$(COMPOSE) --profile ops run --rm rewrap

EVALUATE_ARGS ?= -timeout 3m

evaluate: build ## the evaluation of the risk engine on the synthetic dataset; OLLAMA_URL points at an Ollama that has the model; EVALUATE_ARGS adds flags
	.bin/evaluate -ollama "$${OLLAMA_URL:-}" -model "$${OLLAMA_MODEL:-$(OLLAMA_MODEL)}" -digest "$${OLLAMA_DIGEST:-$(OLLAMA_DIGEST)}" -out out/evaluation.md $(EVALUATE_ARGS)

frontend-install: ## npm ci
	cd $(FRONTEND) && npm ci

frontend-dev: ## Vite dev server on http://localhost:3000, with /v1 passed to the backend on :8080
	cd $(FRONTEND) && npm run dev

frontend-check: ## type check, unit tests and the Prettier check
	cd $(FRONTEND) && npm run check

frontend-build: ## production build of the page into apps/frontend/.dist
	cd $(FRONTEND) && npm run build

frontend-e2e: ## the Playwright tests of the page against the running stand (make stand-up first)
# The rate limits count by address, so a second run would hit "Too many tries" without a flush.
	$(COMPOSE) exec -T redis redis-cli FLUSHDB
	cd $(FRONTEND) && npm run test:e2e

docker-build-frontend: ## the page image FRONTEND_IMAGE:VERSION, on nginx
	docker build -f $(FRONTEND)/Dockerfile \
		--build-arg NODE_ALPINE_IMAGE=$(NODE_ALPINE_IMAGE) --build-arg NGINX_IMAGE=$(NGINX_IMAGE) \
		--build-arg VERSION=$(VERSION) --build-arg SOURCE_URL=$(SOURCE_URL) \
		-t $(FRONTEND_IMAGE):$(VERSION) -t $(FRONTEND_IMAGE):latest .

version: ## the version a local build gets
	@echo $(VERSION)

clean: ## remove the build output
	rm -rf .bin out
