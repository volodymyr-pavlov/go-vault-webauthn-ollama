#!/bin/sh
# Runs golangci-lint and staticcheck on the backend. Both are dependencies of a separate Go module, apps/backend/tools,
# so they do not touch go.sum of the backend itself.
#
#   scripts/lint.sh              both
#   scripts/lint.sh golangci     golangci-lint only
#   scripts/lint.sh staticcheck  staticcheck only
set -eu

cd "$(dirname "$0")/../apps/backend"

tool() {
	go tool -modfile=tools/go.mod "$@"
}

case "${1:-all}" in
all)
	tool golangci-lint run --config ../../.golangci.yml ./...
	tool staticcheck -tags integration ./...
	;;
golangci)
	tool golangci-lint run --config ../../.golangci.yml ./...
	;;
staticcheck)
	tool staticcheck -tags integration ./...
	;;
*)
	echo "usage: lint.sh [all|golangci|staticcheck]" >&2
	exit 2
	;;
esac
