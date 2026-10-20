// Command check runs the style checks of the repository. It combines five analyzers:
// [blocks], [errordecl], [literals], [shadowing] and [vargroups].
//
// The command takes the same arguments as other analysis programs, such as package patterns. With -fix it rewrites the
// code that the blocks and literals analyzers report.
//
//	cd apps/backend && ../../.bin/check ./...
package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/tools/check/blocks"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/tools/check/errordecl"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/tools/check/literals"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/tools/check/shadowing"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/tools/check/vargroups"
)

func main() {
	multichecker.Main(
		blocks.Analyzer,
		errordecl.Analyzer,
		literals.Analyzer,
		shadowing.Analyzer,
		vargroups.Analyzer,
	)
}
