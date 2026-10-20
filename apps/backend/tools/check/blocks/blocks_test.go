package blocks

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestBlocks(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Analyzer, "example")
}

func TestFixAddsTheEmptyLines(t *testing.T) {
	analysistest.RunWithSuggestedFixes(t, analysistest.TestData(), Analyzer, "fixed")
}
