package shadowing

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestShadowing(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Analyzer, "example")
}
