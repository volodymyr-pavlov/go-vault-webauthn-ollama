// Package errordecl finds errors that are declared outside errors.go. A package declares its errors in errors.go and
// nowhere else. This holds for every call of errors.New and for every variable that is named like an error. Test files
// and generated files are not checked.
package errordecl

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Analyzer reports each error declaration outside errors.go.
var Analyzer = &analysis.Analyzer{
	Name: "errordecl",
	Doc:  "finds errors that are declared outside errors.go",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		name := filepath.Base(pass.Fset.Position(file.Pos()).Filename)
		if name == "errors.go" || strings.HasSuffix(name, "_test.go") || ast.IsGenerated(file) {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				if isErrorsNew(n) {
					pass.Reportf(n.Pos(), "errors.New belongs in errors.go")
				}
			case *ast.GenDecl:
				if n.Tok == token.VAR {
					reportNamedErrors(pass, file, n)
				}
			}
			return true
		})
	}
	return nil, nil
}

// isErrorsNew reports whether call is errors.New(...).
func isErrorsNew(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "New" {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && pkg.Name == "errors"
}

// reportNamedErrors reports each variable of declaration that has the name of an error. The declaration must be at
// the package level.
func reportNamedErrors(pass *analysis.Pass, file *ast.File, declaration *ast.GenDecl) {
	for _, declared := range file.Decls {
		if declared != declaration {
			continue
		}
		for _, spec := range declaration.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range value.Names {
				if isErrorName(name.Name) {
					pass.Reportf(name.Pos(), "the error %s belongs in errors.go", name.Name)
				}
			}
		}
	}
}

// isErrorName reports whether name looks like the name of an error. It must start with err or Err, followed by a
// capital letter.
func isErrorName(name string) bool {
	rest, found := strings.CutPrefix(name, "err")
	if !found {
		rest, found = strings.CutPrefix(name, "Err")
	}
	return found && len(rest) > 0 && rest[0] >= 'A' && rest[0] <= 'Z'
}
