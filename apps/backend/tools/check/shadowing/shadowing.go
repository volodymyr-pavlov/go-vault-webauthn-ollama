// Package shadowing finds local variables, parameters and results that have the name of a type, a function, a method,
// a variable or a constant of their package. Such a name hides the declaration inside the function and makes the code
// hard to read.
package shadowing

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// Analyzer reports each local name that hides a declaration of the package.
var Analyzer = &analysis.Analyzer{
	Name: "shadowing",
	Doc:  "finds local names that hide a type, function, method, variable or constant of the package",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	taken := map[string]string{}
	for _, name := range pass.Pkg.Scope().Names() {
		switch pass.Pkg.Scope().Lookup(name).(type) {
		case *types.TypeName:
			taken[name] = "type"
		case *types.Func:
			taken[name] = "function"
		case *types.Var:
			taken[name] = "variable"
		case *types.Const:
			taken[name] = "constant"
		}
	}
	for _, name := range pass.Pkg.Scope().Names() {
		named, ok := pass.Pkg.Scope().Lookup(name).Type().(*types.Named)
		if !ok {
			continue
		}
		for method := range named.Methods() {
			if _, exists := taken[method.Name()]; !exists {
				taken[method.Name()] = "method"
			}
		}
	}
	for _, file := range pass.Files {
		if ast.IsGenerated(file) {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			object, defined := pass.TypesInfo.Defs[id]
			if !defined || object == nil {
				return true
			}
			variable, isVar := object.(*types.Var)
			if !isVar || variable.IsField() || object.Parent() == pass.Pkg.Scope() {
				return true
			}
			if kind, exists := taken[id.Name]; exists {
				pass.Reportf(id.Pos(), "%s %s hides the %s of the package", "variable", id.Name, kind)
			}
			return true
		})
	}
	return nil, nil
}
