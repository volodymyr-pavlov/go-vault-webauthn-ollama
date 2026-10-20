// Package blocks finds statement lists whose logical blocks are not separated by an empty line.
//
// A block is one operation and its check, such as an assignment followed by the if statement that tests what it
// assigned. An empty line separates blocks.
//
// Statements that need no check stay together in one block. A declaration, the loop that fills it and the return of it
// also stay together. A control statement is a block of its own. A return stays with the plain statements before it,
// and a defer stays with the statement above it.
package blocks

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Analyzer reports each missing empty line between blocks. It offers a fix that adds the line.
var Analyzer = &analysis.Analyzer{
	Name: "blocks",
	Doc:  "finds logical blocks that are not separated by an empty line",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		if ast.IsGenerated(file) {
			continue
		}
		content, err := pass.ReadFile(pass.Fset.File(file.Pos()).Name())
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(content), "\n")
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BlockStmt:
				inspect(pass, file, lines, node.List)
			case *ast.CaseClause:
				inspect(pass, file, lines, node.Body)
			case *ast.CommClause:
				inspect(pass, file, lines, node.Body)
			}
			return true
		})
	}
	return nil, nil
}

// inspect reports each place in list where an empty line is due but missing.
func inspect(pass *analysis.Pass, file *ast.File, lines []string, list []ast.Stmt) {
	for i := 1; i < len(list); i++ {
		if !separated(pass, list, i) {
			continue
		}
		start := startLine(pass, file, list[i])
		if start-2 >= 0 && strings.TrimSpace(lines[start-2]) == "" {
			continue
		}
		if pass.Fset.Position(list[i-1].End()).Line >= start {
			continue
		}
		pass.Report(analysis.Diagnostic{
			Pos:     list[i].Pos(),
			Message: "logical blocks must be separated by an empty line",
			SuggestedFixes: []analysis.SuggestedFix{{
				Message: "add an empty line",
				TextEdits: []analysis.TextEdit{{
					Pos:     pass.Fset.File(list[i].Pos()).LineStart(start),
					End:     pass.Fset.File(list[i].Pos()).LineStart(start),
					NewText: []byte("\n"),
				}},
			}},
		})
	}
}

// startLine returns the first line of stmt. If comments stand directly above stmt, it returns the first line of them.
func startLine(pass *analysis.Pass, file *ast.File, stmt ast.Stmt) int {
	line := pass.Fset.Position(stmt.Pos()).Line
	for {
		moved := false
		for _, group := range file.Comments {
			if pass.Fset.Position(group.End()).Line == line-1 && pass.Fset.Position(group.Pos()).Line < line {
				line = pass.Fset.Position(group.Pos()).Line
				moved = true
				break
			}
		}
		if !moved {
			return line
		}
	}
}

// separated reports whether list[i] starts a new block.
func separated(pass *analysis.Pass, list []ast.Stmt, i int) bool {
	previous, next := list[i-1], list[i]
	if checks(pass, previous, next) {
		return false
	}
	if _, ok := next.(*ast.DeferStmt); ok {
		return false
	}
	if finished(list, i-1) {
		return !fillsAndReturns(pass, list, i)
	}
	if _, ok := next.(*ast.ReturnStmt); ok {
		return false
	}
	if isControl(next) {
		if iff, ok := next.(*ast.IfStmt); ok && iff.Init != nil {
			return true
		}
		return !uses(pass, next, defined(pass, previous))
	}
	return i+1 < len(list) && checks(pass, next, list[i+1])
}

// finished reports whether list[i] ends a block. It does if list[i] is a control statement.
func finished(list []ast.Stmt, i int) bool {
	return isControl(list[i])
}

// fillsAndReturns reports whether list[i] returns a variable that list[i-2] declares and the control statement
// list[i-1] fills.
func fillsAndReturns(pass *analysis.Pass, list []ast.Stmt, i int) bool {
	if i < 2 || !isControl(list[i-1]) || checks(pass, list[i-2], list[i-1]) {
		return false
	}
	if _, ok := list[i].(*ast.ReturnStmt); !ok {
		return false
	}
	return uses(pass, list[i], defined(pass, list[i-2]))
}

// isControl reports whether stmt is a control statement: a loop, a switch, a select, an if statement or a block.
func isControl(stmt ast.Stmt) bool {
	switch stmt.(type) {
	case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.BlockStmt:
		return true
	}
	return false
}

// checks reports whether next is the check of previous. It is if previous assigns or declares variables, and next is an
// if statement without an init statement whose condition tests only those variables, err or ok.
func checks(pass *analysis.Pass, previous, next ast.Stmt) bool {
	iff, ok := next.(*ast.IfStmt)
	if !ok || iff.Init != nil {
		return false
	}
	switch previous.(type) {
	case *ast.AssignStmt, *ast.DeclStmt:
	default:
		return false
	}
	assigned := defined(pass, previous)
	tested := false
	ast.Inspect(iff.Cond, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		object := pass.TypesInfo.Uses[id]
		variable, isVar := object.(*types.Var)
		if !isVar || variable.IsField() {
			return true
		}
		if assigned[object] || variable.Name() == "err" || variable.Name() == "ok" {
			tested = true
			return true
		}
		tested = false
		return false
	})
	return tested
}

// defined returns the variables that stmt declares or assigns.
func defined(pass *analysis.Pass, stmt ast.Stmt) map[types.Object]bool {
	objects := map[types.Object]bool{}
	add := func(id *ast.Ident) {
		if object := pass.TypesInfo.Defs[id]; object != nil {
			objects[object] = true
		} else if object := pass.TypesInfo.Uses[id]; object != nil {
			objects[object] = true
		}
	}
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		for _, lhs := range s.Lhs {
			if id, ok := lhs.(*ast.Ident); ok {
				add(id)
			}
		}
	case *ast.DeclStmt:
		if decl, ok := s.Decl.(*ast.GenDecl); ok && decl.Tok == token.VAR {
			for _, spec := range decl.Specs {
				for _, id := range spec.(*ast.ValueSpec).Names {
					add(id)
				}
			}
		}
	}
	return objects
}

// uses reports whether node uses one of objects.
func uses(pass *analysis.Pass, node ast.Node, objects map[types.Object]bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && objects[pass.TypesInfo.Uses[id]] {
			found = true
		}
		return !found
	})
	return found
}
