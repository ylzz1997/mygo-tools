package magic

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

// This test ensures that the tooling rewrite can eliminate bogus go/types errors
// for operator overloading.
func TestRewrite_Mygo1_OperatorsAndReverse(t *testing.T) {
	fset := token.NewFileSet()
	const src = `package main

type Vec struct{ X int }

func (v Vec) _add(o Vec) Vec { return Vec{X: v.X + o.X} }
func (v Vec) _radd(o Vec) Vec { return Vec{X: o.X + v.X} }

func main() {
	var a, b Vec
	_ = a + b
}
`
	f, err := parser.ParseFile(fset, "mygo1.go", []byte(src), parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// 1) preliminary typecheck (expected to have errors in pure Go form)
	info1 := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	var errs1 []error
	cfg1 := &types.Config{
		Importer: importer.Default(),
		Error: func(e error) {
			errs1 = append(errs1, e)
		},
	}
	pkg1, _ := cfg1.Check("command-line-arguments", fset, []*ast.File{f}, info1)
	if pkg1 == nil {
		t.Fatalf("precheck returned nil pkg; errs=%v", errs1)
	}

	// Guard: ensure the heuristic would run in gopls.
	if !NeedsRewrite([]*ast.File{f}) {
		t.Fatalf("NeedsRewrite=false; test setup invalid")
	}

	// 2) Apply MyGO magic rewrite using the (possibly partial) precheck info.
	Rewrite([]*ast.File{f}, pkg1, info1)

	// 3) final typecheck of rewritten AST should succeed without operator/make errors.
	info2 := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	var errs2 []error
	cfg2 := &types.Config{
		Importer: importer.Default(),
		Error: func(e error) {
			errs2 = append(errs2, e)
		},
	}
	_, _ = cfg2.Check("command-line-arguments", fset, []*ast.File{f}, info2)
	if len(errs2) > 0 {
		// High-signal: surface the first few errors to help debugging.
		if len(errs2) > 5 {
			errs2 = errs2[:5]
		}
		t.Fatalf("postcheck has errors (expected none): %v", errs2)
	}
}


