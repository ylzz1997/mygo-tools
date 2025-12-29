package magic

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

// Regression test for comma-indexing FixSrc + magic rewrite.
func TestRewrite_Mygo2_NativeSetitemAndPtrInit(t *testing.T) {
	fset := token.NewFileSet()
	const src = `package main

type Seq struct{}

func (Seq) _getitem(i []int, j []int) int { return 0 }
func (Seq) _setitem(v int, i []int, j []int) {}

func main() {
	var seq Seq
	seq[1, 2] = 3
	_ = seq[1, 2]
}
`
	fixed, _ := FixSrc("mygo2.go", []byte(src))
	if fixed == nil {
		fixed = []byte(src)
	}
	f, err := parser.ParseFile(fset, "mygo2.go", fixed, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v\n---src---\n%s", err, string(fixed))
	}

	info1 := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	// Mirror gopls temp-typecheck behavior: ignore errors but keep going to
	// populate as much types.Info as possible.
	cfg1 := &types.Config{
		Importer: importer.Default(),
		Error:    func(error) {},
	}
	pkg1 := types.NewPackage("command-line-arguments", "main")
	_ = types.NewChecker(cfg1, fset, pkg1, info1).Files([]*ast.File{f})

	if !NeedsRewrite([]*ast.File{f}) {
		t.Fatalf("NeedsRewrite=false; test setup invalid")
	}

	Rewrite([]*ast.File{f}, pkg1, info1)

	// Sanity: after Rewrite, indexing on type params should be rewritten to _getitem/_setitem calls.
	var tpIdxCount int
	ast.Inspect(f, func(n ast.Node) bool {
		ix, _ := n.(*ast.IndexExpr)
		if ix == nil {
			return true
		}
		if id, _ := ix.X.(*ast.Ident); id != nil && id.Name == "seq" {
			tpIdxCount++
		}
		return true
	})
	if tpIdxCount > 0 {
		t.Fatalf("Rewrite did not eliminate IndexExpr on type-param var 'seq'; count=%d", tpIdxCount)
	}

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
		if len(errs2) > 8 {
			errs2 = errs2[:8]
		}
		t.Fatalf("postcheck has errors (expected none): %v", errs2)
	}
}


