package defaults

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

func TestFixSrc_PreservesPhysicalNewlines(t *testing.T) {
	const filename = "x.go"
	src := []byte(`package p

func f(a int, b int = 10, c string = "x y") {}
`)
	out, changed := FixSrc(filename, src)
	if !changed {
		t.Fatalf("FixSrc changed=false, want true")
	}
	if bytes.Count(src, []byte("\n")) != bytes.Count(out, []byte("\n")) {
		t.Fatalf("newline count changed: before=%d after=%d\n---after---\n%s", bytes.Count(src, []byte("\n")), bytes.Count(out, []byte("\n")), string(out))
	}
}

func TestFixSrc_MetadataIsReachable(t *testing.T) {
	const filename = "x.go"
	src := []byte(`package p

func calculate(x int, y int = 10, z int = 5) int { return x+y+z }
`)
	out, changed := FixSrc(filename, src)
	if !changed {
		t.Fatalf("FixSrc changed=false, want true")
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, out, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile failed: %v\n---after---\n%s", err, string(out))
	}
	if !HasAnyMetadata([]*ast.File{f}) {
		t.Fatalf("HasAnyMetadata=false, want true\n---after---\n%s", string(out))
	}
}

func TestRewriteCallsWithTypes_FillsDefaultArgs(t *testing.T) {
	const filename1 = "decl.go"
	const filename2 = "use.go"

	declSrc := []byte(`package p

func calculate(x int, y int = 10, z int = 5) int { return x+y+z }
`)
	useSrc := []byte(`package p

func _() {
	_ = calculate(1)
}
`)

	declFixed, changed := FixSrc(filename1, declSrc)
	if !changed {
		t.Fatalf("FixSrc changed=false, want true")
	}

	fset := token.NewFileSet()
	f1, err := parser.ParseFile(fset, filename1, declFixed, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile(decl) failed: %v\n---after---\n%s", err, string(declFixed))
	}
	f2, err := parser.ParseFile(fset, filename2, useSrc, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile(use) failed: %v\n---use---\n%s", err, string(useSrc))
	}
	files := []*ast.File{f1, f2}

	pkg := types.NewPackage("p", "p")
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Instances:  make(map[*ast.Ident]types.Instance),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes:     make(map[ast.Node]*types.Scope),
	}
	cfg := &types.Config{
		Error: func(error) {},
	}
	_ = types.NewChecker(cfg, fset, pkg, info).Files(files)

	RewriteCallsWithTypes(files, pkg, info)

	// Find the call and assert it now has 3 args.
	var got int
	ast.Inspect(f2, func(n ast.Node) bool {
		call, _ := n.(*ast.CallExpr)
		if call == nil {
			return true
		}
		if id, _ := call.Fun.(*ast.Ident); id != nil && id.Name == "calculate" {
			got = len(call.Args)
			return false
		}
		return true
	})
	if got != 3 {
		t.Fatalf("len(calculate args)=%d, want 3", got)
	}
}


