package magic

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

func typecheckWithErrors(fset *token.FileSet, files []*ast.File) ([]error, *types.Package, *types.Info) {
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
	var errs []error
	cfg := &types.Config{
		Error:    func(e error) { errs = append(errs, e) },
		Importer: importer.Default(),
	}
	_ = types.NewChecker(cfg, fset, pkg, info).Files(files)
	return errs, pkg, info
}

func parseOne(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	return fset, f
}

func TestNativeSynthesis_GenericAdd_Int(t *testing.T) {
	fset, f := parseOne(t, `
package p

type Addable[T any] interface{ _add(T) T }

func GenericAdd[T Addable[T]](a, b T) T { return a + b }

func main() {
	_ = GenericAdd(100, 200)
}
`)

	// First pass: allow errors.
	_, pkg, info := typecheckWithErrors(fset, []*ast.File{f})
	Rewrite([]*ast.File{f}, pkg, info)

	// Second pass: should type-check after rewrite.
	errs, _, _ := typecheckWithErrors(fset, []*ast.File{f})
	if len(errs) != 0 {
		t.Fatalf("expected no type errors after rewrite, got %d (first: %v)", len(errs), errs[0])
	}
}

func TestNativeSynthesis_GetFirst_SliceGetitem(t *testing.T) {
	fset, f := parseOne(t, `
package p

func GetFirst[T any, S interface{ _getitem(int) T }](seq S) T {
	return seq[0]
}

func main() {
	list := []int{1, 2, 3}
	_ = GetFirst(list)
}
`)

	_, pkg, info := typecheckWithErrors(fset, []*ast.File{f})
	Rewrite([]*ast.File{f}, pkg, info)

	errs, _, _ := typecheckWithErrors(fset, []*ast.File{f})
	if len(errs) != 0 {
		t.Fatalf("expected no type errors after rewrite, got %d (first: %v)", len(errs), errs[0])
	}
}

func TestNativeSynthesis_InitMake_TypeParam(t *testing.T) {
	fset, f := parseOne(t, `
package p

type ValIniter[T any] interface{ _init(pos int) }

func CreateBoxViaFunc[T ValIniter[T]](val int) *T {
	return make(T, val)
}

type MySlice []int

func main() {
	s := CreateBoxViaFunc[MySlice](3)
	_ = len(*s)
}
`)

	_, pkg, info := typecheckWithErrors(fset, []*ast.File{f})
	Rewrite([]*ast.File{f}, pkg, info)

	errs, _, _ := typecheckWithErrors(fset, []*ast.File{f})
	if len(errs) != 0 {
		t.Fatalf("expected no type errors after rewrite, got %d (first: %v)", len(errs), errs[0])
	}
}



