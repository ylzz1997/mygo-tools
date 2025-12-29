// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package defaults

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
)

type ImportRef struct {
	Name string // local name in foreign package source, e.g. "time"
	Path string // import path, e.g. "time"
}

// ForeignInfo carries default arg info plus the foreign-package import names used
// inside default expressions, so we can reproduce imports at the call site.
type ForeignInfo struct {
	Info
	Imports []ImportRef
}

// BuildObjectIndex builds an index keyed by go/types objects, by reading metadata
// comments attached to function declarations.
func BuildObjectIndex(files []*ast.File, info *types.Info) map[types.Object]Info {
	out := make(map[types.Object]Info)
	if info == nil {
		return out
	}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, _ := d.(*ast.FuncDecl)
			if fd == nil || fd.Name == nil {
				continue
			}
			m, ok := metadataForFuncDecl(f, fd)
			if !ok {
				continue
			}
			obj := info.Defs[fd.Name]
			if obj == nil {
				continue
			}
			var names []string
			var exprs []string
			for _, def := range m.Defaults {
				if def.Param == "" || def.Expr == "" {
					continue
				}
				names = append(names, def.Param)
				exprs = append(exprs, def.Expr)
			}
			if len(exprs) == 0 {
				continue
			}
			out[obj] = Info{Required: m.Required, Names: names, Exprs: exprs}
		}
	}
	return out
}

func metadataForFuncDecl(f *ast.File, fd *ast.FuncDecl) (Metadata, bool) {
	// Prefer Doc-attached metadata (if any).
	if fd != nil && fd.Doc != nil {
		if m, ok := metadataFromDoc(fd.Doc); ok {
			return m, true
		}
	}
	// Fall back to scanning file comment groups that are immediately adjacent
	// to the "func" token. This is needed because FixSrc may inject metadata
	// as an inline block comment without newlines to preserve physical line
	// structure for LSP diagnostics.
	return metadataFromAttachedComment(f, fd)
}

func metadataFromAttachedComment(f *ast.File, fd *ast.FuncDecl) (Metadata, bool) {
	if f == nil || fd == nil || fd.Pos() == token.NoPos {
		return Metadata{}, false
	}
	// We consider a comment group "attached" if it ends just before the func
	// keyword, allowing for a small amount of whitespace.
	const maxGap = token.Pos(8) // spaces/tabs between comment and 'func'

	var best Metadata
	okBest := false
	for _, cg := range f.Comments {
		if cg == nil {
			continue
		}
		end := cg.End()
		if end == token.NoPos {
			continue
		}
		gap := fd.Pos() - end
		if gap < 0 || gap > maxGap {
			continue
		}
		if m, ok := metadataFromDoc(cg); ok {
			best = m
			okBest = true
		}
	}
	return best, okBest
}

func metadataFromDoc(doc *ast.CommentGroup) (Metadata, bool) {
	if doc == nil {
		return Metadata{}, false
	}
	for _, c := range doc.List {
		txt := trimCommentText(c.Text)
		if strings.HasPrefix(txt, metaPrefixJSON) {
			enc := strings.TrimSpace(strings.TrimPrefix(txt, metaPrefixJSON))
			m, ok := decodeMetadataJSON(enc)
			if ok {
				return m, true
			}
		}
		if strings.HasPrefix(txt, metaPrefixOld) {
			// Best effort for old format; spaces inside expr not supported.
			rest := strings.TrimSpace(strings.TrimPrefix(txt, metaPrefixOld))
			parts := strings.Fields(rest)
			if len(parts) < 2 {
				continue
			}
			var m Metadata
			m.Name = parts[0]
			m.Required = atoi(parts[1])
			for _, p := range parts[2:] {
				eq := strings.IndexByte(p, '=')
				if eq <= 0 || eq+1 >= len(p) {
					continue
				}
				m.Defaults = append(m.Defaults, struct {
					Param string `json:"param"`
					Expr  string `json:"expr"`
				}{Param: p[:eq], Expr: p[eq+1:]})
			}
			if m.Name != "" && len(m.Defaults) > 0 {
				return m, true
			}
		}
	}
	return Metadata{}, false
}

func importNameFromSpec(spec *ast.ImportSpec) string {
	if spec == nil || spec.Path == nil {
		return ""
	}
	if spec.Name != nil {
		return spec.Name.Name
	}
	// Default import name is the base of the path.
	path, ok := strconvUnquote(spec.Path.Value)
	if !ok || path == "" {
		return ""
	}
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	return path
}

func importNameToPath(f *ast.File) map[string]string {
	m := make(map[string]string)
	if f == nil {
		return m
	}
	for _, spec := range f.Imports {
		if spec == nil || spec.Path == nil {
			continue
		}
		name := importNameFromSpec(spec)
		if name == "" || name == "_" || name == "." {
			continue
		}
		path, ok := strconvUnquote(spec.Path.Value)
		if !ok || path == "" {
			continue
		}
		m[name] = path
	}
	return m
}

func collectImportedPkgNamesInExpr(exprStr string, nameToPath map[string]string) []ImportRef {
	e, err := parser.ParseExpr(exprStr)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []ImportRef
	astutil.Apply(e, func(c *astutil.Cursor) bool {
		sel, ok := c.Node().(*ast.SelectorExpr)
		if !ok || sel == nil {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id == nil {
			return true
		}
		path, ok := nameToPath[id.Name]
		if !ok || path == "" {
			return true
		}
		key := id.Name + "\x00" + path
		if !seen[key] {
			seen[key] = true
			out = append(out, ImportRef{Name: id.Name, Path: path})
		}
		return true
	}, nil)
	return out
}

// BuildExportedFuncIndex builds an index for exported top-level functions in a
// foreign package, keyed by "pkgpath.Func".
//
// This does not require go/types for the foreign package.
func BuildExportedFuncIndex(pkgPath string, files []*ast.File) map[string]ForeignInfo {
	out := make(map[string]ForeignInfo)
	for _, f := range files {
		nameToPath := importNameToPath(f)
		for _, d := range f.Decls {
			fd, _ := d.(*ast.FuncDecl)
			if fd == nil || fd.Name == nil || fd.Recv != nil || fd.Doc == nil {
				continue
			}
			if !ast.IsExported(fd.Name.Name) {
				continue
			}
			m, ok := metadataFromDoc(fd.Doc)
			if !ok || len(m.Defaults) == 0 {
				continue
			}
			var names []string
			var exprs []string
			var imps []ImportRef
			for _, def := range m.Defaults {
				if def.Param == "" || def.Expr == "" {
					continue
				}
				names = append(names, def.Param)
				exprs = append(exprs, def.Expr)
				imps = append(imps, collectImportedPkgNamesInExpr(def.Expr, nameToPath)...)
			}
			if len(exprs) == 0 {
				continue
			}
			out[pkgPath+"."+fd.Name.Name] = ForeignInfo{
				Info:    Info{Required: m.Required, Names: names, Exprs: exprs},
				Imports: imps,
			}
		}
	}
	return out
}

func receiverKeyFromExpr(e ast.Expr) string {
	ptr := false
	for {
		switch t := e.(type) {
		case *ast.StarExpr:
			ptr = true
			e = t.X
			continue
		case *ast.IndexExpr:
			// shouldn't appear on receiver types in valid Go, but ignore if present
			e = t.X
			continue
		case *ast.IndexListExpr:
			e = t.X
			continue
		}
		break
	}
	switch t := e.(type) {
	case *ast.Ident:
		if ptr {
			return "*" + t.Name
		}
		return t.Name
	case *ast.SelectorExpr:
		// Unexpected for receiver decls (usually same package), but handle anyway.
		if t.Sel != nil {
			if ptr {
				return "*" + t.Sel.Name
			}
			return t.Sel.Name
		}
	}
	return ""
}

// BuildExportedMethodIndex builds an index for exported methods in a foreign
// package, keyed by "pkgpath.(Recv).Method" where Recv is like "T" or "*T".
func BuildExportedMethodIndex(pkgPath string, files []*ast.File) map[string]ForeignInfo {
	out := make(map[string]ForeignInfo)
	for _, f := range files {
		nameToPath := importNameToPath(f)
		for _, d := range f.Decls {
			fd, _ := d.(*ast.FuncDecl)
			if fd == nil || fd.Name == nil || fd.Recv == nil || fd.Doc == nil {
				continue
			}
			if !ast.IsExported(fd.Name.Name) {
				continue
			}
			if len(fd.Recv.List) == 0 {
				continue
			}
			recvKey := receiverKeyFromExpr(fd.Recv.List[0].Type)
			if recvKey == "" {
				continue
			}
			m, ok := metadataFromDoc(fd.Doc)
			if !ok || len(m.Defaults) == 0 {
				continue
			}
			var names []string
			var exprs []string
			var imps []ImportRef
			for _, def := range m.Defaults {
				if def.Param == "" || def.Expr == "" {
					continue
				}
				names = append(names, def.Param)
				exprs = append(exprs, def.Expr)
				imps = append(imps, collectImportedPkgNamesInExpr(def.Expr, nameToPath)...)
			}
			if len(exprs) == 0 {
				continue
			}
			out[pkgPath+".("+recvKey+")."+fd.Name.Name] = ForeignInfo{
				Info:    Info{Required: m.Required, Names: names, Exprs: exprs},
				Imports: imps,
			}
		}
	}
	return out
}

var builtinIdents = map[string]bool{
	"nil":   true,
	"true":  true,
	"false": true,
	"iota":  true,
}

func exportedNameSet(p *types.Package) map[string]bool {
	out := make(map[string]bool)
	if p == nil || p.Scope() == nil {
		return out
	}
	for _, name := range p.Scope().Names() {
		if ast.IsExported(name) {
			out[name] = true
		}
	}
	return out
}

func qualifyExportedIdents(e ast.Expr, pkgExpr ast.Expr, exported map[string]bool) ast.Expr {
	// Rewrite bare exported idents inside default expression to `pkgExpr.Name`.
	astutil.Apply(e, func(c *astutil.Cursor) bool {
		id, ok := c.Node().(*ast.Ident)
		if !ok || id == nil {
			return true
		}
		if builtinIdents[id.Name] {
			return true
		}
		if !ast.IsExported(id.Name) || !exported[id.Name] {
			return true
		}
		// Already qualified?
		if sel, ok := c.Parent().(*ast.SelectorExpr); ok && sel.Sel == id {
			return true
		}
		c.Replace(&ast.SelectorExpr{X: pkgExpr, Sel: id})
		return true
	}, nil)
	return e
}

func objectKey(obj types.Object) string {
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	if fn, ok := obj.(*types.Func); ok {
		if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
			recv := sig.Recv().Type()
			recvStr := types.TypeString(recv, types.RelativeTo(obj.Pkg()))
			return obj.Pkg().Path() + ".(" + recvStr + ")." + obj.Name()
		}
	}
	return obj.Pkg().Path() + "." + obj.Name()
}

func importQualifiersByPath(f *ast.File, info *types.Info) map[string]ast.Expr {
	out := make(map[string]ast.Expr)
	if f == nil || info == nil {
		return out
	}
	for _, spec := range f.Imports {
		if spec == nil || spec.Path == nil {
			continue
		}
		path, _ := strconvUnquote(spec.Path.Value)
		if path == "" {
			continue
		}
		pn, _ := info.Implicits[spec].(*types.PkgName)
		if pn == nil {
			continue
		}
		name := pn.Name()
		if name == "." || name == "_" || name == "" {
			continue
		}
		out[path] = ast.NewIdent(name)
	}
	return out
}

func strconvUnquote(s string) (string, bool) {
	// Minimal unquote for import paths, which are always quoted strings.
	if len(s) >= 2 && (s[0] == '"' || s[0] == '`') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1], true
	}
	return "", false
}

func existingImportNameByPath(f *ast.File, path string) string {
	if f == nil {
		return ""
	}
	for _, spec := range f.Imports {
		if spec == nil || spec.Path == nil {
			continue
		}
		p, ok := strconvUnquote(spec.Path.Value)
		if !ok || p != path {
			continue
		}
		return importNameFromSpec(spec)
	}
	return ""
}

func ensureImport(f *ast.File, importPath string, preferred string) *ast.Ident {
	if f == nil {
		return nil
	}
	// Already imported?
	if name := existingImportNameByPath(f, importPath); name != "" && name != "_" && name != "." {
		return ast.NewIdent(name)
	}

	name := preferred
	if name == "" || name == "_" || name == "." {
		if i := strings.LastIndexByte(importPath, '/'); i >= 0 {
			name = importPath[i+1:]
		} else {
			name = importPath
		}
	}

	// Avoid collisions with existing import names.
	existing := make(map[string]bool)
	for _, spec := range f.Imports {
		n := importNameFromSpec(spec)
		if n != "" {
			existing[n] = true
		}
	}
	if existing[name] {
		base := name
		for i := 1; ; i++ {
			try := base + "_mygo" + strconv.Itoa(i)
			if !existing[try] {
				name = try
				break
			}
		}
	}

	// Find or create an import decl.
	var impDecl *ast.GenDecl
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if ok && gd.Tok == token.IMPORT {
			impDecl = gd
			break
		}
	}
	if impDecl == nil {
		impDecl = &ast.GenDecl{Tok: token.IMPORT}
		f.Decls = append([]ast.Decl{impDecl}, f.Decls...)
	}
	spec := &ast.ImportSpec{
		Name: ast.NewIdent(name),
		Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(importPath)},
	}
	impDecl.Specs = append(impDecl.Specs, spec)
	f.Imports = append(f.Imports, spec)
	return spec.Name
}

// RewriteCallsWithTypes fills missing call arguments for functions/methods that
// have default-parameter metadata.
//
// This uses go/types info to resolve the called object, so it supports:
// - direct calls: f(...)
// - method calls: x.M(...)
// - package-qualified calls: pkg.F(...)
//
// It is intentionally limited to objects declared in the current package,
// to avoid cross-package metadata propagation.
func RewriteCallsWithTypes(files []*ast.File, pkg *types.Package, info *types.Info) {
	RewriteCallsWithTypesAndForeign(files, pkg, info, nil)
}

// RewriteCallsWithTypesAndForeign is like RewriteCallsWithTypes, but also accepts
// an index of foreign-package exported functions keyed by "pkgpath.Func".
//
// Foreign default expressions are parsed at the call site. If they reference
// exported identifiers from the foreign package, we qualify them using the call
// selector's package expression (e.g. default expr `Second` becomes `time.Second`
// if the call is `time.Sleep()`).
func RewriteCallsWithTypesAndForeign(files []*ast.File, pkg *types.Package, info *types.Info, foreign map[string]ForeignInfo) {
	if pkg == nil || info == nil {
		return
	}
	objIdx := BuildObjectIndex(files, info)
	if len(objIdx) == 0 && len(foreign) == 0 {
		return
	}

	for _, f := range files {
		qualByPath := importQualifiersByPath(f, info)
		astutil.Apply(f, func(c *astutil.Cursor) bool {
			call, ok := c.Node().(*ast.CallExpr)
			if !ok || call == nil {
				return true
			}
			if call.Ellipsis.IsValid() {
				return true
			}

			var obj types.Object
			var foreignPkg ast.Expr // selector.X for pkg.F calls
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				obj = info.Uses[fun]
			case *ast.SelectorExpr:
				if sel := info.Selections[fun]; sel != nil {
					obj = sel.Obj()
				} else if fun.Sel != nil {
					obj = info.Uses[fun.Sel] // pkg-qualified selector
					foreignPkg = fun.X
				}
			}
			if obj == nil {
				return true
			}

			var (
				di          Info
				foreignInfo ForeignInfo
				okInfo      bool
				isForeign   bool
			)
			if obj.Pkg() == pkg {
				di, okInfo = objIdx[obj]
			} else if obj.Pkg() != nil && ast.IsExported(obj.Name()) {
				foreignInfo, okInfo = foreign[objectKey(obj)]
				di = foreignInfo.Info
				isForeign = okInfo
			}
			if !okInfo {
				return true
			}

			total := di.Required + len(di.Exprs)
			if len(call.Args) >= total || len(call.Args) < di.Required {
				return true
			}

			missing := total - len(call.Args)
			start := len(di.Exprs) - missing
			if start < 0 {
				start = 0
			}

			var exported map[string]bool
			if isForeign {
				exported = exportedNameSet(obj.Pkg())
			}
			for _, exprStr := range di.Exprs[start:] {
				e, err := parser.ParseExpr(exprStr)
				if err != nil {
					return true
				}
				if isForeign {
					// First, reproduce any imports needed by the default expression.
					if len(foreignInfo.Imports) > 0 {
						nameToPath := make(map[string]string)
						for _, imp := range foreignInfo.Imports {
							if imp.Name != "" && imp.Path != "" {
								nameToPath[imp.Name] = imp.Path
							}
						}
						if len(nameToPath) > 0 {
							astutil.Apply(e, func(c *astutil.Cursor) bool {
								sel, ok := c.Node().(*ast.SelectorExpr)
								if !ok || sel == nil {
									return true
								}
								id, ok := sel.X.(*ast.Ident)
								if !ok || id == nil {
									return true
								}
								path, ok := nameToPath[id.Name]
								if !ok || path == "" {
									return true
								}
								q := qualByPath[path]
								if q == nil {
									q = ensureImport(f, path, id.Name)
									qualByPath[path] = q
								}
								if q != nil {
									sel.X = q
								}
								return true
							}, nil)
						}
					}

					pkgExpr := foreignPkg
					if pkgExpr == nil && obj.Pkg() != nil {
						pkgExpr = qualByPath[obj.Pkg().Path()]
						if pkgExpr == nil {
							// Ensure the callee package itself is imported, so we can
							// qualify exported identifiers from it.
							pkgExpr = ensureImport(f, obj.Pkg().Path(), "")
							qualByPath[obj.Pkg().Path()] = pkgExpr
						}
					}
					if pkgExpr != nil {
						e = qualifyExportedIdents(e, pkgExpr, exported)
					}
				}
				call.Args = append(call.Args, e)
			}
			return true
		}, nil)
	}
}


