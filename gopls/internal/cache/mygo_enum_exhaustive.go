// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cache

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"

	"golang.org/x/tools/gopls/internal/protocol"
	mygoenum "golang.org/x/tools/internal/mygo/enum"
)

// addMyGOEnumExhaustiveDiagnostics reports a diagnostic when a MyGO enum match
// is not exhaustive (missing variants) and there is no default clause.
//
// This runs on the rewritten tag-switch form produced by internal/mygo/enum.
func addMyGOEnumExhaustiveDiagnostics(pkg *syntaxPackage) {
	if pkg == nil {
		return
	}
	var files []*ast.File
	for _, cgf := range pkg.compiledGoFiles {
		files = append(files, cgf.File)
	}
	idx := mygoenum.BuildIndex(files)
	if !idx.HasAny() {
		return
	}

	for _, cgf := range pkg.compiledGoFiles {
		f := cgf.File
		ast.Inspect(f, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok || sw.Tag == nil || sw.Body == nil {
				return true
			}
			// Only consider tag-switches of the form: switch <ident>._tag
			sel, ok := sw.Tag.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel == nil || sel.Sel.Name != "_tag" {
				return true
			}
			// Require at least one explicit case clause.
			hasDefault := false
			seenTags := make(map[string]bool)
			enumType := ""

			for _, stmt := range sw.Body.List {
				cc, _ := stmt.(*ast.CaseClause)
				if cc == nil {
					continue
				}
				if len(cc.List) == 0 {
					hasDefault = true
					continue
				}
				for _, e := range cc.List {
					id, ok := e.(*ast.Ident)
					if !ok || id == nil {
						continue
					}
					tn, vn, ok := parseTagConst(id.Name)
					if !ok {
						continue
					}
					if enumType == "" {
						enumType = tn
					} else if enumType != tn {
						// Mixed types: skip.
						return true
					}
					seenTags[vn] = true
				}
			}
			if hasDefault || enumType == "" {
				return true
			}

			all := idx.Variants(enumType)
			if len(all) == 0 {
				return true
			}
			var missing []string
			for v := range all {
				if !seenTags[v] {
					missing = append(missing, v)
				}
			}
			if len(missing) == 0 {
				return true
			}
			sort.Strings(missing)

			rng, err := cgf.NodeRange(sw)
			if err != nil {
				return true
			}
			pkg.diagnostics = append(pkg.diagnostics, &Diagnostic{
				URI:      cgf.URI,
				Range:    rng,
				Severity: protocol.SeverityError,
				Source:   DiagnosticSource("mygo"),
				Code:     "mygo/enum-exhaustive",
				Message:  fmt.Sprintf("enum match on %s is not exhaustive (missing: %s)", enumType, strings.Join(missing, ", ")),
			})
			return true
		})
	}
}

func parseTagConst(name string) (typeName, variant string, ok bool) {
	const marker = "__Tag_"
	i := strings.Index(name, marker)
	if i <= 0 {
		return "", "", false
	}
	tn := name[:i]
	vn := name[i+len(marker):]
	if tn == "" || vn == "" {
		return "", "", false
	}
	// Basic identifier sanity: avoid false positives.
	if !token.IsIdentifier(tn) || !token.IsIdentifier(vn) {
		return "", "", false
	}
	return tn, vn, true
}


