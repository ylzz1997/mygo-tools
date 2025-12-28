// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package defaults

import (
	"go/ast"
	"go/parser"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
)

// Info describes default parameters for a function.
type Info struct {
	Required int      // number of required parameters
	Names    []string // defaulted parameter names, in order
	Exprs    []string // default expressions, in order, aligned with Names
}

// Index maps simple function names to their default parameter info.
// For now we only support direct calls to package-level functions (Ident callee).
type Index map[string]Info

// BuildIndex scans file comments for //mygo:defaults metadata injected by FixSrc.
func BuildIndex(files []*ast.File) Index {
	idx := make(Index)
	for _, f := range files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				txt := trimCommentText(c.Text)

				// New format: base64(JSON)
				if strings.HasPrefix(txt, metaPrefixJSON) {
					enc := strings.TrimSpace(strings.TrimPrefix(txt, metaPrefixJSON))
					m, ok := decodeMetadataJSON(enc)
					if !ok || len(m.Defaults) == 0 {
						continue
					}
					var names []string
					var exprs []string
					for _, d := range m.Defaults {
						if d.Param == "" || d.Expr == "" {
							continue
						}
						names = append(names, d.Param)
						exprs = append(exprs, d.Expr)
					}
					if m.Name != "" && len(exprs) > 0 {
						idx[m.Name] = Info{Required: m.Required, Names: names, Exprs: exprs}
					}
					continue
				}

				// Old format: "mygo:defaults f 1 b=10 c=x"
				if strings.HasPrefix(txt, metaPrefixOld) {
					rest := strings.TrimSpace(strings.TrimPrefix(txt, metaPrefixOld))
					parts := strings.Fields(rest)
					if len(parts) < 2 {
						continue
					}
					name := parts[0]
					req := atoi(parts[1])
					var names []string
					var exprs []string
					for _, p := range parts[2:] {
						eq := strings.IndexByte(p, '=')
						if eq <= 0 || eq+1 >= len(p) {
							continue
						}
						names = append(names, p[:eq])
						exprs = append(exprs, p[eq+1:])
					}
					if name != "" && len(exprs) > 0 {
						idx[name] = Info{Required: req, Names: names, Exprs: exprs}
					}
				}
			}
		}
	}
	return idx
}

// RewriteCalls fills missing call arguments for known default-parameter functions.
//
// This is a best-effort transform, and only rewrites calls where:
// - callee is an *ast.Ident
// - no Ellipsis is used
// - arg count is between Required and total parameters
func RewriteCalls(files []*ast.File, idx Index) {
	if len(idx) == 0 {
		return
	}
	for _, f := range files {
		astutil.Apply(f, func(c *astutil.Cursor) bool {
			call, ok := c.Node().(*ast.CallExpr)
			if !ok || call == nil {
				return true
			}
			if call.Ellipsis.IsValid() {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || id == nil {
				return true
			}
			info, ok := idx[id.Name]
			if !ok {
				return true
			}
			total := info.Required + len(info.Exprs)
			if len(call.Args) >= total || len(call.Args) < info.Required {
				return true
			}
			missing := total - len(call.Args)
			start := len(info.Exprs) - missing
			if start < 0 {
				start = 0
			}
			for _, exprStr := range info.Exprs[start:] {
				e, err := parser.ParseExpr(exprStr)
				if err != nil {
					// Give up on this call.
					return true
				}
				call.Args = append(call.Args, e)
			}
			return true
		}, nil)
	}
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
