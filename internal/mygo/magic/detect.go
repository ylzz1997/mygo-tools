// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magic

import (
	"bytes"
	"go/ast"
	"go/printer"
	"go/token"
	"strings"
)

// NeedsRewrite reports whether any of the provided files likely uses MyGO
// method-overloading / magic-function features that require rewriting before
// standard go/types can type-check.
//
// This is intentionally a cheap, syntactic heuristic.
func NeedsRewrite(files []*ast.File) bool {
	if len(files) == 0 {
		return false
	}

	// 1) detect overloaded method declarations (same recv+name).
	seen := make(map[string]bool)
	for _, f := range files {
		for _, d := range f.Decls {
			fd, _ := d.(*ast.FuncDecl)
			if fd == nil || fd.Recv == nil || fd.Name == nil || len(fd.Recv.List) == 0 {
				continue
			}
			recvStr := exprToStringCheap(fd.Recv.List[0].Type)
			key := recvStr + "." + fd.Name.Name
			// If there are 2+ methods with same name, it's probably overloading.
			if seen[key] {
				return true
			}
			seen[key] = true
		}
	}

	// 2) detect magic method declarations.
	for _, f := range files {
		for _, d := range f.Decls {
			fd, _ := d.(*ast.FuncDecl)
			if fd == nil || fd.Recv == nil || fd.Name == nil {
				continue
			}
			n := fd.Name.Name
			if isSingleUnderscoreMagic(n) {
				return true
			}
			// overloaded magic methods become "_add_int" etc.
			for _, base := range []string{
				"_init", "_getitem", "_setitem",
				"_add", "_sub", "_mul", "_div", "_mod",
				"_radd", "_rsub", "_rmul", "_rdiv", "_rmod",
				"_inc", "_dec",
				"_pos", "_neg", "_invert",
				"_eq", "_ne", "_gt", "_ge", "_lt", "_le",
				"_or", "_ror", "_and", "_rand", "_xor", "_rxor",
				"_lshift", "_rlshift", "_rshift", "_rrshift",
				"_bitclear", "_rbitclear",
			} {
				if len(n) > len(base) && n[:len(base)+1] == base+"_" {
					return true
				}
			}
		}
	}

	// 2b) detect magic methods in interface types (commonly used as generic constraints),
	// e.g. `interface{ _recv() T }`, `interface{ _send(T) }`, `interface{ _getitem(int) T }`.
	for _, f := range files {
		found := false
		ast.Inspect(f, func(n ast.Node) bool {
			it, _ := n.(*ast.InterfaceType)
			if it == nil || it.Methods == nil {
				return true
			}
			for _, fld := range it.Methods.List {
				if fld == nil || len(fld.Names) == 0 {
					continue
				}
				for _, nm := range fld.Names {
					if nm == nil {
						continue
					}
					name := nm.Name
					if isSingleUnderscoreMagic(name) {
						found = true
						return false
					}
					// Handle overloaded magic names like "_add_int" (tooling).
					for _, base := range []string{
						"_init", "_getitem", "_setitem",
						"_add", "_sub", "_mul", "_div", "_mod",
						"_radd", "_rsub", "_rmul", "_rdiv", "_rmod",
						"_inc", "_dec",
						"_pos", "_neg", "_invert",
						"_eq", "_ne", "_gt", "_ge", "_lt", "_le",
						"_or", "_ror", "_and", "_rand", "_xor", "_rxor",
						"_lshift", "_rlshift", "_rshift", "_rrshift",
						"_bitclear", "_rbitclear",
						"_recv", "_send",
					} {
						if strings.HasPrefix(name, base+"_") {
							found = true
							return false
						}
					}
				}
			}
			return true
		})
		if found {
			return true
		}
	}

	// 3) detect struct constructor form: make(T, ...) where T is not a map/slice/chan type expr.
	foundCtor := false
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, _ := n.(*ast.CallExpr)
			if call == nil || len(call.Args) == 0 {
				return true
			}
			id, _ := call.Fun.(*ast.Ident)
			if id == nil || id.Name != "make" {
				return true
			}
			switch call.Args[0].(type) {
			case *ast.ArrayType, *ast.MapType, *ast.ChanType:
				return true
			default:
				// Ident/SelectorExpr/IndexExpr/etc.
				foundCtor = true
				return false
			}
		})
		if foundCtor {
			return true
		}
	}

	return false
}

func exprToStringCheap(e ast.Expr) string {
	if e == nil {
		return ""
	}
	var buf bytes.Buffer
	_ = printer.Fprint(&buf, token.NewFileSet(), e)
	return buf.String()
}


