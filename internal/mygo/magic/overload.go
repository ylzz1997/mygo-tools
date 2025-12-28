// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package magic implements MyGO "magic features" rewrites for tools like gopls.
//
// This package is intentionally written against go/ast + go/types so it can run
// inside x/tools without importing cmd/compile internals.
package magic

import (
	"bytes"
	"go/ast"
	"go/printer"
	"go/token"
	"strings"
)

// OverloadIndex records method overload groups after renaming.
// Key is receiver-type string + "." + original method name.
type OverloadIndex struct {
	ByGroup map[string]*OverloadInfo
}

type OverloadInfo struct {
	RecvType   string // syntactic receiver type, e.g. "*User" or "User"
	MethodName string // original method name, e.g. "Add"
	Overloads  []OverloadEntry
}

type OverloadEntry struct {
	NewName string
	Decl    *ast.FuncDecl
}

// RenameOverloadedMethods renames method declarations that share the same
// (receiver type, method name) within the provided files.
//
// This mirrors the MyGO compiler "pre-types" behavior: overloaded methods are
// renamed with a suffix derived from parameter types so the program can be
// type-checked by standard go/types.
//
// Note: call sites are not rewritten here.
func RenameOverloadedMethods(files []*ast.File, fset *token.FileSet) *OverloadIndex {
	idx := &OverloadIndex{ByGroup: make(map[string]*OverloadInfo)}
	if len(files) == 0 {
		return idx
	}

	// Collect groups.
	groups := make(map[string][]*ast.FuncDecl)
	for _, f := range files {
		for _, d := range f.Decls {
			fd, _ := d.(*ast.FuncDecl)
			if fd == nil || fd.Recv == nil || fd.Name == nil {
				continue
			}
			recvType := exprToString(fset, fd.Recv.List[0].Type)
			key := recvType + "." + fd.Name.Name
			groups[key] = append(groups[key], fd)
		}
	}

	for key, fns := range groups {
		if len(fns) <= 1 {
			continue
		}
		recvType, methodName := splitFirst(key, ".")
		info := &OverloadInfo{
			RecvType:   recvType,
			MethodName: methodName,
		}
		for _, fn := range fns {
			paramTypes := getParamTypeStrings(fset, fn.Type)
			suffix := generateMethodSuffix(paramTypes)

			var newName string
			if isSingleUnderscoreMagic(methodName) {
				newName = methodName + suffix
			} else {
				newName = "_" + methodName + suffix
			}
			fn.Name.Name = newName
			info.Overloads = append(info.Overloads, OverloadEntry{NewName: newName, Decl: fn})
		}
		idx.ByGroup[key] = info
	}

	return idx
}

func isSingleUnderscoreMagic(methodName string) bool {
	switch methodName {
	case "_init", "_getitem", "_setitem",
		"_add", "_sub", "_mul", "_div", "_mod",
		"_radd", "_rsub", "_rmul", "_rdiv", "_rmod",
		"_inc", "_dec",
		"_pos", "_neg", "_invert",
		"_eq", "_ne", "_gt", "_ge", "_lt", "_le",
		"_or", "_ror", "_and", "_rand", "_xor", "_rxor",
		"_lshift", "_rlshift", "_rshift", "_rrshift",
		"_bitclear", "_rbitclear",
		"_recv", "_send":
		return true
	default:
		return false
	}
}

func exprToString(fset *token.FileSet, e ast.Expr) string {
	if e == nil {
		return ""
	}
	var buf bytes.Buffer
	_ = printer.Fprint(&buf, fset, e)
	// Normalize whitespace to match compiler behavior (no spaces).
	return strings.ReplaceAll(buf.String(), " ", "")
}

func getParamTypeStrings(fset *token.FileSet, ft *ast.FuncType) []string {
	if ft == nil || ft.Params == nil {
		return nil
	}
	var out []string
	for _, f := range ft.Params.List {
		if f == nil || f.Type == nil {
			continue
		}
		ts := exprToString(fset, f.Type)
		// One entry per parameter name; if unnamed, still count one.
		n := len(f.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			out = append(out, ts)
		}
	}
	return out
}

func generateMethodSuffix(paramTypes []string) string {
	if len(paramTypes) == 0 {
		return "_void"
	}
	var b strings.Builder
	for _, pt := range paramTypes {
		b.WriteByte('_')
		b.WriteString(sanitizeTypeName(pt))
	}
	return b.String()
}

func sanitizeTypeName(typeName string) string {
	// Variadic: ...T -> variadic_T
	if strings.HasPrefix(typeName, "...") {
		return "variadic_" + sanitizeTypeName(strings.TrimPrefix(typeName, "..."))
	}
	var b strings.Builder
	for _, ch := range typeName {
		switch ch {
		case '*':
			b.WriteString("ptr")
		case '[':
			b.WriteString("slice")
		case ']':
			// skip
		case '.':
			b.WriteByte('_')
		case ' ':
			// skip
		default:
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func splitFirst(s, sep string) (string, string) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):]
	}
	return s, ""
}


