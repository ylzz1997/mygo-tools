// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package typecheck implements a MyGO-aware type-checking rewrite pipeline.
//
// It is designed to be reusable across tools (gopls, analyzers, etc).
//
// Background:
// - MyGO extends go/parser to produce MyGO-only AST nodes such as
//   OptionalChainExpr and TernaryExpr.
// - go/types does not know these nodes.
//
// Strategy (2-phase):
//  1) Replace MyGO-only nodes with go/types-friendly placeholders, then run a
//     temporary type-check to collect enough type information.
//  2) Expand placeholders into standard Go AST (IIFE + nil checks + &addr),
//     then run the real type-check on the expanded AST.
//
// Notes:
// - We intentionally avoid importing MyGO-specific packages directly. Instead,
//   we use reflection to detect optional/ternary node types so upstream Go
//   builds remain unaffected.
package typecheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"

	goastutil "golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/internal/typesinternal"
)

func isOptionalChainExpr(n ast.Node) bool {
	if n == nil {
		return false
	}
	return reflect.TypeOf(n).String() == "*ast.OptionalChainExpr"
}

func isTernaryExpr(n ast.Node) bool {
	if n == nil {
		return false
	}
	return reflect.TypeOf(n).String() == "*ast.TernaryExpr"
}

func isElvisExpr(n ast.Node) bool {
	if n == nil {
		return false
	}
	return reflect.TypeOf(n).String() == "*ast.ElvisExpr"
}

// NeedsRewrite reports whether file contains any MyGO-only AST nodes that
// require rewriting before go/types can type-check it.
func NeedsRewrite(file *ast.File) bool {
	need := false
	ast.Inspect(file, func(n ast.Node) bool {
		if isOptionalChainExpr(n) || isTernaryExpr(n) || isElvisExpr(n) {
			need = true
			return false
		}
		return true
	})
	return need
}

type ternaryInfo struct {
	cond ast.Expr
	x    ast.Expr
	y    ast.Expr // may be nil (short form)
	pos  token.Pos
}

type elvisInfo struct {
	x   ast.Expr
	y   ast.Expr
	pos token.Pos
}

type placeholders struct {
	optionalSelectors map[*ast.SelectorExpr]token.Pos
	optionalCalls     map[*ast.CallExpr]token.Pos
	ternaryParens     map[*ast.ParenExpr]ternaryInfo
	elvisParens       map[*ast.ParenExpr]elvisInfo
}

func newPlaceholders() *placeholders {
	return &placeholders{
		optionalSelectors: make(map[*ast.SelectorExpr]token.Pos),
		optionalCalls:     make(map[*ast.CallExpr]token.Pos),
		ternaryParens:     make(map[*ast.ParenExpr]ternaryInfo),
		elvisParens:       make(map[*ast.ParenExpr]elvisInfo),
	}
}

// preparePlaceholders mutates file in-place, replacing MyGO-only nodes with
// placeholders, returning a descriptor for later expansion.
func preparePlaceholders(file *ast.File) *placeholders {
	ph := newPlaceholders()

	var pre func(*goastutil.Cursor) bool

	// rewriteExpr rewrites a detached expression tree (not currently in the file AST)
	// by temporarily wrapping it in an ExprStmt so that Cursor.Replace can update it.
	rewriteExpr := func(e ast.Expr) ast.Expr {
		if e == nil {
			return nil
		}
		stmt := &ast.ExprStmt{X: e}
		goastutil.Apply(stmt, pre, nil)
		return stmt.X
	}

	pre = func(c *goastutil.Cursor) bool {
		// Mark optional calls early (we must not rewrite their selector placeholder).
		if call, ok := c.Node().(*ast.CallExpr); ok {
			if isOptionalChainExpr(call.Fun) {
				ph.optionalCalls[call] = call.Pos()
			}
			return true
		}

		if isOptionalChainExpr(c.Node()) {
			v := reflect.ValueOf(c.Node()).Elem()
			xAny := v.FieldByName("X").Interface()
			selAny := v.FieldByName("Sel").Interface()
			x, _ := xAny.(ast.Expr)
			sel, _ := selAny.(*ast.Ident)
			placeholder := &ast.SelectorExpr{X: x, Sel: sel}

			// If used as CallExpr.Fun, don't track selector; call rewrite will handle.
			if parent := c.Parent(); parent != nil {
				if _, ok := parent.(*ast.CallExpr); ok && c.Name() == "Fun" {
					c.Replace(placeholder)
					return true
				}
			}

			ph.optionalSelectors[placeholder] = c.Node().Pos()
			c.Replace(placeholder)
			return true
		}

		if isTernaryExpr(c.Node()) {
			v := reflect.ValueOf(c.Node()).Elem()
			condAny := v.FieldByName("Cond").Interface()
			xAny := v.FieldByName("X").Interface()
			yAny := v.FieldByName("Y").Interface()
			cond, _ := condAny.(ast.Expr)
			x, _ := xAny.(ast.Expr)
			y, _ := yAny.(ast.Expr)
			pos := c.Node().Pos()

			// cond/y are not part of the placeholder subtree, so rewrite them now.
			cond = rewriteExpr(cond)
			y = rewriteExpr(y)

			paren := &ast.ParenExpr{Lparen: pos, X: x, Rparen: pos}
			ph.ternaryParens[paren] = ternaryInfo{cond: cond, x: x, y: y, pos: pos}
			c.Replace(paren)
			return true
		}

		if isElvisExpr(c.Node()) {
			v := reflect.ValueOf(c.Node()).Elem()
			xAny := v.FieldByName("X").Interface()
			yAny := v.FieldByName("Y").Interface()
			x, _ := xAny.(ast.Expr)
			y, _ := yAny.(ast.Expr)
			pos := c.Node().Pos()

			// y is not part of the placeholder subtree, so rewrite it now.
			y = rewriteExpr(y)

			// Placeholder is a dereference (*x) so that:
			// - x is still type-checked (we need its type for rewrite),
			// - the placeholder has the "value" type (matching elvis semantics),
			// - go/types produces sensible inference for surrounding code.
			deref := &ast.StarExpr{Star: pos, X: x}
			paren := &ast.ParenExpr{Lparen: pos, X: deref, Rparen: pos}
			ph.elvisParens[paren] = elvisInfo{x: x, y: y, pos: pos}
			c.Replace(paren)
			return true
		}

		return true
	}

	goastutil.Apply(file, pre, nil)

	return ph
}

func parseTypeExpr(typeStr string) ast.Expr {
	e, err := parser.ParseExpr(typeStr)
	if err != nil {
		return &ast.Ident{Name: "any"}
	}
	return e
}

func ptrTypeExpr(base ast.Expr) ast.Expr {
	return &ast.StarExpr{Star: base.Pos(), X: base}
}

func nilIdent(pos token.Pos) *ast.Ident {
	return &ast.Ident{NamePos: pos, Name: "nil"}
}

func rewriteOptionalSelector(sel *ast.SelectorExpr, pos token.Pos, info *types.Info, qual types.Qualifier) ast.Expr {
	baseType := info.TypeOf(sel.X)
	if baseType == nil {
		return sel
	}
	paramTypeExpr := parseTypeExpr(types.TypeString(baseType, qual))

	fieldType := info.TypeOf(sel)
	if fieldType == nil {
		return sel
	}
	fieldTypeExpr := parseTypeExpr(types.TypeString(fieldType, qual))
	retTypeExpr := ptrTypeExpr(fieldTypeExpr)

	vName := &ast.Ident{NamePos: pos, Name: "_mygo_v"}
	vRef1 := &ast.Ident{NamePos: pos, Name: "_mygo_v"}
	vRef2 := &ast.Ident{NamePos: pos, Name: "_mygo_v"}

	nilCheck := &ast.IfStmt{
		If: pos,
		Cond: &ast.BinaryExpr{
			X:     vRef1,
			OpPos: pos,
			Op:    token.EQL,
			Y:     nilIdent(pos),
		},
		Body: &ast.BlockStmt{
			Lbrace: pos,
			List: []ast.Stmt{
				&ast.ReturnStmt{Return: pos, Results: []ast.Expr{nilIdent(pos)}},
			},
			Rbrace: pos,
		},
	}

	addr := &ast.UnaryExpr{
		OpPos: pos,
		Op:    token.AND,
		X:     &ast.SelectorExpr{X: vRef2, Sel: sel.Sel},
	}

	fn := &ast.FuncLit{
		Type: &ast.FuncType{
			Func: pos,
			Params: &ast.FieldList{
				Opening: pos,
				List: []*ast.Field{{
					Names: []*ast.Ident{vName},
					Type:  paramTypeExpr,
				}},
				Closing: pos,
			},
			Results: &ast.FieldList{
				Opening: pos,
				List: []*ast.Field{{Type: retTypeExpr}},
				Closing: pos,
			},
		},
		Body: &ast.BlockStmt{
			Lbrace: pos,
			List: []ast.Stmt{
				nilCheck,
				&ast.ReturnStmt{Return: pos, Results: []ast.Expr{addr}},
			},
			Rbrace: pos,
		},
	}

	return &ast.CallExpr{Fun: fn, Lparen: pos, Args: []ast.Expr{sel.X}, Rparen: pos}
}

func rewriteOptionalCall(call *ast.CallExpr, pos token.Pos, info *types.Info, qual types.Qualifier) ast.Expr {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return call
	}

	baseType := info.TypeOf(sel.X)
	if baseType == nil {
		return call
	}
	paramTypeExpr := parseTypeExpr(types.TypeString(baseType, qual))

	resType := info.TypeOf(call) // nil for void calls used as statements

	vName := &ast.Ident{NamePos: pos, Name: "_mygo_v"}
	vRef1 := &ast.Ident{NamePos: pos, Name: "_mygo_v"}
	vRef2 := &ast.Ident{NamePos: pos, Name: "_mygo_v"}

	methodCall := &ast.CallExpr{
		Fun:    &ast.SelectorExpr{X: vRef2, Sel: sel.Sel},
		Lparen: pos,
		Args:   call.Args,
		Rparen: pos,
	}

	if resType == nil {
		nilCheck := &ast.IfStmt{
			If: pos,
			Cond: &ast.BinaryExpr{
				X:     vRef1,
				OpPos: pos,
				Op:    token.EQL,
				Y:     nilIdent(pos),
			},
			Body: &ast.BlockStmt{
				Lbrace: pos,
				List:   []ast.Stmt{&ast.ReturnStmt{Return: pos}},
				Rbrace: pos,
			},
		}

		fn := &ast.FuncLit{
			Type: &ast.FuncType{
				Func: pos,
				Params: &ast.FieldList{
					Opening: pos,
					List: []*ast.Field{{
						Names: []*ast.Ident{vName},
						Type:  paramTypeExpr,
					}},
					Closing: pos,
				},
			},
			Body: &ast.BlockStmt{
				Lbrace: pos,
				List: []ast.Stmt{
					nilCheck,
					&ast.ExprStmt{X: methodCall},
				},
				Rbrace: pos,
			},
		}
		return &ast.CallExpr{Fun: fn, Lparen: pos, Args: []ast.Expr{sel.X}, Rparen: pos}
	}

	retElem := parseTypeExpr(types.TypeString(resType, qual))
	retTypeExpr := ptrTypeExpr(retElem)

	rName := &ast.Ident{NamePos: pos, Name: "_mygo_r0"}
	rRef := &ast.Ident{NamePos: pos, Name: "_mygo_r0"}
	addr := &ast.UnaryExpr{OpPos: pos, Op: token.AND, X: rRef}

	nilCheck := &ast.IfStmt{
		If: pos,
		Cond: &ast.BinaryExpr{
			X:     vRef1,
			OpPos: pos,
			Op:    token.EQL,
			Y:     nilIdent(pos),
		},
		Body: &ast.BlockStmt{
			Lbrace: pos,
			List: []ast.Stmt{
				&ast.ReturnStmt{Return: pos, Results: []ast.Expr{nilIdent(pos)}},
			},
			Rbrace: pos,
		},
	}

	assign := &ast.AssignStmt{
		Lhs:    []ast.Expr{rName},
		TokPos: pos,
		Tok:    token.DEFINE,
		Rhs:    []ast.Expr{methodCall},
	}

	fn := &ast.FuncLit{
		Type: &ast.FuncType{
			Func: pos,
			Params: &ast.FieldList{
				Opening: pos,
				List: []*ast.Field{{
					Names: []*ast.Ident{vName},
					Type:  paramTypeExpr,
				}},
				Closing: pos,
			},
			Results: &ast.FieldList{
				Opening: pos,
				List: []*ast.Field{{Type: retTypeExpr}},
				Closing: pos,
			},
		},
		Body: &ast.BlockStmt{
			Lbrace: pos,
			List: []ast.Stmt{
				nilCheck,
				assign,
				&ast.ReturnStmt{Return: pos, Results: []ast.Expr{addr}},
			},
			Rbrace: pos,
		},
	}

	return &ast.CallExpr{Fun: fn, Lparen: pos, Args: []ast.Expr{sel.X}, Rparen: pos}
}

func rewriteTernary(paren *ast.ParenExpr, ti ternaryInfo, info *types.Info, qual types.Qualifier) ast.Expr {
	resType := info.TypeOf(paren.X)
	if resType == nil {
		resType = types.Typ[types.UntypedNil]
	}
	retTypeExpr := parseTypeExpr(types.TypeString(resType, qual))

	ifStmt := &ast.IfStmt{
		If:   ti.pos,
		Cond: ti.cond,
		Body: &ast.BlockStmt{
			Lbrace: ti.pos,
			List: []ast.Stmt{
				&ast.ReturnStmt{Return: ti.pos, Results: []ast.Expr{ti.x}},
			},
			Rbrace: ti.pos,
		},
	}

	var tail ast.Stmt
	if ti.y != nil {
		tail = &ast.ReturnStmt{Return: ti.pos, Results: []ast.Expr{ti.y}}
	} else {
		zName := &ast.Ident{NamePos: ti.pos, Name: "_mygo_zero"}
		tail = &ast.BlockStmt{
			Lbrace: ti.pos,
			List: []ast.Stmt{
				&ast.DeclStmt{Decl: &ast.GenDecl{
					TokPos: ti.pos,
					Tok:    token.VAR,
					Specs:  []ast.Spec{&ast.ValueSpec{Names: []*ast.Ident{zName}, Type: retTypeExpr}},
				}},
				&ast.ReturnStmt{Return: ti.pos, Results: []ast.Expr{&ast.Ident{NamePos: ti.pos, Name: "_mygo_zero"}}},
			},
			Rbrace: ti.pos,
		}
	}

	fn := &ast.FuncLit{
		Type: &ast.FuncType{
			Func:    ti.pos,
			Params:  &ast.FieldList{Opening: ti.pos, Closing: ti.pos},
			Results: &ast.FieldList{Opening: ti.pos, List: []*ast.Field{{Type: retTypeExpr}}, Closing: ti.pos},
		},
		Body: &ast.BlockStmt{
			Lbrace: ti.pos,
			List:   []ast.Stmt{ifStmt, tail},
			Rbrace: ti.pos,
		},
	}

	return &ast.CallExpr{Fun: fn, Lparen: ti.pos, Rparen: ti.pos}
}

func rewriteElvis(paren *ast.ParenExpr, ei elvisInfo, info *types.Info, qual types.Qualifier) ast.Expr {
	baseType := info.TypeOf(ei.x)
	if baseType == nil {
		return paren
	}
	paramTypeExpr := parseTypeExpr(types.TypeString(baseType, qual))

	resType := info.TypeOf(paren.X)
	if resType == nil {
		resType = types.Typ[types.UntypedNil]
	}
	retTypeExpr := parseTypeExpr(types.TypeString(resType, qual))

	vName := &ast.Ident{NamePos: ei.pos, Name: "_mygo_v"}
	vRef1 := &ast.Ident{NamePos: ei.pos, Name: "_mygo_v"}
	vRef2 := &ast.Ident{NamePos: ei.pos, Name: "_mygo_v"}

	nilCheck := &ast.IfStmt{
		If: ei.pos,
		Cond: &ast.BinaryExpr{
			X:     vRef1,
			OpPos: ei.pos,
			Op:    token.EQL,
			Y:     nilIdent(ei.pos),
		},
		Body: &ast.BlockStmt{
			Lbrace: ei.pos,
			List: []ast.Stmt{
				&ast.ReturnStmt{Return: ei.pos, Results: []ast.Expr{ei.y}},
			},
			Rbrace: ei.pos,
		},
	}

	deref := &ast.StarExpr{Star: ei.pos, X: vRef2}

	fn := &ast.FuncLit{
		Type: &ast.FuncType{
			Func: ei.pos,
			Params: &ast.FieldList{
				Opening: ei.pos,
				List: []*ast.Field{{
					Names: []*ast.Ident{vName},
					Type:  paramTypeExpr,
				}},
				Closing: ei.pos,
			},
			Results: &ast.FieldList{
				Opening: ei.pos,
				List:    []*ast.Field{{Type: retTypeExpr}},
				Closing: ei.pos,
			},
		},
		Body: &ast.BlockStmt{
			Lbrace: ei.pos,
			List: []ast.Stmt{
				nilCheck,
				&ast.ReturnStmt{Return: ei.pos, Results: []ast.Expr{deref}},
			},
			Rbrace: ei.pos,
		},
	}

	return &ast.CallExpr{Fun: fn, Lparen: ei.pos, Args: []ast.Expr{ei.x}, Rparen: ei.pos}
}

func expandPlaceholders(file *ast.File, ph *placeholders, info *types.Info, pkg *types.Package) {
	qual := typesinternal.FileQualifier(file, pkg)

	goastutil.Apply(file, func(c *goastutil.Cursor) bool {
		if sel, ok := c.Node().(*ast.SelectorExpr); ok {
			if pos, ok := ph.optionalSelectors[sel]; ok {
				c.Replace(rewriteOptionalSelector(sel, pos, info, qual))
				return true
			}
			return true
		}
		if call, ok := c.Node().(*ast.CallExpr); ok {
			if pos, ok := ph.optionalCalls[call]; ok {
				c.Replace(rewriteOptionalCall(call, pos, info, qual))
				return true
			}
			return true
		}
		if paren, ok := c.Node().(*ast.ParenExpr); ok {
			if ei, ok := ph.elvisParens[paren]; ok {
				c.Replace(rewriteElvis(paren, ei, info, qual))
				return true
			}
			if ti, ok := ph.ternaryParens[paren]; ok {
				c.Replace(rewriteTernary(paren, ti, info, qual))
				return true
			}
			return true
		}
		return true
	}, nil)
}

// RewriteInPlace performs MyGO 2-phase rewrite on the provided files, using
// tmpPkg/tmpInfo from a temporary typecheck.
//
// The caller is responsible for:
// - cloning ASTs before calling (to avoid shared cache mutation),
// - performing the temporary typecheck that populates tmpInfo,
// - running the final typecheck after rewrite.
func RewriteInPlace(files []*ast.File, tmpInfo *types.Info, tmpPkg *types.Package) {
	phs := make([]*placeholders, 0, len(files))
	for _, f := range files {
		phs = append(phs, preparePlaceholders(f))
	}
	for i, f := range files {
		expandPlaceholders(f, phs[i], tmpInfo, tmpPkg)
	}
}


