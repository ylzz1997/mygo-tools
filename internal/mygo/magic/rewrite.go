// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magic

import (
	"crypto/sha1"
	"encoding/hex"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	goastutil "golang.org/x/tools/go/ast/astutil"
	internalastutil "golang.org/x/tools/internal/astutil"
)

type reqMethod struct {
	name string
	sig  *types.Signature
}

type tpPlan struct {
	tpIdx       int
	orig        types.Type
	wrapperName string
}

// Rewrite applies MyGO magic rewrites to make code type-check under standard go/types.
//
// It is designed for tooling (gopls) and therefore focuses on producing a
// type-checkable Go AST and good editor behavior.
func Rewrite(files []*ast.File, pkg *types.Package, info *types.Info) {
	if len(files) == 0 || pkg == nil || info == nil {
		return
	}
	for _, f := range files {
		rewriteNativeSynthesisForConstraints(files, f, pkg, info)
		rewriteCompoundAssign(f)
		rewriteIncDec(f, pkg, info)
		rewriteIndexing(f, pkg, info)
		rewriteMakeConstructors(f, pkg, info)
		rewriteOperators(f, pkg, info)
		rewriteOverloadedMethodCalls(f, pkg, info)
	}
}

// rewriteNativeSynthesisForConstraints emulates a subset of the MyGO compiler's
// "native type magic method synthesis" for tools (gopls), based on README rules.
//
// Since go/types cannot be taught new methods on basic/slice/map/chan types, we
// make constraint-satisfaction work by:
// - injecting hidden wrapper types that implement magic methods (_add/_getitem/_init/...),
// - rewriting generic call sites to pass wrapper values,
// - casting the result back to the original native type (and using unsafe for *T).
//
// This is a best-effort, tooling-only rewrite: the goal is to eliminate bogus
// editor errors, not to preserve runtime behavior for rewritten wrappers.
func rewriteNativeSynthesisForConstraints(allFiles []*ast.File, file *ast.File, pkg *types.Package, info *types.Info) {
	if len(allFiles) == 0 || allFiles[0] == nil {
		return
	}
	anchor := allFiles[0]

	// Track whether we need "unsafe" for pointer casts.
	needUnsafe := false
	ensureUnsafeImport := func() {
		if !needUnsafe {
			return
		}
		ensureImport(anchor, "unsafe")
	}

	// Cache: wrapper key -> wrapper name.
	// Key is a stable string describing the native type + required methods.
	wrappers := make(map[string]string)

	getWrapper := func(key string, mk func(name string)) string {
		if n, ok := wrappers[key]; ok {
			return n
		}
		h := sha1.Sum([]byte(key))
		sfx := hex.EncodeToString(h[:6]) // 12 hex chars, short but stable
		name := "__mygo_native_" + sfx
		wrappers[key] = name
		mk(name)
		return name
	}

	// Resolve a generic function object for a call.
	resolveCalledFunc := func(call *ast.CallExpr) (fn *types.Func, sig *types.Signature, typeArgs []ast.Expr, funNode ast.Expr) {
		if call == nil {
			return nil, nil, nil, nil
		}
		funNode = ast.Unparen(call.Fun)
		// Handle explicit instantiation: f[T](...) or f[A,B](...)
		switch n := funNode.(type) {
		case *ast.IndexExpr:
			typeArgs = []ast.Expr{n.Index}
			funNode = ast.Unparen(n.X)
		case *ast.IndexListExpr:
			typeArgs = n.Indices
			funNode = ast.Unparen(n.X)
		}

		switch fun := funNode.(type) {
		case *ast.Ident:
			fn, _ = info.Uses[fun].(*types.Func)
			if fn == nil {
				return nil, nil, typeArgs, funNode
			}
			sig, _ = fn.Type().(*types.Signature)
			return fn, sig, typeArgs, funNode
		case *ast.SelectorExpr:
			// Best-effort: only handle selector that resolves to a function.
			if fun.Sel == nil {
				return nil, nil, typeArgs, funNode
			}
			fn, _ = info.Uses[fun.Sel].(*types.Func)
			if fn == nil {
				return nil, nil, typeArgs, funNode
			}
			sig, _ = fn.Type().(*types.Signature)
			return fn, sig, typeArgs, funNode
		default:
			return nil, nil, typeArgs, funNode
		}
	}

	// Determine which type parameter each argument "belongs to" (simple cases).
	// Return map: arg index -> (tpIndex, wantPtr)
	argToTP := func(sig *types.Signature) map[int]struct {
		tpIdx   int
		wantPtr bool
	} {
		out := make(map[int]struct {
			tpIdx   int
			wantPtr bool
		})
		if sig == nil || sig.TypeParams() == nil || sig.TypeParams().Len() == 0 || sig.Params() == nil {
			return out
		}
		nparams := sig.Params().Len()
		// Only handle non-variadic, and positional args.
		for i := 0; i < nparams; i++ {
			p := sig.Params().At(i)
			if p == nil {
				continue
			}
			pt := p.Type()
			wantPtr := false
			if ptr, ok := pt.(*types.Pointer); ok && ptr != nil {
				wantPtr = true
				pt = ptr.Elem()
			}
			tpn, ok := pt.(*types.TypeParam)
			if !ok || tpn == nil || tpn.Obj() == nil {
				continue
			}
			// Find index.
			for ti := 0; ti < sig.TypeParams().Len(); ti++ {
				if sig.TypeParams().At(ti) == tpn {
					out[i] = struct {
						tpIdx   int
						wantPtr bool
					}{tpIdx: ti, wantPtr: wantPtr}
					break
				}
			}
		}
		return out
	}

	// Extract required magic methods from constraint interface.
	requiredMagic := func(tp *types.TypeParam) []reqMethod {
		if tp == nil {
			return nil
		}
		iface, _ := tp.Constraint().Underlying().(*types.Interface)
		if iface == nil {
			return nil
		}
		var out []reqMethod
		for i := 0; i < iface.NumMethods(); i++ {
			m := iface.Method(i)
			if m == nil {
				continue
			}
			n := m.Name()
			if !isSingleUnderscoreMagic(n) {
				continue
			}
			sig, _ := m.Type().(*types.Signature)
			out = append(out, reqMethod{name: n, sig: sig})
		}
		return out
	}

	// Determine whether a type is a native basic/slice/map/chan eligible for synthesis.
	kindOfNative := func(t types.Type) (kind string, base types.Type) {
		if t == nil {
			return "", nil
		}
		// Preserve named types (e.g. type MySlice []int): we still wrap by converting the *value*.
		u := t.Underlying()
		switch u.(type) {
		case *types.Slice:
			return "slice", t
		case *types.Map:
			return "map", t
		case *types.Chan:
			return "chan", t
		case *types.Basic:
			return "basic", t
		default:
			return "", nil
		}
	}

	// Build a wrapper for a concrete native type that provides the required methods.
	ensureWrapperFor := func(native types.Type, methods []reqMethod) (wrapperName string, ok bool) {
		if native == nil || len(methods) == 0 {
			return "", false
		}
		k, _ := kindOfNative(native)
		if k == "" {
			return "", false
		}

		// Only synthesize wrappers for a known subset of methods.
		// If we can't build at least one required method, bail (do not rewrite).
		keyParts := []string{"native", types.TypeString(native, nil)}
		for _, m := range methods {
			keyParts = append(keyParts, m.name, methodSigString(m.sig))
		}
		key := strings.Join(keyParts, "|")

		// Determine which methods we can synthesize.
		canAny := false
		for _, m := range methods {
			if canSynthesizeMethod(native, m.name, m.sig) {
				canAny = true
				break
			}
		}
		if !canAny {
			return "", false
		}

		wrapperName = getWrapper(key, func(name string) {
			// Inject type + methods into the anchor file.
			injectWrapperDecls(anchor, name, native, methods)
		})
		return wrapperName, true
	}

	// Rewrite calls.
	goastutil.Apply(file, func(c *goastutil.Cursor) bool {
		call, ok := c.Node().(*ast.CallExpr)
		if !ok || call == nil {
			return true
		}
		_, sig, typeArgs, _ := resolveCalledFunc(call)
		if sig == nil || sig.TypeParams() == nil || sig.TypeParams().Len() == 0 {
			return true
		}

		// Only handle cases where we can map args -> specific type params.
		mapping := argToTP(sig)
		if len(mapping) == 0 && len(typeArgs) == 0 {
			return true
		}

		// Determine concrete type for each type param:
		// - from explicit type arguments if present,
		// - otherwise from mapped value args (simple cases).
		tpConcrete := make(map[int]types.Type)
		if len(typeArgs) > 0 {
			for ti := 0; ti < len(typeArgs) && ti < sig.TypeParams().Len(); ti++ {
				ta := typeArgs[ti]
				if tt := typeArgType(info, ta); tt != nil {
					tpConcrete[ti] = tt
				}
			}
		}
		for ai, mi := range mapping {
			if ai >= len(call.Args) {
				continue
			}
			at := info.TypeOf(call.Args[ai])
			if at == nil {
				continue
			}
			// If param is *T and arg is addressable, type could be *something; strip ptr for synthesis.
			if mi.wantPtr {
				if p, ok := at.(*types.Pointer); ok && p != nil {
					at = p.Elem()
				}
			}
			if _, ok := tpConcrete[mi.tpIdx]; !ok {
				tpConcrete[mi.tpIdx] = at
			}
		}

		// Decide wrappers per type param.
		var plans []tpPlan
		for ti := 0; ti < sig.TypeParams().Len(); ti++ {
			tp := sig.TypeParams().At(ti)
			orig := tpConcrete[ti]
			if orig == nil {
				continue
			}
			methods := requiredMagic(tp)
			if len(methods) == 0 {
				continue
			}
			wname, ok := ensureWrapperFor(orig, methods)
			if !ok {
				continue
			}
			plans = append(plans, tpPlan{tpIdx: ti, orig: orig, wrapperName: wname})
		}
		if len(plans) == 0 {
			return true
		}

		// If this call has explicit type arguments (f[T]), rewrite them to wrapper types.
		// This is necessary for cases like f[T]() where there are no value args to wrap.
		if len(typeArgs) > 0 {
			switch fnNode := ast.Unparen(call.Fun).(type) {
			case *ast.IndexExpr:
				if fnNode != nil {
					if p := findPlan(plans, 0); p != nil {
						fnNode.Index = &ast.Ident{Name: p.wrapperName}
					}
				}
			case *ast.IndexListExpr:
				if fnNode != nil {
					for ti := 0; ti < len(fnNode.Indices) && ti < sig.TypeParams().Len(); ti++ {
						if p := findPlan(plans, ti); p != nil {
							fnNode.Indices[ti] = &ast.Ident{Name: p.wrapperName}
						}
					}
				}
			}
		}

		// Apply argument conversions for mapped args.
		for ai, mi := range mapping {
			if ai >= len(call.Args) {
				continue
			}
			plan := findPlan(plans, mi.tpIdx)
			if plan == nil {
				continue
			}
			// Wrap arg as: Wrapper(arg)
			call.Args[ai] = &ast.CallExpr{
				Fun:  &ast.Ident{Name: plan.wrapperName},
				Args: []ast.Expr{call.Args[ai]},
			}
		}

		// Cast result back in common patterns:
		// - result is T:  Orig(callWrapped)
		// - result is *T: (*Orig)(unsafe.Pointer(callWrapped))
		//
		// We only do this if there is exactly 1 result.
		if sig.Results() != nil && sig.Results().Len() == 1 {
			rt := sig.Results().At(0).Type()
			// If result is T (a type param), cast to original native type name.
			if tpn, ok := rt.(*types.TypeParam); ok && tpn != nil {
				for _, p := range plans {
					if sig.TypeParams().At(p.tpIdx) == tpn {
						c.Replace(&ast.CallExpr{
							Fun:  typeExprForNative(p.orig),
							Args: []ast.Expr{call},
						})
						return false
					}
				}
			}
			// If result is *T, cast via unsafe.Pointer.
			if ptr, ok := rt.(*types.Pointer); ok && ptr != nil {
				if tpn, ok := ptr.Elem().(*types.TypeParam); ok && tpn != nil {
					for _, p := range plans {
						if sig.TypeParams().At(p.tpIdx) == tpn {
							needUnsafe = true
							ensureUnsafeImport()
							c.Replace(&ast.CallExpr{
								Fun: &ast.ParenExpr{
									X: &ast.StarExpr{
										X: typeExprForNative(p.orig),
									},
								},
								Args: []ast.Expr{
									&ast.CallExpr{
										Fun: &ast.SelectorExpr{
											X:   &ast.Ident{Name: "unsafe"},
											Sel: &ast.Ident{Name: "Pointer"},
										},
										Args: []ast.Expr{call},
									},
								},
							})
							return false
						}
					}
				}
			}
		}

		return true
	}, nil)
}

func typeArgType(info *types.Info, e ast.Expr) types.Type {
	if info == nil || e == nil {
		return nil
	}
	// Prefer Types map (type-checker provided).
	if tv, ok := info.Types[e]; ok && tv.IsType() && tv.Type != nil {
		return tv.Type
	}
	// Fallback: for simple identifiers/selectors, resolve the object.
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		if obj, ok := info.Uses[x].(*types.TypeName); ok && obj != nil {
			return obj.Type()
		}
	case *ast.SelectorExpr:
		if x.Sel != nil {
			if obj, ok := info.Uses[x.Sel].(*types.TypeName); ok && obj != nil {
				return obj.Type()
			}
		}
	}
	return nil
}

func findPlan(plans []tpPlan, tpIdx int) *tpPlan {
	for i := range plans {
		if plans[i].tpIdx == tpIdx {
			return &plans[i]
		}
	}
	return nil
}

func ensureImport(file *ast.File, path string) {
	if file == nil || file.Name == nil {
		return
	}
	// Avoid go/astutil.AddImport with a fresh FileSet: the MyGO fork of go/types
	// is sensitive to NoPos/unknown positions and may panic during type-checking.
	// We do a minimal AST-only import insertion and assign stable positions.
	for _, imp := range file.Imports {
		if imp != nil && imp.Path != nil && imp.Path.Value == strconv.Quote(path) {
			return
		}
	}
	pos := posForFile(file)
	spec := &ast.ImportSpec{
		Path: &ast.BasicLit{ValuePos: pos, Kind: token.STRING, Value: strconv.Quote(path)},
	}
	// Try to find an existing import decl.
	for _, d := range file.Decls {
		gd, _ := d.(*ast.GenDecl)
		if gd != nil && gd.Tok == token.IMPORT {
			gd.Specs = append(gd.Specs, spec)
			file.Imports = append(file.Imports, spec)
			return
		}
	}
	// No import decl: create one at the top.
	gd := &ast.GenDecl{
		TokPos: pos,
		Tok:    token.IMPORT,
		Specs:  []ast.Spec{spec},
	}
	file.Decls = append([]ast.Decl{gd}, file.Decls...)
	file.Imports = append(file.Imports, spec)
}

func methodSigString(sig *types.Signature) string {
	if sig == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("(")
	if sig.Params() != nil {
		for i := 0; i < sig.Params().Len(); i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(types.TypeString(sig.Params().At(i).Type(), nil))
		}
	}
	b.WriteString(")->")
	if sig.Results() != nil {
		if sig.Results().Len() == 0 {
			b.WriteString("void")
		} else if sig.Results().Len() == 1 {
			b.WriteString(types.TypeString(sig.Results().At(0).Type(), nil))
		} else {
			b.WriteString("tuple")
		}
	} else {
		b.WriteString("void")
	}
	return b.String()
}

func canSynthesizeMethod(native types.Type, name string, sig *types.Signature) bool {
	if native == nil || name == "" {
		return false
	}
	u := native.Underlying()
	switch u := u.(type) {
	case *types.Basic:
		info := u.Info()
		isNumeric := info&types.IsNumeric != 0
		isString := info&types.IsString != 0
		isInteger := info&types.IsInteger != 0
		switch name {
		case "_add":
			return isNumeric || isString
		case "_sub", "_mul", "_div", "_mod":
			return isNumeric && !isString
		case "_radd":
			return isNumeric || isString
		case "_rsub", "_rmul", "_rdiv", "_rmod":
			return isNumeric && !isString
		case "_and", "_or", "_xor", "_bitclear":
			return isInteger
		case "_rand", "_ror", "_rxor", "_rbitclear":
			return isInteger
		case "_lshift", "_rshift", "_rlshift", "_rrshift":
			return isInteger
		case "_eq", "_ne", "_lt", "_le", "_gt", "_ge":
			return isNumeric || isString
		case "_pos", "_neg":
			return isNumeric && !isString
		case "_invert":
			return isInteger
		default:
			_ = sig
			return false
		}
	case *types.Slice:
		switch name {
		case "_getitem":
			return true
		case "_init":
			return true
		default:
			_ = sig
			return false
		}
	case *types.Map:
		switch name {
		case "_getitem":
			return true
		case "_init":
			return true
		default:
			_ = sig
			return false
		}
	case *types.Chan:
		switch name {
		case "_init":
			return true
		default:
			_ = sig
			return false
		}
	default:
		return false
	}
}

func typeExprForNative(t types.Type) ast.Expr {
	// Build an AST type expression for common types (basic/named/slice/map/chan/pointer).
	if t == nil {
		return &ast.Ident{Name: "any"}
	}
	if b, ok := t.Underlying().(*types.Basic); ok && b != nil {
		switch b.Kind() {
		case types.Int:
			return &ast.Ident{Name: "int"}
		case types.Int8:
			return &ast.Ident{Name: "int8"}
		case types.Int16:
			return &ast.Ident{Name: "int16"}
		case types.Int32:
			return &ast.Ident{Name: "int32"}
		case types.Int64:
			return &ast.Ident{Name: "int64"}
		case types.Uint:
			return &ast.Ident{Name: "uint"}
		case types.Uint8:
			return &ast.Ident{Name: "uint8"}
		case types.Uint16:
			return &ast.Ident{Name: "uint16"}
		case types.Uint32:
			return &ast.Ident{Name: "uint32"}
		case types.Uint64:
			return &ast.Ident{Name: "uint64"}
		case types.Uintptr:
			return &ast.Ident{Name: "uintptr"}
		case types.Float32:
			return &ast.Ident{Name: "float32"}
		case types.Float64:
			return &ast.Ident{Name: "float64"}
		case types.Complex64:
			return &ast.Ident{Name: "complex64"}
		case types.Complex128:
			return &ast.Ident{Name: "complex128"}
		case types.String:
			return &ast.Ident{Name: "string"}
		case types.Bool:
			return &ast.Ident{Name: "bool"}
		}
	}
	// For named types in the current package, use the type's name as ident.
	if n, ok := t.(*types.Named); ok && n != nil && n.Obj() != nil {
		return &ast.Ident{Name: n.Obj().Name()}
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return &ast.StarExpr{X: typeExprForNative(u.Elem())}
	case *types.Slice:
		return &ast.ArrayType{Elt: typeExprForNative(u.Elem())}
	case *types.Array:
		return &ast.ArrayType{
			Len: &ast.BasicLit{Kind: token.INT, Value: strconv.FormatInt(u.Len(), 10)},
			Elt: typeExprForNative(u.Elem()),
		}
	case *types.Map:
		return &ast.MapType{Key: typeExprForNative(u.Key()), Value: typeExprForNative(u.Elem())}
	case *types.Chan:
		dir := ast.ChanDir(ast.SEND | ast.RECV)
		switch u.Dir() {
		case types.SendOnly:
			dir = ast.SEND
		case types.RecvOnly:
			dir = ast.RECV
		}
		return &ast.ChanType{Dir: dir, Value: typeExprForNative(u.Elem())}
	}
	// Fallback: "any" to avoid generating invalid AST.
	return &ast.Ident{Name: "any"}
}

func injectWrapperDecls(file *ast.File, wrapperName string, native types.Type, methods []reqMethod) {
	if file == nil || wrapperName == "" || native == nil {
		return
	}
	pos := posForFile(file)
	// Don't duplicate.
	for _, d := range file.Decls {
		gd, _ := d.(*ast.GenDecl)
		if gd == nil || gd.Tok != token.TYPE {
			continue
		}
		for _, s := range gd.Specs {
			ts, _ := s.(*ast.TypeSpec)
			if ts != nil && ts.Name != nil && ts.Name.Name == wrapperName {
				return
			}
		}
	}

	// type <wrapper> <native>
	typeDecl := &ast.GenDecl{
		TokPos: pos,
		Tok:    token.TYPE,
		Specs: []ast.Spec{
			&ast.TypeSpec{
				Name: &ast.Ident{NamePos: pos, Name: wrapperName},
				Type: typeExprForNative(native),
			},
		},
	}
	file.Decls = append(file.Decls, typeDecl)

	// Generate methods we know how to synthesize and that are required by constraint.
	seen := make(map[string]bool)
	for _, m := range methods {
		if m.name == "" {
			continue
		}
		// Key by (name + signature) so we can satisfy constraints requiring different overloads.
		k := m.name + "|" + methodSigString(m.sig)
		if seen[k] {
			continue
		}
		seen[k] = true
		if !canSynthesizeMethod(native, m.name, m.sig) {
			continue
		}
		if fn := synthMethodDecl(wrapperName, native, m.name, m.sig, pos); fn != nil {
			file.Decls = append(file.Decls, fn)
		}
	}
}

func synthMethodDecl(wrapperName string, native types.Type, name string, reqSig *types.Signature, pos token.Pos) *ast.FuncDecl {
	if wrapperName == "" || native == nil || name == "" {
		return nil
	}
	u := native.Underlying()

	recv := &ast.FieldList{
		List: []*ast.Field{{
			Names: []*ast.Ident{{NamePos: pos, Name: "x"}},
			Type:  &ast.Ident{Name: wrapperName},
		}},
	}
	recvPtr := &ast.FieldList{
		List: []*ast.Field{{
			Names: []*ast.Ident{{NamePos: pos, Name: "x"}},
			Type:  &ast.StarExpr{X: &ast.Ident{Name: wrapperName}},
		}},
	}

	// Helper: cast receiver to native type expr.
	castX := func() ast.Expr {
		return &ast.CallExpr{Fun: typeExprForNative(native), Args: []ast.Expr{&ast.Ident{NamePos: pos, Name: "x"}}}
	}

	switch u := u.(type) {
	case *types.Basic:
		info := u.Info()
		isNumeric := info&types.IsNumeric != 0
		isString := info&types.IsString != 0
		isInteger := info&types.IsInteger != 0

		// Binary method templates: func (x W) _add(y W) W { return x + y }
		bin := func(op token.Token, swap bool) *ast.FuncDecl {
			// y parameter
			paramY := &ast.Field{Names: []*ast.Ident{{NamePos: pos, Name: "y"}}, Type: &ast.Ident{Name: wrapperName}}
			// body: return W( (native(x) op native(y)) )
			xx := castX()
			var yy ast.Expr = &ast.CallExpr{Fun: typeExprForNative(native), Args: []ast.Expr{&ast.Ident{NamePos: pos, Name: "y"}}}
			var left, right ast.Expr = xx, yy
			if swap {
				left, right = yy, xx
			}
			expr := &ast.BinaryExpr{X: left, Op: op, Y: right}
			return &ast.FuncDecl{
				Name: &ast.Ident{NamePos: pos, Name: name},
				Recv: recv,
				Type: &ast.FuncType{
					Params:  &ast.FieldList{List: []*ast.Field{paramY}},
					Results: &ast.FieldList{List: []*ast.Field{{Type: &ast.Ident{Name: wrapperName}}}},
				},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ReturnStmt{Results: []ast.Expr{
						&ast.CallExpr{Fun: &ast.Ident{Name: wrapperName}, Args: []ast.Expr{expr}},
					}},
				}},
			}
		}

		// Compare templates: return bool
		cmp := func(op token.Token) *ast.FuncDecl {
			paramY := &ast.Field{Names: []*ast.Ident{{NamePos: pos, Name: "y"}}, Type: &ast.Ident{Name: wrapperName}}
			xx := castX()
			yy := &ast.CallExpr{Fun: typeExprForNative(native), Args: []ast.Expr{&ast.Ident{NamePos: pos, Name: "y"}}}
			expr := &ast.BinaryExpr{X: xx, Op: op, Y: yy}
			return &ast.FuncDecl{
				Name: &ast.Ident{NamePos: pos, Name: name},
				Recv: recv,
				Type: &ast.FuncType{
					Params:  &ast.FieldList{List: []*ast.Field{paramY}},
					Results: &ast.FieldList{List: []*ast.Field{{Type: &ast.Ident{Name: "bool"}}}},
				},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ReturnStmt{Results: []ast.Expr{expr}},
				}},
			}
		}

		// Unary templates: func (x W) _neg() W { return W(-native(x)) }
		unary := func(op token.Token) *ast.FuncDecl {
			xx := castX()
			expr := &ast.UnaryExpr{Op: op, X: xx}
			return &ast.FuncDecl{
				Name: &ast.Ident{NamePos: pos, Name: name},
				Recv: recv,
				Type: &ast.FuncType{
					Params:  &ast.FieldList{List: nil},
					Results: &ast.FieldList{List: []*ast.Field{{Type: &ast.Ident{Name: wrapperName}}}},
				},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ReturnStmt{Results: []ast.Expr{
						&ast.CallExpr{Fun: &ast.Ident{Name: wrapperName}, Args: []ast.Expr{expr}},
					}},
				}},
			}
		}

		// Shift templates: func (x W) _lshift(y W) W { return W(native(x) << native(y)) }
		shift := func(op token.Token, swap bool) *ast.FuncDecl {
			if !isInteger {
				return nil
			}
			paramY := &ast.Field{Names: []*ast.Ident{{NamePos: pos, Name: "y"}}, Type: &ast.Ident{Name: wrapperName}}
			xx := castX()
			var yy ast.Expr = &ast.CallExpr{Fun: typeExprForNative(native), Args: []ast.Expr{&ast.Ident{NamePos: pos, Name: "y"}}}
			var left, right ast.Expr = xx, yy
			if swap {
				left, right = yy, xx
			}
			expr := &ast.BinaryExpr{X: left, Op: op, Y: right}
			return &ast.FuncDecl{
				Name: &ast.Ident{NamePos: pos, Name: name},
				Recv: recv,
				Type: &ast.FuncType{
					Params:  &ast.FieldList{List: []*ast.Field{paramY}},
					Results: &ast.FieldList{List: []*ast.Field{{Type: &ast.Ident{Name: wrapperName}}}},
				},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ReturnStmt{Results: []ast.Expr{
						&ast.CallExpr{Fun: &ast.Ident{Name: wrapperName}, Args: []ast.Expr{expr}},
					}},
				}},
			}
		}

		switch name {
		case "_add":
			if isNumeric || isString {
				return bin(token.ADD, false)
			}
		case "_sub":
			if isNumeric && !isString {
				return bin(token.SUB, false)
			}
		case "_mul":
			if isNumeric && !isString {
				return bin(token.MUL, false)
			}
		case "_div":
			if isNumeric && !isString {
				return bin(token.QUO, false)
			}
		case "_mod":
			if isNumeric && !isString {
				return bin(token.REM, false)
			}
		case "_radd":
			if isNumeric || isString {
				return bin(token.ADD, true)
			}
		case "_rsub":
			if isNumeric && !isString {
				return bin(token.SUB, true)
			}
		case "_rmul":
			if isNumeric && !isString {
				return bin(token.MUL, true)
			}
		case "_rdiv":
			if isNumeric && !isString {
				return bin(token.QUO, true)
			}
		case "_rmod":
			if isNumeric && !isString {
				return bin(token.REM, true)
			}
		case "_and":
			if isInteger {
				return bin(token.AND, false)
			}
		case "_or":
			if isInteger {
				return bin(token.OR, false)
			}
		case "_xor":
			if isInteger {
				return bin(token.XOR, false)
			}
		case "_bitclear":
			if isInteger {
				return bin(token.AND_NOT, false)
			}
		case "_rand":
			if isInteger {
				return bin(token.AND, true)
			}
		case "_ror":
			if isInteger {
				return bin(token.OR, true)
			}
		case "_rxor":
			if isInteger {
				return bin(token.XOR, true)
			}
		case "_rbitclear":
			if isInteger {
				return bin(token.AND_NOT, true)
			}
		case "_lshift":
			return shift(token.SHL, false)
		case "_rshift":
			return shift(token.SHR, false)
		case "_rlshift":
			return shift(token.SHL, true)
		case "_rrshift":
			return shift(token.SHR, true)
		case "_eq":
			if isNumeric || isString {
				return cmp(token.EQL)
			}
		case "_ne":
			if isNumeric || isString {
				return cmp(token.NEQ)
			}
		case "_lt":
			if isNumeric || isString {
				return cmp(token.LSS)
			}
		case "_le":
			if isNumeric || isString {
				return cmp(token.LEQ)
			}
		case "_gt":
			if isNumeric || isString {
				return cmp(token.GTR)
			}
		case "_ge":
			if isNumeric || isString {
				return cmp(token.GEQ)
			}
		case "_pos":
			if isNumeric && !isString {
				return unary(token.ADD)
			}
		case "_neg":
			if isNumeric && !isString {
				return unary(token.SUB)
			}
		case "_invert":
			if isInteger {
				return unary(token.XOR)
			}
		}
		return nil

	case *types.Slice:
		switch name {
		case "_getitem":
			// Prefer the README rule: _getitem(int) Elem
			// If reqSig disagrees, still generate the canonical form (tooling-only).
			paramI := &ast.Field{Names: []*ast.Ident{{NamePos: pos, Name: "i"}}, Type: &ast.Ident{Name: "int"}}
			resT := typeExprForNative(u.Elem())
			return &ast.FuncDecl{
				Name: &ast.Ident{Name: "_getitem"},
				Recv: recv,
				Type: &ast.FuncType{
					Params:  &ast.FieldList{List: []*ast.Field{paramI}},
					Results: &ast.FieldList{List: []*ast.Field{{Type: resT}}},
				},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ReturnStmt{Results: []ast.Expr{
						&ast.IndexExpr{
							X:     castX(),
							Index: &ast.Ident{Name: "i"},
						},
					}},
				}},
			}
		case "_init":
			// Support both _init() and _init(int) based on required signature.
			nargs := 0
			if reqSig != nil && reqSig.Params() != nil {
				nargs = reqSig.Params().Len()
			}
			if nargs == 0 {
				return &ast.FuncDecl{
					Name: &ast.Ident{Name: "_init"},
					Recv: recv,
					Type: &ast.FuncType{Params: &ast.FieldList{}},
					Body: &ast.BlockStmt{List: nil},
				}
			}
			if nargs == 2 {
				paramN := &ast.Field{Names: []*ast.Ident{{NamePos: pos, Name: "pos"}}, Type: &ast.Ident{Name: "int"}}
				paramC := &ast.Field{Names: []*ast.Ident{{NamePos: pos, Name: "cap"}}, Type: &ast.Ident{Name: "int"}}
				return &ast.FuncDecl{
					Name: &ast.Ident{Name: "_init"},
					Recv: recv,
					Type: &ast.FuncType{
						Params: &ast.FieldList{List: []*ast.Field{paramN, paramC}},
					},
					Body: &ast.BlockStmt{List: nil},
				}
			}
			paramN := &ast.Field{Names: []*ast.Ident{{NamePos: pos, Name: "pos"}}, Type: &ast.Ident{Name: "int"}}
			return &ast.FuncDecl{
				Name: &ast.Ident{Name: "_init"},
				Recv: recv,
				Type: &ast.FuncType{
					Params: &ast.FieldList{List: []*ast.Field{paramN}},
				},
				Body: &ast.BlockStmt{List: nil},
			}
		}
		return nil

	case *types.Map:
		switch name {
		case "_getitem":
			// Canonical: _getitem(Key) Elem
			paramK := &ast.Field{Names: []*ast.Ident{{NamePos: pos, Name: "k"}}, Type: typeExprForNative(u.Key())}
			resT := typeExprForNative(u.Elem())
			return &ast.FuncDecl{
				Name: &ast.Ident{Name: "_getitem"},
				Recv: recv,
				Type: &ast.FuncType{
					Params:  &ast.FieldList{List: []*ast.Field{paramK}},
					Results: &ast.FieldList{List: []*ast.Field{{Type: resT}}},
				},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ReturnStmt{Results: []ast.Expr{
						&ast.IndexExpr{
							X:     castX(),
							Index: &ast.Ident{Name: "k"},
						},
					}},
				}},
			}
		case "_init":
			// Support both _init() and _init(int) based on required signature.
			nargs := 0
			if reqSig != nil && reqSig.Params() != nil {
				nargs = reqSig.Params().Len()
			}
			if nargs == 1 {
				paramN := &ast.Field{Names: []*ast.Ident{{NamePos: pos, Name: "pos"}}, Type: &ast.Ident{Name: "int"}}
				return &ast.FuncDecl{
					Name: &ast.Ident{Name: "_init"},
					Recv: recv,
					Type: &ast.FuncType{Params: &ast.FieldList{List: []*ast.Field{paramN}}},
					Body: &ast.BlockStmt{List: nil},
				}
			}
			return &ast.FuncDecl{
				Name: &ast.Ident{Name: "_init"},
				Recv: recv,
				Type: &ast.FuncType{Params: &ast.FieldList{}},
				Body: &ast.BlockStmt{List: nil},
			}
		}
		return nil

	case *types.Chan:
		switch name {
		case "_init":
			// Support both _init() and _init(int) based on required signature.
			nargs := 0
			if reqSig != nil && reqSig.Params() != nil {
				nargs = reqSig.Params().Len()
			}
			if nargs == 1 {
				paramN := &ast.Field{Names: []*ast.Ident{{NamePos: pos, Name: "pos"}}, Type: &ast.Ident{Name: "int"}}
				return &ast.FuncDecl{
					Name: &ast.Ident{Name: "_init"},
					Recv: recv,
					Type: &ast.FuncType{Params: &ast.FieldList{List: []*ast.Field{paramN}}},
					Body: &ast.BlockStmt{List: nil},
				}
			}
			return &ast.FuncDecl{
				Name: &ast.Ident{Name: "_init"},
				Recv: recv,
				Type: &ast.FuncType{Params: &ast.FieldList{}},
				Body: &ast.BlockStmt{List: nil},
			}
		}
		return nil
	}
	_ = recvPtr
	return nil
}

func posForFile(f *ast.File) token.Pos {
	if f == nil {
		return token.Pos(1)
	}
	if f.Package != token.NoPos {
		return f.Package
	}
	if f.Name != nil && f.Name.NamePos != token.NoPos {
		return f.Name.NamePos
	}
	return token.Pos(1)
}

func rewriteCompoundAssign(file *ast.File) {
	goastutil.Apply(file, func(c *goastutil.Cursor) bool {
		as, ok := c.Node().(*ast.AssignStmt)
		if !ok {
			return true
		}
		// Only handle simple `x OP= y` (single LHS/RHS) and expand to `x = x OP y`.
		if len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		var op token.Token
		switch as.Tok {
		case token.ADD_ASSIGN:
			op = token.ADD
		case token.SUB_ASSIGN:
			op = token.SUB
		case token.MUL_ASSIGN:
			op = token.MUL
		case token.QUO_ASSIGN:
			op = token.QUO
		case token.REM_ASSIGN:
			op = token.REM
		case token.AND_ASSIGN:
			op = token.AND
		case token.OR_ASSIGN:
			op = token.OR
		case token.XOR_ASSIGN:
			op = token.XOR
		case token.SHL_ASSIGN:
			op = token.SHL
		case token.SHR_ASSIGN:
			op = token.SHR
		case token.AND_NOT_ASSIGN:
			op = token.AND_NOT
		default:
			return true
		}
		pos := as.TokPos
		lhs := as.Lhs[0]
		rhs := as.Rhs[0]
		as.Tok = token.ASSIGN
		as.Rhs[0] = &ast.BinaryExpr{X: cloneExpr(lhs), OpPos: pos, Op: op, Y: rhs}
		return true
	}, nil)
}

func rewriteIncDec(file *ast.File, pkg *types.Package, info *types.Info) {
	goastutil.Apply(file, func(c *goastutil.Cursor) bool {
		s, ok := c.Node().(*ast.IncDecStmt)
		if !ok {
			return true
		}
		var mname string
		switch s.Tok {
		case token.INC:
			mname = "_inc"
		case token.DEC:
			mname = "_dec"
		default:
			return true
		}
		recvT := info.TypeOf(s.X)
		if recvT == nil {
			return true
		}
		name, ok := chooseMagicMethodName(recvT, pkg, info, mname, nil)
		if !ok {
			// Keep builtin ++/-- for native numerics etc.
			return true
		}
		call := makeMethodCall(s.X, name, nil)
		c.Replace(&ast.ExprStmt{X: call})
		return false
	}, nil)
}

func rewriteIndexing(file *ast.File, pkg *types.Package, info *types.Info) {
	goastutil.Apply(file, func(c *goastutil.Cursor) bool {
		switch n := c.Node().(type) {
		case *ast.AssignStmt:
			// a[i] = v  ==>  a._setitem(v, i) (if _setitem exists)
			if n.Tok != token.ASSIGN || len(n.Lhs) != 1 || len(n.Rhs) != 1 {
				return true
			}
			switch lhs := n.Lhs[0].(type) {
			case *ast.IndexExpr:
				recvT := info.TypeOf(lhs.X)
				if recvT == nil {
					return true
				}
				args := []ast.Expr{n.Rhs[0], lhs.Index}
				name, ok := chooseMagicMethodName(recvT, pkg, info, "_setitem", args)
				if !ok {
					return true
				}
				call := makeMethodCall(lhs.X, name, args)
				c.Replace(&ast.ExprStmt{X: call})
				return false
			case *ast.SliceExpr:
				recvT := info.TypeOf(lhs.X)
				if recvT == nil {
					return true
				}
				// Encode missing bounds as -1 (consistent with comma-index encoding).
				mk := func(e ast.Expr) ast.Expr {
					if e != nil {
						return e
					}
					return &ast.BasicLit{Kind: token.INT, Value: "-1"}
				}
				args := []ast.Expr{n.Rhs[0], mk(lhs.Low), mk(lhs.High)}
				if lhs.Slice3 {
					args = append(args, mk(lhs.Max))
				}
				name, ok := chooseMagicMethodName(recvT, pkg, info, "_setitem", args)
				if !ok {
					return true
				}
				call := makeMethodCall(lhs.X, name, args)
				c.Replace(&ast.ExprStmt{X: call})
				return false
			default:
				return true
			}

		case *ast.IndexExpr:
			// a[i]  ==>  a._getitem(i) (if _getitem exists)
			recvT := info.TypeOf(n.X)
			if recvT == nil {
				return true
			}
			args := []ast.Expr{n.Index}
			name, ok := chooseMagicMethodName(recvT, pkg, info, "_getitem", args)
			if !ok {
				return true
			}
			call := makeMethodCall(n.X, name, args)
			c.Replace(call)
			return false

		case *ast.SliceExpr:
			// a[i:j] ==> a._getitem(i, j) (if _getitem exists)
			recvT := info.TypeOf(n.X)
			if recvT == nil {
				return true
			}
			mk := func(e ast.Expr) ast.Expr {
				if e != nil {
					return e
				}
				return &ast.BasicLit{Kind: token.INT, Value: "-1"}
			}
			args := []ast.Expr{mk(n.Low), mk(n.High)}
			if n.Slice3 {
				args = append(args, mk(n.Max))
			}
			name, ok := chooseMagicMethodName(recvT, pkg, info, "_getitem", args)
			if !ok {
				return true
			}
			call := makeMethodCall(n.X, name, args)
			c.Replace(call)
			return false
		}
		return true
	}, nil)
}

func rewriteMakeConstructors(file *ast.File, pkg *types.Package, info *types.Info) {
	goastutil.Apply(file, func(c *goastutil.Cursor) bool {
		call, ok := c.Node().(*ast.CallExpr)
		if !ok {
			return true
		}
		id, _ := call.Fun.(*ast.Ident)
		if id == nil || id.Name != "make" || len(call.Args) == 0 {
			return true
		}
		tExpr := call.Args[0]
		tv, ok := info.Types[tExpr]
		if !ok || !tv.IsType() || tv.Type == nil {
			return true
		}
		ut := tv.Type.Underlying()
		switch ut.(type) {
		case *types.Slice, *types.Map, *types.Chan:
			return true // keep builtin make
		}

		// Type parameter form (MyGO extension):
		// make(T, args...) is lowered to an IIFE returning *T and (if available)
		// calling the `_init` method from T's constraint via an interface assertion.
		if tp, ok := tv.Type.(*types.TypeParam); ok && tp != nil {
			iface, _ := tp.Constraint().Underlying().(*types.Interface)
			if iface == nil {
				return true
			}
			args := call.Args[1:]
			var initSig *types.Signature
			for i := 0; i < iface.NumMethods(); i++ {
				m := iface.Method(i)
				if m == nil || m.Name() != "_init" {
					continue
				}
				sig, _ := m.Type().(*types.Signature)
				if sig == nil || sig.Params() == nil {
					continue
				}
				// Match by arity (best-effort; ignore types to avoid dependency on synthesis).
				if sig.Params().Len() == len(args) {
					initSig = sig
					break
				}
			}
			if initSig == nil {
				return true
			}

			pos := call.Lparen
			v := &ast.Ident{NamePos: pos, Name: "_mygo_v"}

			// var _mygo_v T
			decl := &ast.DeclStmt{Decl: &ast.GenDecl{
				TokPos: pos,
				Tok:    token.VAR,
				Specs: []ast.Spec{
					&ast.ValueSpec{
						Names: []*ast.Ident{v},
						Type:  cloneExpr(tExpr),
					},
				},
			}}

			// any(&_mygo_v).(interface{ _init(<params...>) })._init(args...)
			var mparams []*ast.Field
			for pi := 0; pi < initSig.Params().Len(); pi++ {
				pt := initSig.Params().At(pi).Type()
				mparams = append(mparams, &ast.Field{Type: typeExprForNative(pt)})
			}
			ifaceLit := &ast.InterfaceType{
				Methods: &ast.FieldList{List: []*ast.Field{
					{
						Names: []*ast.Ident{{Name: "_init"}},
						Type: &ast.FuncType{
							Params: &ast.FieldList{List: mparams},
						},
					},
				}},
			}
			addr := &ast.UnaryExpr{Op: token.AND, X: v}
			assert := &ast.TypeAssertExpr{
				X:    &ast.CallExpr{Fun: &ast.Ident{Name: "any"}, Args: []ast.Expr{addr}},
				Type: ifaceLit,
			}
			initCall := &ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   assert,
					Sel: &ast.Ident{Name: "_init"},
				},
				Args: args,
			}

			ret := &ast.ReturnStmt{
				Return: pos,
				Results: []ast.Expr{
					&ast.UnaryExpr{Op: token.AND, X: v},
				},
			}

			fn := &ast.FuncLit{
				Type: &ast.FuncType{
					Func:   pos,
					Params: &ast.FieldList{Opening: pos, Closing: pos},
					Results: &ast.FieldList{Opening: pos, List: []*ast.Field{
						{Type: &ast.StarExpr{Star: pos, X: cloneExpr(tExpr)}},
					}, Closing: pos},
				},
				Body: &ast.BlockStmt{
					Lbrace: pos,
					List: []ast.Stmt{
						decl,
						&ast.ExprStmt{X: initCall},
						ret,
					},
					Rbrace: pos,
				},
			}

			c.Replace(&ast.CallExpr{Fun: fn, Lparen: pos, Rparen: pos})
			return false
		}

		// Choose an _init overload on *T if available.
		recvType := types.NewPointer(tv.Type)
		args := call.Args[1:]
		initName, ok := chooseMagicMethodName(recvType, pkg, info, "_init", args)
		if !ok {
			return true
		}

		pos := call.Lparen
		v := &ast.Ident{NamePos: pos, Name: "_mygo_v"}

		newCall := &ast.CallExpr{
			Fun:    &ast.Ident{NamePos: pos, Name: "new"},
			Lparen: pos,
			Args:   []ast.Expr{cloneExpr(tExpr)},
			Rparen: pos,
		}
		assign := &ast.AssignStmt{
			TokPos: pos,
			Tok:    token.DEFINE,
			Lhs:    []ast.Expr{v},
			Rhs:    []ast.Expr{newCall},
		}
		initCall := makeMethodCall(v, initName, args)
		ret := &ast.ReturnStmt{Return: pos, Results: []ast.Expr{v}}

		fn := &ast.FuncLit{
			Type: &ast.FuncType{
				Func:    pos,
				Params:  &ast.FieldList{Opening: pos, Closing: pos},
				Results: &ast.FieldList{Opening: pos, List: []*ast.Field{{Type: &ast.StarExpr{Star: pos, X: cloneExpr(tExpr)}}}, Closing: pos},
			},
			Body: &ast.BlockStmt{
				Lbrace: pos,
				List: []ast.Stmt{
					assign,
					&ast.ExprStmt{X: initCall},
					ret,
				},
				Rbrace: pos,
			},
		}

		c.Replace(&ast.CallExpr{Fun: fn, Lparen: pos, Rparen: pos})
		return false
	}, nil)
}

func rewriteOperators(file *ast.File, pkg *types.Package, info *types.Info) {
	goastutil.Apply(file, func(c *goastutil.Cursor) bool {
		be, ok := c.Node().(*ast.BinaryExpr)
		if !ok {
			return true
		}
		// Only consider operators that MyGO overloads.
		magic, rmagic, mirrorRight := opToMagic(be.Op)
		if magic == "" {
			return true
		}

		x := be.X
		y := be.Y

		xt := info.TypeOf(x)
		yt := info.TypeOf(y)
		if xt == nil || yt == nil {
			return true
		}

		// Forward: x._add(y)
		if name, ok := chooseMagicMethodName(xt, pkg, info, magic, []ast.Expr{y}); ok {
			c.Replace(makeMethodCall(x, name, []ast.Expr{y}))
			return false
		}

		// Reverse/mirror: y._radd(x) or for comparisons y._gt(x) etc.
		tryName := rmagic
		if mirrorRight != "" {
			tryName = mirrorRight
		}
		if tryName != "" {
			if name, ok := chooseMagicMethodName(yt, pkg, info, tryName, []ast.Expr{x}); ok {
				c.Replace(makeMethodCall(y, name, []ast.Expr{x}))
				return false
			}
		}

		return true
	}, nil)

	// Unary ops
	goastutil.Apply(file, func(c *goastutil.Cursor) bool {
		ue, ok := c.Node().(*ast.UnaryExpr)
		if !ok {
			return true
		}
		magic := unaryToMagic(ue.Op)
		if magic == "" {
			return true
		}
		x := ue.X
		xt := info.TypeOf(x)
		if xt == nil {
			return true
		}
		if name, ok := chooseMagicMethodName(xt, pkg, info, magic, nil); ok {
			c.Replace(makeMethodCall(x, name, nil))
			return false
		}
		return true
	}, nil)
}

func rewriteOverloadedMethodCalls(file *ast.File, pkg *types.Package, info *types.Info) {
	goastutil.Apply(file, func(c *goastutil.Cursor) bool {
		call, ok := c.Node().(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			return true
		}
		recvT := info.TypeOf(sel.X)
		if recvT == nil {
			return true
		}
		// If selection already exists, this call type-checks as-is; skip.
		if info.Selections[sel] != nil {
			return true
		}

		base := sel.Sel.Name
		cands := candidateNamesForBase(recvT, pkg, base)
		if len(cands) == 0 {
			return true
		}
		best, ok := chooseBestByTypes(recvT, pkg, info, cands, call.Args)
		if !ok {
			return true
		}
		sel.Sel.Name = best
		return true
	}, nil)
}

func makeMethodCall(recv ast.Expr, method string, args []ast.Expr) *ast.CallExpr {
	pos := recv.Pos()
	return &ast.CallExpr{
		Fun:    &ast.SelectorExpr{X: recv, Sel: &ast.Ident{NamePos: pos, Name: method}},
		Lparen: pos,
		Args:   args,
		Rparen: pos,
	}
}

func cloneExpr(e ast.Expr) ast.Expr {
	if e == nil {
		return nil
	}
	if n := internalastutil.CloneNode(e); n != nil {
		return n
	}
	return e // fallback
}
