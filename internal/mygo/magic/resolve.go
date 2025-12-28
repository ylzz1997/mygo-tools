// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magic

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

func opToMagic(op token.Token) (magic string, reverse string, mirrorRight string) {
	switch op {
	// arithmetic
	case token.ADD:
		return "_add", "_radd", ""
	case token.SUB:
		return "_sub", "_rsub", ""
	case token.MUL:
		return "_mul", "_rmul", ""
	case token.QUO:
		return "_div", "_rdiv", ""
	case token.REM:
		return "_mod", "_rmod", ""

	// compare: mirror fallback on RHS
	case token.EQL:
		return "_eq", "", "_eq"
	case token.NEQ:
		return "_ne", "", "_ne"
	case token.GTR:
		return "_gt", "", "_lt"
	case token.GEQ:
		return "_ge", "", "_le"
	case token.LSS:
		return "_lt", "", "_gt"
	case token.LEQ:
		return "_le", "", "_ge"

	// bitwise
	case token.OR:
		return "_or", "_ror", ""
	case token.AND:
		return "_and", "_rand", ""
	case token.XOR:
		return "_xor", "_rxor", ""
	case token.SHL:
		return "_lshift", "_rlshift", ""
	case token.SHR:
		return "_rshift", "_rrshift", ""
	case token.AND_NOT:
		return "_bitclear", "_rbitclear", ""
	}
	return "", "", ""
}

func unaryToMagic(op token.Token) string {
	switch op {
	case token.ADD:
		return "_pos"
	case token.SUB:
		return "_neg"
	case token.XOR:
		return "_invert"
	}
	return ""
}

func chooseMagicMethodName(recvT types.Type, pkg *types.Package, info *types.Info, base string, args []ast.Expr) (string, bool) {
	if recvT == nil || pkg == nil || info == nil || base == "" {
		return "", false
	}
	cands := candidateNamesForMagic(recvT, pkg, base)
	if len(cands) == 0 {
		return "", false
	}
	best, ok := chooseBestByTypes(recvT, pkg, info, cands, args)
	return best, ok
}

func candidateNamesForMagic(recvT types.Type, pkg *types.Package, base string) []string {
	ms := collectMethodNames(recvT, pkg)
	var out []string
	// Prefer exact base if present.
	for _, n := range ms {
		if n == base {
			out = append(out, n)
		}
	}
	pfx := base + "_"
	for _, n := range ms {
		if strings.HasPrefix(n, pfx) {
			out = append(out, n)
		}
	}
	return uniqStrings(out)
}

func candidateNamesForBase(recvT types.Type, pkg *types.Package, base string) []string {
	if recvT == nil || pkg == nil || base == "" {
		return nil
	}
	ms := collectMethodNames(recvT, pkg)
	var out []string

	// If the base method exists, don't treat it as overloaded.
	for _, n := range ms {
		if n == base {
			return nil
		}
	}

	var pfx string
	if strings.HasPrefix(base, "_") && isSingleUnderscoreMagic(base) {
		pfx = base + "_"
	} else {
		pfx = "_" + base + "_"
	}
	for _, n := range ms {
		if strings.HasPrefix(n, pfx) {
			out = append(out, n)
		}
	}
	return uniqStrings(out)
}

func collectMethodNames(recvT types.Type, pkg *types.Package) []string {
	m := make([]string, 0, 8)
	add := func(t types.Type) {
		ms := types.NewMethodSet(t)
		for i := 0; i < ms.Len(); i++ {
			sel := ms.At(i)
			if sel == nil || sel.Obj() == nil {
				continue
			}
			if sel.Obj().Pkg() != nil && pkg != nil && sel.Obj().Pkg().Path() != pkg.Path() {
				// Still include methods from embedded types in other pkgs; tooling rewrite
				// is best-effort and should be conservative. We'll include them anyway.
			}
			m = append(m, sel.Obj().Name())
		}
	}
	add(recvT)
	if _, ok := recvT.(*types.Pointer); !ok {
		add(types.NewPointer(recvT))
	}
	return uniqStrings(m)
}

func chooseBestByTypes(recvT types.Type, pkg *types.Package, info *types.Info, methodNames []string, args []ast.Expr) (string, bool) {
	type cand struct {
		name      string
		score     int
		variadic  bool
		ok        bool
	}
	argTypes := make([]types.Type, len(args))
	for i, a := range args {
		argTypes[i] = info.TypeOf(a)
	}

	var cands []cand
	for _, name := range methodNames {
		fn := lookupMethod(recvT, pkg, name)
		if fn == nil {
			continue
		}
		sig, _ := fn.Type().(*types.Signature)
		if sig == nil {
			continue
		}
		s, v, ok := scoreCall(sig, argTypes)
		if !ok {
			continue
		}
		cands = append(cands, cand{name: name, score: s, variadic: v, ok: true})
	}
	if len(cands) == 0 {
		return "", false
	}
	sort.SliceStable(cands, func(i, j int) bool {
		// Lower score is better; non-variadic preferred on tie.
		if cands[i].score != cands[j].score {
			return cands[i].score < cands[j].score
		}
		if cands[i].variadic != cands[j].variadic {
			return !cands[i].variadic
		}
		return cands[i].name < cands[j].name
	})
	return cands[0].name, true
}

func lookupMethod(recvT types.Type, pkg *types.Package, name string) *types.Func {
	if recvT == nil || name == "" {
		return nil
	}
	// 1) method set of recvT
	if ms := types.NewMethodSet(recvT); ms != nil {
		if sel := ms.Lookup(pkg, name); sel != nil {
			if fn, _ := sel.Obj().(*types.Func); fn != nil {
				return fn
			}
		}
	}
	// 2) method set of *recvT (for implicit addressable method calls)
	if _, ok := recvT.(*types.Pointer); !ok {
		ptr := types.NewPointer(recvT)
		if ms := types.NewMethodSet(ptr); ms != nil {
			if sel := ms.Lookup(pkg, name); sel != nil {
				if fn, _ := sel.Obj().(*types.Func); fn != nil {
					return fn
				}
			}
		}
	}
	return nil
}

func scoreCall(sig *types.Signature, args []types.Type) (score int, variadic bool, ok bool) {
	if sig == nil {
		return 0, false, false
	}
	params := sig.Params()
	n := params.Len()
	if sig.Variadic() {
		variadic = true
		if len(args) < n-1 {
			return 0, variadic, false
		}
		// fixed part
		for i := 0; i < n-1; i++ {
			s, ok := scoreArg(args[i], params.At(i).Type())
			if !ok {
				return 0, variadic, false
			}
			score += s
		}
		// variadic part uses elem type
		last := params.At(n - 1).Type()
		slice, _ := last.(*types.Slice)
		if slice == nil {
			return 0, variadic, false
		}
		elt := slice.Elem()
		for i := n - 1; i < len(args); i++ {
			s, ok := scoreArg(args[i], elt)
			if !ok {
				return 0, variadic, false
			}
			// penalize variadic slightly to prefer fixed-arity overloads.
			score += s + 1
		}
		return score, variadic, true
	}
	if len(args) != n {
		return 0, false, false
	}
	for i := 0; i < n; i++ {
		s, ok := scoreArg(args[i], params.At(i).Type())
		if !ok {
			return 0, false, false
		}
		score += s
	}
	return score, false, true
}

func scoreArg(arg, param types.Type) (int, bool) {
	// Be permissive for tooling: if arg type is unknown (often due to earlier
	// type errors such as invalid make(T,...)), treat it as a wildcard so that
	// we can still pick a reasonable overload and proceed with rewriting.
	if param == nil {
		return 100, false
	}
	if arg == nil {
		return 10, true
	}
	if types.Identical(arg, param) {
		return 0, true
	}
	if types.AssignableTo(arg, param) {
		return 1, true
	}
	if types.ConvertibleTo(arg, param) {
		return 2, true
	}
	return 0, false
}

func uniqStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}


