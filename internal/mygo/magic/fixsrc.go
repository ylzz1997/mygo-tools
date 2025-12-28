// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magic

import (
	"bytes"
	"unicode"
)

// FixSrc rewrites MyGO comma/slice indexing syntax into parseable Go code.
//
// Motivation:
// - Standard Go syntax doesn't allow "x[i, j]" or "x[i:j, k:l]".
// - gopls runs go/parser, so we must rewrite these forms at the source level.
//
// Rules (from README):
// - If a comma is present inside brackets, we encode each dimension as []int:
//   - point index: i        -> []int{i}
//   - slice index: a:b[:c]  -> []int{aOr-1, bOr-1[, cOr-1]}
// - Reading:  x[i, j]        -> x._getitem([]int{i}, []int{j})
// - Writing:  x[i, j] = v    -> x._setitem(v, []int{i}, []int{j})
//
// Notes:
// - This is best-effort and intentionally conservative about not touching
//   obvious generic instantiations like f[T](...) / T[A]{...} (lookahead "(" / "{").
func FixSrc(filename string, src []byte) ([]byte, bool) {
	_ = filename // reserved for future //line mapping if needed
	if len(src) == 0 {
		return nil, false
	}

	var out bytes.Buffer
	changed := false

	isEscapedIn := func(b []byte, i int) bool {
		// returns whether b[i] is escaped by a preceding backslash in a regular string/rune
		if i <= 0 {
			return false
		}
		n := 0
		for j := i - 1; j >= 0 && b[j] == '\\'; j-- {
			n++
		}
		return n%2 == 1
	}

	isASCIIIdent := func(b []byte) bool {
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			return false
		}
		isLetter := func(c byte) bool {
			return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
		}
		isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
		if !isLetter(b[0]) {
			return false
		}
		for i := 1; i < len(b); i++ {
			if isLetter(b[i]) || isDigit(b[i]) {
				continue
			}
			return false
		}
		return true
	}

	isPredeclaredTypeIdent := func(b []byte) bool {
		b = bytes.TrimSpace(b)
		if !isASCIIIdent(b) {
			return false
		}
		switch string(b) {
		case "any", "comparable", "error",
			"bool", "byte", "complex64", "complex128",
			"float32", "float64",
			"int", "int8", "int16", "int32", "int64",
			"rune",
			"string",
			"uint", "uint8", "uint16", "uint32", "uint64", "uintptr":
			return true
		default:
			return false
		}
	}

	lastIdentStartsUpper := func(b []byte) bool {
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			return false
		}
		if i := bytes.LastIndexByte(b, '.'); i >= 0 {
			b = b[i+1:]
		}
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			return false
		}
		c := b[0]
		return c >= 'A' && c <= 'Z'
	}

	looksDefinitelyTypeArg := func(b []byte) bool {
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			return false
		}
		// Composite/keyword types can't be value expressions without a type context.
		switch {
		case bytes.HasPrefix(b, []byte("*")),
			bytes.HasPrefix(b, []byte("[]")),
			bytes.HasPrefix(b, []byte("map[")),
			bytes.HasPrefix(b, []byte("<-chan")),
			bytes.HasPrefix(b, []byte("chan ")),
			bytes.HasPrefix(b, []byte("chan<-")),
			bytes.HasPrefix(b, []byte("func(")),
			bytes.HasPrefix(b, []byte("struct{")),
			bytes.HasPrefix(b, []byte("interface{")),
			bytes.HasPrefix(b, []byte("[")): // array type like [N]T
			return true
		}
		if isPredeclaredTypeIdent(b) {
			return true
		}
		// Heuristic: pkg.ExportedType is likely a type argument.
		if bytes.Contains(b, []byte(".")) && lastIdentStartsUpper(b) {
			return true
		}
		return false
	}

	receiverLooksIdentOrSelector := func(prefix []byte, end int) bool {
		// end is an index into prefix (exclusive).
		j := end - 1
		for j >= 0 {
			if prefix[j] == '\n' || prefix[j] == '\r' {
				break
			}
			if prefix[j] == ' ' || prefix[j] == '\t' {
				j--
				continue
			}
			break
		}
		if j < 0 {
			return false
		}
		k := j
		for k >= 0 {
			c := prefix[k]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' {
				k--
				continue
			}
			break
		}
		recv := bytes.TrimSpace(prefix[k+1 : j+1])
		if isASCIIIdent(recv) {
			return true
		}
		if bytes.Contains(recv, []byte(".")) {
			parts := bytes.Split(recv, []byte("."))
			if len(parts) >= 2 {
				for _, p := range parts {
					if !isASCIIIdent(p) {
						return false
					}
				}
				return true
			}
		}
		return false
	}

	// Detect top-level ':' within a segment (ignoring ternary '? :').
	hasTopLevelColon := func(seg []byte) bool {
		trim := bytes.TrimSpace(seg)
		var (
			par, brk, brc int
			lc, bc, raw, str, rn bool
		)
		for i := 0; i < len(trim); i++ {
			ch := trim[i]
			if lc {
				if ch == '\n' {
					lc = false
				}
				continue
			}
			if bc {
				if ch == '*' && i+1 < len(trim) && trim[i+1] == '/' {
					bc = false
					i++
				}
				continue
			}
			if raw {
				if ch == '`' {
					raw = false
				}
				continue
			}
			if str {
				if ch == '"' && !isEscapedIn(trim, i) {
					str = false
				}
				continue
			}
			if rn {
				if ch == '\'' && !isEscapedIn(trim, i) {
					rn = false
				}
				continue
			}
			if ch == '/' && i+1 < len(trim) {
				if trim[i+1] == '/' {
					lc = true
					i++
					continue
				}
				if trim[i+1] == '*' {
					bc = true
					i++
					continue
				}
			}
			switch ch {
			case '`':
				raw = true
			case '"':
				str = true
			case '\'':
				rn = true
			case '(':
				par++
			case ')':
				if par > 0 {
					par--
				}
			case '[':
				brk++
			case ']':
				if brk > 0 {
					brk--
				}
			case '{':
				brc++
			case '}':
				if brc > 0 {
					brc--
				}
			case ':':
				if par == 0 && brk == 0 && brc == 0 {
					// ignore ternary ":" (x ? y : z)
					j := i - 1
					for j >= 0 && unicode.IsSpace(rune(trim[j])) {
						j--
					}
					if j >= 0 && trim[j] == '?' {
						continue
					}
					return true
				}
			}
		}
		return false
	}

	// scan state
	inLineComment := false
	inBlockComment := false
	inRaw := false   // `
	inString := false // "
	inRune := false  // '

	emitUntil := 0

	// Find matching closing bracket for src[open]=='['.
	findMatchingBracket := func(open int) int {
		depth := 0
		// local state while scanning inside [...]
		lc := false
		bc := false
		raw := false
		str := false
		rn := false
		for i := open; i < len(src); i++ {
			ch := src[i]
			if lc {
				if ch == '\n' {
					lc = false
				}
				continue
			}
			if bc {
				if ch == '*' && i+1 < len(src) && src[i+1] == '/' {
					bc = false
					i++
				}
				continue
			}
			if raw {
				if ch == '`' {
					raw = false
				}
				continue
			}
			if str {
				if ch == '"' && !isEscapedIn(src, i) {
					str = false
				}
				continue
			}
			if rn {
				if ch == '\'' && !isEscapedIn(src, i) {
					rn = false
				}
				continue
			}

			if ch == '/' && i+1 < len(src) {
				if src[i+1] == '/' {
					lc = true
					i++
					continue
				}
				if src[i+1] == '*' {
					bc = true
					i++
					continue
				}
			}
			switch ch {
			case '`':
				raw = true
			case '"':
				str = true
			case '\'':
				rn = true
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					return i
				}
			}
		}
		return -1
	}

	// Split a bracket content by top-level commas, respecting nesting.
	splitTopLevelCommas := func(b []byte) (parts [][]byte, hasComma bool) {
		var (
			par, brk, brc int
			start         int
			// local string/comment state
			lc, bc, raw, str, rn bool
		)
		for i := 0; i < len(b); i++ {
			ch := b[i]
			if lc {
				if ch == '\n' {
					lc = false
				}
				continue
			}
			if bc {
				if ch == '*' && i+1 < len(b) && b[i+1] == '/' {
					bc = false
					i++
				}
				continue
			}
			if raw {
				if ch == '`' {
					raw = false
				}
				continue
			}
			if str {
				if ch == '"' && !isEscapedIn(b, i) {
					str = false
				}
				continue
			}
			if rn {
				if ch == '\'' && !isEscapedIn(b, i) {
					rn = false
				}
				continue
			}

			if ch == '/' && i+1 < len(b) {
				if b[i+1] == '/' {
					lc = true
					i++
					continue
				}
				if b[i+1] == '*' {
					bc = true
					i++
					continue
				}
			}

			switch ch {
			case '`':
				raw = true
			case '"':
				str = true
			case '\'':
				rn = true
			case '(':
				par++
			case ')':
				if par > 0 {
					par--
				}
			case '[':
				brk++
			case ']':
				if brk > 0 {
					brk--
				}
			case '{':
				brc++
			case '}':
				if brc > 0 {
					brc--
				}
			case ',':
				if par == 0 && brk == 0 && brc == 0 {
					hasComma = true
					parts = append(parts, b[start:i])
					start = i + 1
				}
			}
		}
		parts = append(parts, b[start:])
		return parts, hasComma
	}

	// Parse one segment into []int{...} literal.
	encodeSegment := func(seg []byte) []byte {
		trim := bytes.TrimSpace(seg)
		// Find slice colons at top-level, but ignore ternary ":" (preceded by "?").
		var (
			par, brk, brc int
			colonIdx      []int
			lc, bc, raw, str, rn bool
		)
		for i := 0; i < len(trim); i++ {
			ch := trim[i]
			if lc {
				if ch == '\n' {
					lc = false
				}
				continue
			}
			if bc {
				if ch == '*' && i+1 < len(trim) && trim[i+1] == '/' {
					bc = false
					i++
				}
				continue
			}
			if raw {
				if ch == '`' {
					raw = false
				}
				continue
			}
			if str {
				if ch == '"' && !isEscapedIn(trim, i) {
					str = false
				}
				continue
			}
			if rn {
				if ch == '\'' && !isEscapedIn(trim, i) {
					rn = false
				}
				continue
			}
			if ch == '/' && i+1 < len(trim) {
				if trim[i+1] == '/' {
					lc = true
					i++
					continue
				}
				if trim[i+1] == '*' {
					bc = true
					i++
					continue
				}
			}
			switch ch {
			case '`':
				raw = true
			case '"':
				str = true
			case '\'':
				rn = true
			case '(':
				par++
			case ')':
				if par > 0 {
					par--
				}
			case '[':
				brk++
			case ']':
				if brk > 0 {
					brk--
				}
			case '{':
				brc++
			case '}':
				if brc > 0 {
					brc--
				}
			case ':':
				if par == 0 && brk == 0 && brc == 0 {
					// ignore ternary ":" (x ? y : z)
					j := i - 1
					for j >= 0 && unicode.IsSpace(rune(trim[j])) {
						j--
					}
					if j >= 0 && trim[j] == '?' {
						continue
					}
					colonIdx = append(colonIdx, i)
				}
			}
		}

		// helper: slice part with sentinel for missing
		part := func(b []byte) []byte {
			b = bytes.TrimSpace(b)
			if len(b) == 0 {
				return []byte("-1")
			}
			return b
		}

		var elems [][]byte
		if len(colonIdx) == 0 {
			if len(trim) == 0 {
				elems = [][]byte{[]byte("-1")}
			} else {
				elems = [][]byte{trim}
			}
		} else {
			// a:b[:c]
			var cuts []int
			cuts = append(cuts, -1)
			cuts = append(cuts, colonIdx...)
			cuts = append(cuts, len(trim))
			for i := 0; i < len(cuts)-1; i++ {
				lo := cuts[i] + 1
				hi := cuts[i+1]
				elems = append(elems, part(trim[lo:hi]))
			}
			// Ensure 2- or 3-part only; if more, treat as point index fallback.
			if len(elems) < 2 || len(elems) > 3 {
				elems = [][]byte{trim}
			}
		}

		var buf bytes.Buffer
		buf.WriteString("[]int{")
		for i, e := range elems {
			if i > 0 {
				buf.WriteString(", ")
			}
			buf.Write(e)
		}
		buf.WriteByte('}')
		return buf.Bytes()
	}

	i := 0
	for i < len(src) {
		ch := src[i]
		if inLineComment {
			if ch == '\n' {
				inLineComment = false
			}
			i++
			continue
		}
		if inBlockComment {
			if ch == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlockComment = false
				i += 2
				continue
			}
			i++
			continue
		}
		if inRaw {
			if ch == '`' {
				inRaw = false
			}
			i++
			continue
		}
		if inString {
			if ch == '"' && !isEscapedIn(src, i) {
				inString = false
			}
			i++
			continue
		}
		if inRune {
			if ch == '\'' && !isEscapedIn(src, i) {
				inRune = false
			}
			i++
			continue
		}

		if ch == '/' && i+1 < len(src) {
			if src[i+1] == '/' {
				inLineComment = true
				i += 2
				continue
			}
			if src[i+1] == '*' {
				inBlockComment = true
				i += 2
				continue
			}
		}
		switch ch {
		case '`':
			inRaw = true
			i++
			continue
		case '"':
			inString = true
			i++
			continue
		case '\'':
			inRune = true
			i++
			continue
		}

		if ch != '[' {
			i++
			continue
		}

		open := i
		close := findMatchingBracket(open)
		if close < 0 {
			i++
			continue
		}
		inner := src[open+1 : close]

		// split by commas; only rewrite if a top-level comma exists.
		parts, hasComma := splitTopLevelCommas(inner)
		if !hasComma {
			i = close + 1
			continue
		}

		// trim trailing spaces before '[' (avoid "x [i,j]" -> "x ._getitem")
		trimOpen := open
		for trimOpen > emitUntil {
			b := src[trimOpen-1]
			if b == '\n' || b == '\r' {
				break
			}
			if b == ' ' || b == '\t' {
				trimOpen--
				continue
			}
			break
		}

		// Ambiguity reduction: don't rewrite very-likely generic instantiations like f[int, string]
		// (which are valid Go and should remain intact).
		// We only skip when:
		// - no segment has top-level ':' (since ':' implies slice indexing)
		// - receiver looks like ident/selector
		// - every segment looks definitely like a type argument (strict heuristic)
		noColon := true
		for _, p := range parts {
			if hasTopLevelColon(p) {
				noColon = false
				break
			}
		}
		if noColon && receiverLooksIdentOrSelector(src, trimOpen) {
			allTypey := true
			for _, p := range parts {
				if !looksDefinitelyTypeArg(p) {
					allTypey = false
					break
				}
			}
			if allTypey {
				i = close + 1
				continue
			}
		}

		// Heuristic: don't rewrite obvious generic instantiation forms like f[T](...) or T[A]{...}.
		k := close + 1
		for k < len(src) && (src[k] == ' ' || src[k] == '\t' || src[k] == '\r') {
			k++
		}
		if k < len(src) && (src[k] == '(' || src[k] == '{') {
			i = close + 1
			continue
		}

		// Build encoded args: each part becomes []int{...}.
		var args bytes.Buffer
		for pi, p := range parts {
			if pi > 0 {
				args.WriteString(", ")
			}
			args.Write(encodeSegment(p))
		}

		// Determine whether this is a simple assignment: x[i,j] = rhs
		kk := close + 1
		for kk < len(src) && unicode.IsSpace(rune(src[kk])) && src[kk] != '\n' {
			kk++
		}
		isAssign := kk < len(src) && src[kk] == '=' && !(kk+1 < len(src) && src[kk+1] == '=')

		// Emit text up to the expression receiver.
		out.Write(src[emitUntil:trimOpen])

		if !isAssign {
			out.WriteString("._getitem(")
			out.Write(args.Bytes())
			out.WriteByte(')')
			emitUntil = close + 1
			changed = true
			i = close + 1
			continue
		}

		// Assignment form: rewrite `x[i,j] = rhs` -> `x._setitem(rhs, args...)`
		// Capture rhs until statement end (newline or ';') at top-level.
		rhsStart := kk + 1
		for rhsStart < len(src) && (src[rhsStart] == ' ' || src[rhsStart] == '\t') {
			rhsStart++
		}

		var (
			par, brk, brc int
			lc2, bc2, raw2, str2, rn2 bool
		)
		end := rhsStart
		for end < len(src) {
			cch := src[end]
			if lc2 {
				if cch == '\n' {
					lc2 = false
					// newline ends statement at top-level
					if par == 0 && brk == 0 && brc == 0 {
						break
					}
				}
				end++
				continue
			}
			if bc2 {
				if cch == '*' && end+1 < len(src) && src[end+1] == '/' {
					bc2 = false
					end += 2
					continue
				}
				end++
				continue
			}
			if raw2 {
				if cch == '`' {
					raw2 = false
				}
				end++
				continue
			}
			if str2 {
				if cch == '"' && !isEscapedIn(src, end) {
					str2 = false
				}
				end++
				continue
			}
			if rn2 {
				if cch == '\'' && !isEscapedIn(src, end) {
					rn2 = false
				}
				end++
				continue
			}
			if cch == '/' && end+1 < len(src) {
				if src[end+1] == '/' {
					lc2 = true
					end += 2
					continue
				}
				if src[end+1] == '*' {
					bc2 = true
					end += 2
					continue
				}
			}
			switch cch {
			case '`':
				raw2 = true
			case '"':
				str2 = true
			case '\'':
				rn2 = true
			case '(':
				par++
			case ')':
				if par > 0 {
					par--
				}
			case '[':
				brk++
			case ']':
				if brk > 0 {
					brk--
				}
			case '{':
				brc++
			case '}':
				if brc > 0 {
					brc--
				}
			case ';':
				if par == 0 && brk == 0 && brc == 0 {
					// semicolon ends statement
					break
				}
			case '\n':
				if par == 0 && brk == 0 && brc == 0 {
					break
				}
			}
			// stop conditions (break out of for) need a label
			if (cch == ';' || cch == '\n') && par == 0 && brk == 0 && brc == 0 {
				break
			}
			end++
		}

		rhs := bytes.TrimSpace(src[rhsStart:end])
		out.WriteString("._setitem(")
		out.Write(rhs)
		if len(rhs) > 0 {
			out.WriteString(", ")
		}
		out.Write(args.Bytes())
		out.WriteByte(')')

		emitUntil = end
		changed = true
		i = end
	}

	if !changed {
		return nil, false
	}
	out.Write(src[emitUntil:])
	return out.Bytes(), true
}


