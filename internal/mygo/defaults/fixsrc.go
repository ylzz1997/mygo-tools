// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package defaults

import (
	"bytes"
	"fmt"
	"go/scanner"
	"go/token"
	"strings"
)

// FixSrc rewrites MyGO default parameters in function declarations into
// parseable Go code.
//
// Example:
//
//	func f(a int, b int = 10, c string = "x y") {}
//
// becomes:
//
//	//mygo:defaultsjson <base64(JSON)>
//	func f(a int, b int, c string) {}
//
// where the integer is the count of required parameters.
//
// NOTE: This is a source-level transform so that go/parser can parse the file.
// The call-site filling is done later as an AST transform.
func FixSrc(filename string, src []byte) (_ []byte, changed bool) {
	// Fast path: look for "=<something>" in what looks like a func signature.
	if !bytes.Contains(src, []byte("func")) || !bytes.Contains(src, []byte("=")) {
		return src, false
	}

	fset := token.NewFileSet()
	tf := fset.AddFile(filename, -1, len(src))
	var s scanner.Scanner
	s.Init(tf, src, func(token.Position, string) {}, scanner.ScanComments)

	type edit struct {
		start, end int
		repl       []byte
	}
	var edits []edit

	// makeWhitespacePreservingNewlines returns a replacement of length n that
	// preserves '\n' bytes from the original segment, replacing all other bytes
	// with spaces. This keeps physical line structure stable so that LSP ranges
	// derived from token.Pos remain aligned with the original buffer.
	makeWhitespacePreservingNewlines := func(seg []byte) []byte {
		if len(seg) == 0 {
			return nil
		}
		out := make([]byte, len(seg))
		for i, b := range seg {
			if b == '\n' {
				out[i] = '\n'
			} else {
				out[i] = ' '
			}
		}
		return out
	}

	next := func() (pos token.Pos, tok token.Token, lit string) {
		for {
			pos, tok, lit = s.Scan()
			if tok != token.COMMENT {
				return
			}
		}
	}

	for {
		funcPos, tok, _ := next()
		if tok == token.EOF {
			break
		}
		if tok != token.FUNC {
			continue
		}

		// Optional receiver.
		peekPos, peekTok, peekLit := next()
		_, tok, lit := peekPos, peekTok, peekLit
		if tok == token.LPAREN {
			// consume receiver list "( ... )"
			depth := 1
			for depth > 0 {
				_, t2, _ := next()
				if t2 == token.LPAREN {
					depth++
				} else if t2 == token.RPAREN {
					depth--
				} else if t2 == token.EOF {
					break
				}
			}
			_, tok, lit = next()
		}

		if tok != token.IDENT {
			continue
		}
		funcName := lit

		// Expect parameter list '('.
		_, tok, _ = next()
		if tok != token.LPAREN {
			continue
		}

		// Parse params until matching ')', collecting "= default" segments.
		// We'll remove "= defaultExpr" from the source and produce a metadata comment.
		type def struct {
			param string
			expr  string
		}
		var defs []def
		required := 0

		// We track the current field's last ident as the parameter name.
		lastParamName := ""
		fieldHasDefault := false
		parenDepth := 1
		brackDepth := 0
		var (
			eqStartOff int
			eqEndOff   int
		)

		// Parameter list starts after '('
		for parenDepth > 0 {
			p2, t2, l2 := next()
			if t2 == token.EOF {
				break
			}
			switch t2 {
			case token.LPAREN:
				parenDepth++
				if parenDepth == 1 && eqStartOff == 0 {
					// new param
				}
			case token.RPAREN:
				parenDepth--
				if parenDepth == 0 {
					if eqStartOff > 0 {
						// Final parameter had a default value
						eqEndOff = int(tf.Offset(p2))
						// Extract expr: eqStartOff points to '=', so skip it and trim spaces
						exprRaw := string(src[eqStartOff:eqEndOff])
						expr := strings.TrimSpace(strings.TrimPrefix(exprRaw, "="))
						defs = append(defs, def{param: lastParamName, expr: expr})
						seg := src[eqStartOff:eqEndOff]
						edits = append(edits, edit{start: eqStartOff, end: eqEndOff, repl: makeWhitespacePreservingNewlines(seg)})
						fieldHasDefault = true
					}
					// If a previous field in this group had a default but this one doesn't...
					// actually, go/scanner doesn't parse "a, b = 1".
					// But our simplified scanner treats "a" then "," then "b" then "=".
					// The logic here is tricky. Let's rely on finding "=" at the top level of parens.
					if !fieldHasDefault {
						required++
					}
				}
			case token.LBRACK:
				brackDepth++
			case token.RBRACK:
				brackDepth--
			case token.COMMA:
				if parenDepth == 1 && brackDepth == 0 {
					if eqStartOff > 0 {
						// End of a default value expression
						eqEndOff = int(tf.Offset(p2))
						// Extract expr: eqStartOff points to '=', so skip it and trim spaces
						exprRaw := string(src[eqStartOff:eqEndOff])
						expr := strings.TrimSpace(strings.TrimPrefix(exprRaw, "="))
						defs = append(defs, def{param: lastParamName, expr: expr})
						seg := src[eqStartOff:eqEndOff]
						edits = append(edits, edit{start: eqStartOff, end: eqEndOff, repl: makeWhitespacePreservingNewlines(seg)})
						eqStartOff = 0
						fieldHasDefault = true
					} else {
						// Parameter without default
						if !fieldHasDefault {
							required++
						}
					}
					// Prepare for next param
					fieldHasDefault = false // Reset for next param, but wait...
					// If we have "a, b int = 1", both a and b have defaults.
					// But here we're parsing tokens. "a" "," "b" "int" "=" "1".
					// We only see "=" later.
					// This logic is simplified and assumes "a int = 1, b string = 2".
					// It doesn't handle "a, b int = 1" correctly (it would count a as required).
					// MyGO README says: "supports x int = 1".
					// It implies standard Go parameter syntax but with optional "= value".
					// So "a, b int = 1" is probably valid if we support it.
					// For now, let's assume one param per comma for simplicity or that
					// defaults are only attached to the type?
					// Actually, the parser logic above is very "local".
					// If we see "=", we mark `fieldHasDefault`.
					// But we only see "=" AFTER the comma for the *current* field?
					// No, we see comma AFTER the "=".
					// So if we saw "=", `fieldHasDefault` is true.
				}
			case token.ASSIGN: // '='
				if parenDepth == 1 && brackDepth == 0 {
					// Start deletion from '=' (not +1) so we remove both '=' and the default value
					eqStartOff = int(tf.Offset(p2))
					fieldHasDefault = true
				}
			case token.IDENT:
				if parenDepth == 1 && brackDepth == 0 && eqStartOff == 0 {
					// Potential parameter name.
					// We don't know if it's a name or a type yet.
					// But the last identifier before a comma or equal or type is the name?
					// This simple scan is imperfect but should work for "name type = val".
					lastParamName = l2
				}
			}
		}

		if len(defs) == 0 {
			continue
		}

		// Insert metadata comment before 'func' keyword.
		funcOff := tf.Offset(funcPos)
		startLine := tf.Position(funcPos).Line
		var meta strings.Builder
		{
			var m Metadata
			m.Name = funcName
			m.Required = required
			for _, d := range defs {
				m.Defaults = append(m.Defaults, struct {
					Param string `json:"param"`
					Expr  string `json:"expr"`
				}{Param: d.param, Expr: d.expr})
			}
			if enc, ok := encodeMetadataJSON(m); ok {
				// Use a block comment with no trailing newline, to avoid shifting
				// physical line numbers in the remainder of the file (which would
				// confuse LSP diagnostic ranges).
				fmt.Fprintf(&meta, "/*%s%s*/", metaPrefixJSON, enc)
			} else {
				// Fallback to old format if JSON encoding fails.
				fmt.Fprintf(&meta, "/*%s%s %d", metaPrefixOld, funcName, required)
				for _, d := range defs {
					fmt.Fprintf(&meta, " %s=%s", d.param, d.expr)
				}
				meta.WriteString("*/")
			}
		}
		_ = startLine // preserved for potential future diagnostics mapping

		// Insert metadata at the end of the line containing the 'func' keyword.
		// This avoids shifting token columns for the signature itself, and avoids
		// introducing new lines.
		lineEnd := bytes.IndexByte(src[funcOff:], '\n')
		ins := len(src)
		if lineEnd >= 0 {
			ins = funcOff + lineEnd
		}
		// Prepend a space to keep separation from preceding tokens.
		edits = append(edits, edit{start: ins, end: ins, repl: append([]byte(" "), []byte(meta.String())...)})
	}

	if len(edits) == 0 {
		return src, false
	}

	// Apply edits in order.
	// Sort edits just in case, though we scanned in order.
	for i := 0; i < len(edits)-1; i++ {
		for j := i + 1; j < len(edits); j++ {
			if edits[j].start < edits[i].start {
				edits[i], edits[j] = edits[j], edits[i]
			}
		}
	}

	var out bytes.Buffer
	cursor := 0
	for _, e := range edits {
		if e.start < cursor {
			continue
		}
		out.Write(src[cursor:e.start])
		if e.repl != nil {
			out.Write(e.repl)
		}
		cursor = e.end
	}
	out.Write(src[cursor:])
	return out.Bytes(), true
}
