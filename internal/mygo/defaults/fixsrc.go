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

		// Track identifiers within the current parameter field (between top-level commas).
		// For "name type = expr", the first ident is the parameter name; the last ident
		// is often the type name (e.g. "string", "int").
		lastParamName := ""
		fieldFirstIdent := ""
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
						paramName := fieldFirstIdent
						if paramName == "" {
							paramName = lastParamName
						}
						defs = append(defs, def{param: paramName, expr: expr})
						seg := src[eqStartOff:eqEndOff]
						edits = append(edits, edit{start: eqStartOff, end: eqEndOff, repl: makeWhitespacePreservingNewlines(seg)})
						fieldHasDefault = true
					}
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
						paramName := fieldFirstIdent
						if paramName == "" {
							paramName = lastParamName
						}
						defs = append(defs, def{param: paramName, expr: expr})
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
					// Prepare for next field.
					fieldHasDefault = false
					fieldFirstIdent = ""
					lastParamName = ""
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
					lastParamName = l2
					if fieldFirstIdent == "" {
						fieldFirstIdent = l2
					}
				}
			}
		}

		if len(defs) == 0 {
			continue
		}

		// Insert metadata comment before 'func' keyword.
		funcOff := tf.Offset(funcPos)
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

		// Insert metadata immediately before 'func', without introducing newlines.
		// This keeps physical line numbers stable (critical for LSP diagnostics).
		//
		// Note: this shifts columns on the declaration line only; call sites and
		// other lines keep identical offsets.
		repl := append([]byte(meta.String()), ' ')
		edits = append(edits, edit{start: funcOff, end: funcOff, repl: repl})
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
