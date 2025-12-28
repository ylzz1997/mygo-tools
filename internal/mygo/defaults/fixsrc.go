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
//   func f(a int, b int = 10, c string = "x y") {}
//
// becomes:
//   //mygo:defaultsjson <base64(JSON)>
//   func f(a int, b int, c string) {}
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
			case token.RPAREN:
				parenDepth--
				if parenDepth == 0 {
					// Finish last field.
					if !fieldHasDefault {
						// Count this field as required if it has at least one name.
						if lastParamName != "" {
							required++
						}
					}
				}
			case token.LBRACK:
				brackDepth++
			case token.RBRACK:
				if brackDepth > 0 {
					brackDepth--
				}
			case token.IDENT:
				// Capture last ident in field list; we assume the last ident before
				// the type is the parameter name.
				// This is heuristic but works for typical `name type` params.
				lastParamName = l2
			case token.COMMA:
				if parenDepth == 1 && brackDepth == 0 {
					// End of a field.
					if !fieldHasDefault {
						if lastParamName != "" {
							required++
						}
					}
					lastParamName = ""
					fieldHasDefault = false
				}
			case token.ASSIGN:
				if parenDepth == 1 && brackDepth == 0 {
					// Capture default expression until ',' or ')', respecting nesting.
					fieldHasDefault = true
					eqStartOff = tf.Offset(p2)
					// Expr begins after '=' token; find first non-space byte.
					exprStart := eqStartOff + 1
					for exprStart < len(src) && (src[exprStart] == ' ' || src[exprStart] == '\t') {
						exprStart++
					}
					exprEnd := exprStart
					nest := 0
					// We will scan raw bytes until delimiter at nest==0; also track quotes crudely.
					inStr := byte(0)
					for exprEnd < len(src) {
						ch := src[exprEnd]
						if inStr != 0 {
							if ch == '\\' {
								exprEnd += 2
								continue
							}
							if ch == inStr {
								inStr = 0
							}
							exprEnd++
							continue
						}
						if ch == '"' || ch == '\'' || ch == '`' {
							inStr = ch
							exprEnd++
							continue
						}
						switch ch {
						case '(', '[', '{':
							nest++
						case ')', ']', '}':
							if nest > 0 {
								nest--
							} else {
								// likely end of param list
								if ch == ')' {
									goto doneExpr
								}
							}
						case ',':
							if nest == 0 {
								goto doneExpr
							}
						}
						exprEnd++
					}
				doneExpr:
					eqEndOff = exprEnd
					if lastParamName != "" && eqStartOff >= 0 && eqEndOff >= eqStartOff {
						defs = append(defs, def{
							param: lastParamName,
							expr:  strings.TrimSpace(string(src[exprStart:eqEndOff])),
						})
						edits = append(edits, edit{start: eqStartOff, end: eqEndOff, repl: nil}) // delete
						changed = true
					}
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
		fmt.Fprintf(&meta, "//line %s:%d\n", filename, startLine)
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
				fmt.Fprintf(&meta, "//%s%s\n", metaPrefixJSON, enc)
			} else {
				// Fallback to old format if JSON encoding fails.
				fmt.Fprintf(&meta, "//%s%s %d", metaPrefixOld, funcName, required)
				for _, d := range defs {
					fmt.Fprintf(&meta, " %s=%s", d.param, d.expr)
				}
				meta.WriteString("\n")
			}
		}
		fmt.Fprintf(&meta, "//line %s:%d\n", filename, startLine)

		edits = append(edits, edit{start: funcOff, end: funcOff, repl: []byte(meta.String())})
	}

	if !changed {
		return src, false
	}

	// Apply edits in order.
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


