// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package enum

import (
	"bytes"
	"fmt"
	"go/scanner"
	"go/token"
	"strings"
	"unicode"
)

// FixSrc rewrites MyGO enum type declarations into parseable Go code.
//
// It only targets the declaration form:
//   type Name [T any, ...] enum { Variant ... }
//
// It does not attempt to rewrite pattern matching or constructor expressions.
// Those are handled later at the AST rewrite stage.
func FixSrc(filename string, src []byte) (_ []byte, changed bool) {
	// Fast path.
	if !bytes.Contains(src, []byte(" enum")) && !bytes.Contains(src, []byte("\tenum")) {
		return src, false
	}

	fset := token.NewFileSet()
	tf := fset.AddFile("mygo-enum", -1, len(src))

	var s scanner.Scanner
	var errs scanner.ErrorList
	s.Init(tf, src, func(pos token.Position, msg string) {
		// Don't fail parsing here; just record.
		errs.Add(pos, msg)
	}, scanner.ScanComments)

	type edit struct {
		start, end int
		repl       []byte
	}
	var edits []edit

	// Helper to scan next non-comment token.
	next := func() (pos token.Pos, tok token.Token, lit string) {
		for {
			pos, tok, lit = s.Scan()
			if tok != token.COMMENT {
				return
			}
		}
	}

	// We scan for: TYPE IDENT [..]? IDENT("enum") LBRACE ... RBRACE
	for {
		pos, tok, lit := next()
		if tok == token.EOF {
			break
		}
		if tok != token.TYPE {
			continue
		}

		typePos := pos
		_, tok, lit = next()
		if tok != token.IDENT {
			continue
		}
		name := lit

		// Optional type params.
		var tparamsText string
		var tparamNames []string
		peekPos, peekTok, peekLit := next()
		if peekTok == token.LBRACK {
			// Capture from '[' to matching ']'.
			lbrackOff := tf.Offset(peekPos)
			depth := 1
			var lastPos token.Pos
			for depth > 0 {
				p2, t2, _ := next()
				lastPos = p2
				if t2 == token.LBRACK {
					depth++
				} else if t2 == token.RBRACK {
					depth--
				} else if t2 == token.EOF {
					depth = 0
					break
				}
			}
			rbrackOff := tf.Offset(lastPos) + 1 // include ']'
			if rbrackOff > lbrackOff && rbrackOff <= len(src) {
				tparamsText = string(src[lbrackOff:rbrackOff])
				tparamNames = parseTypeParamNames(tparamsText)
			}
			// Continue scanning after bracket list.
			_, tok, lit = next()
		} else {
			// No type params: put token back into "current" by reusing peek values.
			pos, tok, lit = peekPos, peekTok, peekLit
		}

		if tok != token.IDENT || lit != "enum" {
			continue
		}

		lbracePos, lbraceTok, _ := next()
		if lbraceTok != token.LBRACE {
			continue
		}
		lbraceOff := tf.Offset(lbracePos)

		// Find the matching '}' for this enum block.
		braceDepth := 1
		var rbracePos token.Pos
		for braceDepth > 0 {
			p2, t2, _ := next()
			if t2 == token.EOF {
				break
			}
			if t2 == token.LBRACE {
				braceDepth++
			} else if t2 == token.RBRACE {
				braceDepth--
				if braceDepth == 0 {
					rbracePos = p2
					break
				}
			}
		}
		if !rbracePos.IsValid() {
			continue
		}
		rbraceOff := tf.Offset(rbracePos)

		startOff := tf.Offset(typePos)
		endOff := rbraceOff + 1 // include '}'
		if startOff < 0 || endOff > len(src) || startOff >= endOff {
			continue
		}

		body := src[lbraceOff+1 : rbraceOff]
		variants := parseEnumBody(body)
		if len(variants) == 0 {
			// Still rewrite into an empty struct so the file parses.
		}

		// Preserve original line mapping using //line directives.
		startLine := tf.Position(typePos).Line
		endLine := tf.Position(rbracePos).Line
		replBody := generateEnumLowering(name, tparamsText, tparamNames, variants)
		var repl bytes.Buffer
		fmt.Fprintf(&repl, "//line %s:%d\n", filename, startLine)
		repl.Write(replBody)
		if !bytes.HasSuffix(replBody, []byte("\n")) {
			repl.WriteByte('\n')
		}
		fmt.Fprintf(&repl, "//line %s:%d\n", filename, endLine+1)
		edits = append(edits, edit{start: startOff, end: endOff, repl: repl.Bytes()})
	}

	if len(edits) == 0 {
		return src, false
	}

	// Apply edits in order (scanner guarantees increasing offsets; but be safe).
	// Sort by start offset.
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
			// Overlapping edit: skip (shouldn't happen).
			continue
		}
		out.Write(src[cursor:e.start])
		out.Write(e.repl)
		cursor = e.end
	}
	out.Write(src[cursor:])
	return out.Bytes(), true
}

type variant struct {
	name   string
	fields []string // type expressions
}

func parseEnumBody(body []byte) []variant {
	// Use go/scanner to tokenize the body; it handles comments/strings.
	fset := token.NewFileSet()
	tf := fset.AddFile("mygo-enum-body", -1, len(body))
	var s scanner.Scanner
	s.Init(tf, body, func(token.Position, string) {}, scanner.ScanComments)

	next := func() (pos token.Pos, tok token.Token, lit string) {
		for {
			pos, tok, lit = s.Scan()
			if tok != token.COMMENT {
				return
			}
		}
	}

	var vars []variant
	for {
		_, tok, lit := next()
		if tok == token.EOF {
			break
		}
		if tok == token.SEMICOLON {
			continue
		}
		if tok != token.IDENT {
			continue
		}
		vname := lit
		_, tok, _ = next()
		if tok != token.LPAREN {
			// Unit variant.
			vars = append(vars, variant{name: vname})
			// Consume until semicolon or EOF to move forward.
			continue
		}

		// Capture args until matching ')', splitting on commas at depth 1.
		var parts []string
		argStart := -1
		parenDepth := 1
		lastPos := token.NoPos
		for parenDepth > 0 {
			p2, t2, _ := next()
			lastPos = p2
			if t2 == token.EOF {
				break
			}
			if t2 == token.LPAREN || t2 == token.LBRACK || t2 == token.LBRACE {
				parenDepth++
				if argStart < 0 {
					// Start of first arg.
					argStart = tf.Offset(p2)
				}
				continue
			}
			if t2 == token.RPAREN || t2 == token.RBRACK || t2 == token.RBRACE {
				parenDepth--
				if parenDepth == 0 {
					// End of args.
					if argStart >= 0 {
						end := tf.Offset(p2)
						if end >= argStart && end <= len(body) {
							part := strings.TrimSpace(string(body[argStart:end]))
							if part != "" {
								parts = append(parts, part)
							}
						}
					}
					break
				}
				continue
			}
			if t2 == token.COMMA && parenDepth == 1 {
				// End current arg.
				if argStart >= 0 {
					end := tf.Offset(p2)
					if end >= argStart && end <= len(body) {
						part := strings.TrimSpace(string(body[argStart:end]))
						if part != "" {
							parts = append(parts, part)
						}
					}
				}
				argStart = -1
				continue
			}
			if argStart < 0 && parenDepth == 1 && t2 != token.SEMICOLON {
				argStart = tf.Offset(p2)
			}
		}
		_ = lastPos // keep for symmetry; not used.
		vars = append(vars, variant{name: vname, fields: parts})
	}
	return vars
}

func parseTypeParamNames(tparamsText string) []string {
	// Extract the leading IDENT of each type parameter: [T any, E error] => ["T","E"].
	b := []byte(tparamsText)
	fset := token.NewFileSet()
	tf := fset.AddFile("mygo-tparams", -1, len(b))
	var s scanner.Scanner
	s.Init(tf, b, func(token.Position, string) {}, 0)
	var names []string
	expectName := false
	for {
		_, tok, lit := s.Scan()
		switch tok {
		case token.LBRACK:
			expectName = true
		case token.COMMA:
			expectName = true
		case token.RBRACK, token.EOF:
			return names
		case token.IDENT:
			if expectName {
				names = append(names, lit)
				expectName = false
			}
		}
	}
}

func generateEnumLowering(typeName, tparamsText string, tparamNames []string, vars []variant) []byte {
	// Build type argument list for instantiations: [T, E]
	targs := ""
	if len(tparamNames) > 0 {
		targs = "[" + strings.Join(tparamNames, ", ") + "]"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "// mygo:generated (enum lowering)\n")
	fmt.Fprintf(&b, "type %s%s struct {\n\t_tag int\n\t_payload any\n}\n", typeName, tparamsText)
	fmt.Fprintf(&b, "const (\n")
	for i, v := range vars {
		if i == 0 {
			fmt.Fprintf(&b, "\t%s__Tag_%s = iota\n", typeName, v.name)
		} else {
			fmt.Fprintf(&b, "\t%s__Tag_%s\n", typeName, v.name)
		}
	}
	fmt.Fprintf(&b, ")\n")

	for _, v := range vars {
		if len(v.fields) == 0 {
			continue
		}
		fmt.Fprintf(&b, "type %s__payload_%s%s struct {\n", typeName, v.name, tparamsText)
		for i, ft := range v.fields {
			fmt.Fprintf(&b, "\tF%d %s\n", i, strings.TrimSpace(ft))
		}
		fmt.Fprintf(&b, "}\n")
	}

	for _, v := range vars {
		ctorName := fmt.Sprintf("%s__%s", typeName, v.name)
		fmt.Fprintf(&b, "func %s%s(", ctorName, tparamsText)
		for i, ft := range v.fields {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "v%d %s", i, strings.TrimSpace(ft))
		}
		b.WriteString(") ")
		fmt.Fprintf(&b, "%s%s {\n", typeName, targs)
		if len(v.fields) == 0 {
			fmt.Fprintf(&b, "\treturn %s%s{_tag: %s__Tag_%s, _payload: nil}\n", typeName, targs, typeName, v.name)
			fmt.Fprintf(&b, "}\n")
			continue
		}
		fmt.Fprintf(&b, "\treturn %s%s{_tag: %s__Tag_%s, _payload: %s__payload_%s%s{", typeName, targs, typeName, v.name, typeName, v.name, targs)
		for i := range v.fields {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "F%d: v%d", i, i)
		}
		b.WriteString("}}\n")
		b.WriteString("}\n")
	}

	// Add a small anchor so the type isn't "unused" in degenerate cases.
	// (Not strictly needed, but helps keep the generated decls stable.)
	fmt.Fprintf(&b, "var _ = %s__Tag_%s\n", typeName, firstVariantName(vars))
	return []byte(b.String())
}

func firstVariantName(vars []variant) string {
	if len(vars) == 0 {
		return "Invalid"
	}
	return vars[0].name
}

func isIdentStart(r rune) bool { return r == '_' || unicode.IsLetter(r) }


