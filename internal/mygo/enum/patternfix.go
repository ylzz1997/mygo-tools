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
)

// FixPatternSrc rewrites MyGO if/for pattern match syntax into parseable Go.
//
// Supported forms:
//   if  T.Variant(x) := expr { ... }
//   if  T.Variant(x) := expr; guard { ... }
//   if  T.Variant(x) := expr { ... } else { ... }
//   if  T.Variant(x) := expr { ... } else if ...   (else-if kept as statement; rewritten on next pass)
//
//   for T.Variant(x) := expr { ... }
//   for T.Variant(x) := expr; guard { ... }
//
// Strategy: rewrite to switch / labeled for+switch so that:
// - the original pattern expression remains in a `case`, which is parseable,
// - the enum AST rewriter can later lower case patterns and bind payload vars.
//
// This function is intentionally conservative to avoid rewriting ordinary Go
// `if init; cond {}` statements.
func FixPatternSrc(filename string, src []byte) (_ []byte, changed bool) {
	// Fast path for most files.
	if !bytes.Contains(src, []byte(" := ")) && !bytes.Contains(src, []byte(":=")) {
		return src, false
	}
	if !bytes.Contains(src, []byte("if ")) && !bytes.Contains(src, []byte("for ")) {
		return src, false
	}

	// Apply repeatedly to catch else-if chains produced by a rewrite.
	out := src
	for range 10 {
		next, ok := fixPatternOnce(filename, out)
		if !ok {
			break
		}
		out = next
		changed = true
	}
	return out, changed
}

func fixPatternOnce(filename string, src []byte) (_ []byte, changed bool) {
	fset := token.NewFileSet()
	tf := fset.AddFile("mygo-pattern", -1, len(src))

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

	forLabelN := 0

	for {
		pos, tok, _ := next()
		if tok == token.EOF {
			break
		}
		if tok != token.IF && tok != token.FOR {
			continue
		}
		kwTok := tok
		startOff := tf.Offset(pos)

		// Pattern must start immediately after IF/FOR.
		patStartPos, patStartTok, patStartLit := next()
		if patStartTok != token.IDENT {
			continue
		}
		// Parse "T" or "T[...]" part.
		_ = patStartLit

		// Optional type args: [...]
		_, curTok, _ := next()
		if curTok == token.LBRACK {
			depth := 1
			for depth > 0 {
				_, t2, _ := next()
				if t2 == token.LBRACK {
					depth++
				} else if t2 == token.RBRACK {
					depth--
				} else if t2 == token.EOF {
					break
				}
			}
			_, curTok, _ = next()
		}
		if curTok != token.PERIOD {
			continue
		}
		_, curTok, _ = next()
		if curTok != token.IDENT {
			continue
		}
		// Optional payload binding: (x, y, _)
		pAfterSelPos, pAfterSelTok, _ := next()
		if pAfterSelTok == token.LPAREN {
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
			pAfterSelPos, pAfterSelTok, _ = next()
		}

		if pAfterSelTok != token.DEFINE {
			continue
		}
		definePos := pAfterSelPos

		// Capture pattern text: from patStartPos to definePos.
		patStartOff := tf.Offset(patStartPos)
		defineOff := tf.Offset(definePos)
		if patStartOff < 0 || defineOff < 0 || defineOff > len(src) || patStartOff >= defineOff {
			continue
		}
		patternText := strings.TrimSpace(string(src[patStartOff:defineOff]))

		// RHS expression until ';' or '{' (we assume no composite literal braces here).
		exprStartPos, exprTok, _ := next()
		if exprTok == token.EOF {
			continue
		}
		exprStartOff := tf.Offset(exprStartPos)
		exprEndOff := -1
		guardStartOff := -1
		guardEndOff := -1

		// Find either '{' (no guard) or ';' (guard) at depth 0.
		depth := 0
		var bracePos token.Pos
		for {
			p2, t2, _ := next()
			if t2 == token.EOF {
				break
			}
			switch t2 {
			case token.LPAREN, token.LBRACK:
				depth++
			case token.RPAREN, token.RBRACK:
				if depth > 0 {
					depth--
				}
			case token.SEMICOLON:
				if depth == 0 {
					exprEndOff = tf.Offset(p2)
					// guard begins after semicolon
					gsPos, gt, _ := next()
					if gt == token.EOF {
						break
					}
					guardStartOff = tf.Offset(gsPos)
					// scan guard until '{'
					for {
						pg, tg, _ := next()
						if tg == token.EOF {
							break
						}
						if tg == token.LBRACE {
							guardEndOff = tf.Offset(pg)
							bracePos = pg
							break
						}
					}
				}
			case token.LBRACE:
				if depth == 0 {
					exprEndOff = tf.Offset(p2)
					bracePos = p2
				}
			}
			if bracePos.IsValid() {
				break
			}
		}
		if !bracePos.IsValid() || exprEndOff < 0 {
			continue
		}

		thenBlockStartOff := tf.Offset(bracePos)
		if thenBlockStartOff < 0 || thenBlockStartOff >= len(src) {
			continue
		}

		// Parse then block by matching braces.
		thenEndOff := findMatchingRbrace(src, thenBlockStartOff)
		if thenEndOff < 0 {
			continue
		}
		thenBlockText := string(src[thenBlockStartOff : thenEndOff+1])

		// Check for else after then block.
		//
		// Supported:
		// - else { ... }
		// - else if ... { ... } [else ...]
		//
		// For else-if chains, we capture the entire nested `if ...` statement and
		// place it in the generated switch default branch.
		cursor := thenEndOff + 1
		// Consume whitespace/comments crudely.
		for cursor < len(src) && (src[cursor] == ' ' || src[cursor] == '\t' || src[cursor] == '\n' || src[cursor] == '\r') {
			cursor++
		}
		elseBlockText := "" // "{ ... }"
		elseIfStmtText := "" // "if ... { ... } [else ...]"
		if bytes.HasPrefix(src[cursor:], []byte("else")) {
			// Find start of else payload.
			cursor += len("else")
			for cursor < len(src) && (src[cursor] == ' ' || src[cursor] == '\t' || src[cursor] == '\n' || src[cursor] == '\r') {
				cursor++
			}
			if cursor < len(src) && src[cursor] == '{' {
				elseEnd := findMatchingRbrace(src, cursor)
				if elseEnd > 0 {
					elseBlockText = string(src[cursor : elseEnd+1])
					cursor = elseEnd + 1
				}
			} else if bytes.HasPrefix(src[cursor:], []byte("if")) {
				ifEnd := findEndOfIfStmt(src, cursor)
				if ifEnd > cursor {
					elseIfStmtText = strings.TrimSpace(string(src[cursor:ifEnd]))
					cursor = ifEnd
				}
			}
		}

		exprText := strings.TrimSpace(string(src[exprStartOff:exprEndOff]))
		guardText := ""
		if guardStartOff >= 0 && guardEndOff >= guardStartOff {
			guardText = strings.TrimSpace(string(src[guardStartOff:guardEndOff]))
		}

		// Replacement span: from keyword to end of then block (or else block if present).
		endOff := thenEndOff + 1
		if elseBlockText != "" || elseIfStmtText != "" {
			// elseText starts at thenEndOff+1+...; capture exact end by length
			// (cursor currently points after else block).
			endOff = cursor
		}

		// Build replacement.
		startLine := tf.Position(pos).Line
		endLine := tf.Position(tf.Pos(endOff - 1)).Line
		var repl strings.Builder
		fmt.Fprintf(&repl, "//line %s:%d\n", filename, startLine)
		switchTmp := "_mygo_pm"
		if kwTok == token.IF {
			// switch tmp := expr; tmp { case pattern: <then> default: <else> }
			fmt.Fprintf(&repl, "switch %s := %s; %s {\n", switchTmp, exprText, switchTmp)
			fmt.Fprintf(&repl, "case %s:\n", patternText)
			if guardText != "" {
				fmt.Fprintf(&repl, "if %s %s", guardText, thenBlockText)
				// If guard fails, run else branch (else block or else-if chain).
				if elseBlockText != "" {
					fmt.Fprintf(&repl, " else %s", elseBlockText)
				} else if elseIfStmtText != "" {
					fmt.Fprintf(&repl, " else {\n%s\n}", elseIfStmtText)
				}
				repl.WriteString("\n")
			} else {
				repl.WriteString(thenBlockText)
				repl.WriteString("\n")
			}
			if (elseBlockText != "" || elseIfStmtText != "") && guardText == "" {
				repl.WriteString("default:\n")
				if elseBlockText != "" {
					repl.WriteString(elseBlockText)
				} else {
					repl.WriteString(elseIfStmtText)
				}
				repl.WriteString("\n")
			} else if (elseBlockText != "" || elseIfStmtText != "") && guardText != "" {
				// guard handled else inline; still need default for non-match (and for guard failures we already run else)
				repl.WriteString("default:\n")
				if elseBlockText != "" {
					repl.WriteString(elseBlockText)
				} else {
					repl.WriteString(elseIfStmtText)
				}
				repl.WriteString("\n")
			}
			repl.WriteString("}")
		} else {
			// for pattern: labeled for + switch; break label on default or guard failure
			label := fmt.Sprintf("_mygo_for_pm_%d", forLabelN)
			forLabelN++
			fmt.Fprintf(&repl, "%s:\nfor {\n", label)
			fmt.Fprintf(&repl, "switch %s := %s; %s {\n", switchTmp, exprText, switchTmp)
			fmt.Fprintf(&repl, "case %s:\n", patternText)
			if guardText != "" {
				fmt.Fprintf(&repl, "if !(%s) { break %s }\n", guardText, label)
			}
			repl.WriteString(thenBlockText)
			repl.WriteString("\n")
			repl.WriteString("default:\n")
			fmt.Fprintf(&repl, "break %s\n", label)
			repl.WriteString("}\n}\n")
		}

		// Restore subsequent line mapping.
		if !strings.HasSuffix(repl.String(), "\n") {
			repl.WriteString("\n")
		}
		fmt.Fprintf(&repl, "//line %s:%d\n", filename, endLine+1)

		edits = append(edits, edit{start: startOff, end: endOff, repl: []byte(repl.String())})
	}

	if len(edits) == 0 {
		return src, false
	}
	// Apply edits from back to front.
	for i := 0; i < len(edits)-1; i++ {
		for j := i + 1; j < len(edits); j++ {
			if edits[j].start < edits[i].start {
				edits[i], edits[j] = edits[j], edits[i]
			}
		}
	}
	out := make([]byte, 0, len(src)+256)
	cursor := 0
	for _, e := range edits {
		if e.start < cursor {
			continue
		}
		out = append(out, src[cursor:e.start]...)
		out = append(out, e.repl...)
		cursor = e.end
		changed = true
	}
	out = append(out, src[cursor:]...)
	return out, changed
}

func findMatchingRbrace(src []byte, lbraceOff int) int {
	if lbraceOff < 0 || lbraceOff >= len(src) || src[lbraceOff] != '{' {
		return -1
	}
	// Use a scanner starting at lbraceOff to match braces.
	fset := token.NewFileSet()
	f := fset.AddFile("mygo-brace", -1, len(src[lbraceOff:]))
	var s scanner.Scanner
	s.Init(f, src[lbraceOff:], func(token.Position, string) {}, scanner.ScanComments)
	depth := 0
	for {
		p, tok, _ := s.Scan()
		if tok == token.EOF {
			return -1
		}
		if tok == token.LBRACE {
			depth++
		} else if tok == token.RBRACE {
			depth--
			if depth == 0 {
				return lbraceOff + f.Offset(p)
			}
		}
	}
}

// findEndOfIfStmt returns the index (byte offset) just after the end of the
// if-statement starting at ifOff, or -1 if it can't be determined.
//
// It recognizes:
//   if ... { ... } [else { ... } | else if ...]
func findEndOfIfStmt(src []byte, ifOff int) int {
	if ifOff < 0 || ifOff >= len(src) || !bytes.HasPrefix(src[ifOff:], []byte("if")) {
		return -1
	}
	fset := token.NewFileSet()
	f := fset.AddFile("mygo-ifstmt", -1, len(src[ifOff:]))
	var s scanner.Scanner
	s.Init(f, src[ifOff:], func(token.Position, string) {}, scanner.ScanComments)

	next := func() (pos token.Pos, tok token.Token, lit string) {
		for {
			pos, tok, lit = s.Scan()
			if tok != token.COMMENT {
				return
			}
		}
	}

	// Expect IF.
	_, tok, _ := next()
	if tok != token.IF {
		return -1
	}

	// Find first then '{' and its matching '}'.
	var thenLbraceOff int = -1
	depth := 0
	for {
		p, t, _ := next()
		if t == token.EOF {
			return -1
		}
		switch t {
		case token.LPAREN, token.LBRACK:
			depth++
		case token.RPAREN, token.RBRACK:
			if depth > 0 {
				depth--
			}
		case token.LBRACE:
			if depth == 0 {
				thenLbraceOff = ifOff + f.Offset(p)
				goto foundThen
			}
		}
	}
foundThen:
	thenRbraceOff := findMatchingRbrace(src, thenLbraceOff)
	if thenRbraceOff < 0 {
		return -1
	}
	cursor := thenRbraceOff + 1
	for cursor < len(src) && (src[cursor] == ' ' || src[cursor] == '\t' || src[cursor] == '\n' || src[cursor] == '\r') {
		cursor++
	}
	if !bytes.HasPrefix(src[cursor:], []byte("else")) {
		return cursor
	}
	cursor += len("else")
	for cursor < len(src) && (src[cursor] == ' ' || src[cursor] == '\t' || src[cursor] == '\n' || src[cursor] == '\r') {
		cursor++
	}
	if cursor < len(src) && src[cursor] == '{' {
		elseEnd := findMatchingRbrace(src, cursor)
		if elseEnd < 0 {
			return -1
		}
		return elseEnd + 1
	}
	if bytes.HasPrefix(src[cursor:], []byte("if")) {
		return findEndOfIfStmt(src, cursor)
	}
	return -1
}


