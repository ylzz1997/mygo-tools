package golang

import (
	"testing"

	"golang.org/x/tools/gopls/internal/protocol"
)

func TestLexicalSemanticTokens_MyGOKeywords(t *testing.T) {
	src := []byte(`package p

@decorator
enum Shape {
    Point
}

func f(x any) {
    _ = x?.y
    _ = x?:y
    _ = @notdecor
    match x { }
}
`)
	toks, err := lexicalSemanticTokens("file:///p.go", src, nil)
	if err != nil {
		t.Fatalf("lexicalSemanticTokens: %v", err)
	}
	if toks == nil || len(toks.Data) == 0 {
		t.Fatalf("got no semantic tokens")
	}

	legend := protocol.SemanticTokensLegend{
		TokenTypes:     []string{"namespace", "type", "typeParameter", "parameter", "variable", "function", "method", "macro", "keyword", "comment", "string", "number", "operator", "label"},
		TokenModifiers: []string{"definition", "defaultLibrary", "readonly"},
	}
	got := decodeSemanticTokens(toks.Data, legend)
	mapper := protocol.NewMapper("file:///p.go", src)

	// Keyword assertions (exact text).
	if !hasTypedText(mapper, got, "keyword", "enum") {
		t.Fatalf("expected keyword token for %q", "enum")
	}
	if !hasTypedText(mapper, got, "keyword", "match") {
		t.Fatalf("expected keyword token for %q", "match")
	}

	// Operator assertions (exact text).
	if !hasTypedText(mapper, got, "operator", "?.") {
		t.Fatalf("expected operator token for %q", "?.")
	}
	if !hasTypedText(mapper, got, "operator", "?:") {
		t.Fatalf("expected merged operator token for %q", "?:")
	}
	if !hasTypedText(mapper, got, "operator", "@") {
		t.Fatalf("expected operator token for %q", "@")
	}
	// Decorator name should be macro-styled.
	if !hasTypedText(mapper, got, "macro", "decorator") {
		t.Fatalf("expected macro token for decorator name %q", "decorator")
	}
	// But inline "@notdecor" should NOT be treated as a decorator.
	if hasTypedText(mapper, got, "macro", "notdecor") {
		t.Fatalf("did not expect macro token for inline decorator-like text %q", "notdecor")
	}
}

type decodedTok struct {
	line, start, length uint32
	typ                string
}

func decodeSemanticTokens(data []uint32, legend protocol.SemanticTokensLegend) []decodedTok {
	var out []decodedTok
	var line, start uint32
	for i := 0; i+4 < len(data); i += 5 {
		dLine, dStart := data[i], data[i+1]
		length, ttype, tmods := data[i+2], data[i+3], data[i+4]
		line += dLine
		if dLine == 0 {
			start += dStart
		} else {
			start = dStart
		}
		typ := "<?>"
		if int(ttype) < len(legend.TokenTypes) {
			typ = legend.TokenTypes[ttype]
		}
		_ = tmods
		out = append(out, decodedTok{line: line, start: start, length: length, typ: typ})
	}
	return out
}

func hasTypedText(mapper *protocol.Mapper, toks []decodedTok, wantType, wantText string) bool {
	for _, tk := range toks {
		if tk.typ != wantType {
			continue
		}
		startPos := protocol.Position{Line: tk.line, Character: tk.start}
		endPos := protocol.Position{Line: tk.line, Character: tk.start + tk.length}
		off1, err1 := mapper.PositionOffset(startPos)
		off2, err2 := mapper.PositionOffset(endPos)
		if err1 != nil || err2 != nil || off1 < 0 || off2 < off1 || off2 > len(mapper.Content) {
			continue
		}
		if string(mapper.Content[off1:off2]) == wantText {
			return true
		}
	}
	return false
}


