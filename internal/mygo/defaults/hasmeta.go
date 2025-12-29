package defaults

import "go/ast"

// HasAnyMetadata reports whether any file contains MyGO defaults metadata
// injected by FixSrc.
//
// This is a cheap pre-check used by tooling to decide whether it must run the
// (more expensive) type-driven default-argument rewrite.
func HasAnyMetadata(files []*ast.File) bool {
	for _, f := range files {
		if f == nil {
			continue
		}
		for _, cg := range f.Comments {
			if cg == nil {
				continue
			}
			for _, c := range cg.List {
				if c == nil {
					continue
				}
				txt := trimCommentText(c.Text)
				if len(txt) == 0 {
					continue
				}
				if hasMetaPrefix(txt) {
					return true
				}
			}
		}
	}
	return false
}

func hasMetaPrefix(txt string) bool {
	// metaPrefix* are in metadata.go
	if len(txt) >= len(metaPrefixJSON) && txt[:len(metaPrefixJSON)] == metaPrefixJSON {
		return true
	}
	if len(txt) >= len(metaPrefixOld) && txt[:len(metaPrefixOld)] == metaPrefixOld {
		return true
	}
	return false
}


