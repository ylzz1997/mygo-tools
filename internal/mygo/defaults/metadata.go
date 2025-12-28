// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package defaults

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Metadata is emitted by FixSrc and consumed by BuildIndex.
type Metadata struct {
	Name     string `json:"name"`
	Required int    `json:"required"`
	Defaults []struct {
		Param string `json:"param"`
		Expr  string `json:"expr"`
	} `json:"defaults"`
}

const (
	metaPrefixJSON = "mygo:defaultsjson "
	metaPrefixOld  = "mygo:defaults "
)

func encodeMetadataJSON(m Metadata) (string, bool) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", false
	}
	return base64.RawStdEncoding.EncodeToString(b), true
}

func decodeMetadataJSON(s string) (Metadata, bool) {
	var m Metadata
	dec, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return m, false
	}
	if err := json.Unmarshal(dec, &m); err != nil {
		return m, false
	}
	if m.Name == "" {
		return m, false
	}
	return m, true
}

func trimCommentText(text string) string {
	// text includes leading "//"
	return strings.TrimSpace(strings.TrimPrefix(text, "//"))
}


