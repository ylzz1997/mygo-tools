#!/usr/bin/env bash
set -euo pipefail

# Build mygopls using the MyGO toolchain in this repo.
#
# Why: MyGO files still use the .go suffix. The only reliable way for gopls to
# understand MyGO syntax is to compile and run it with the MyGO toolchain
# (forked go/parser/token/ast).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MYGO_ROOT="${MYGO_ROOT:-"$ROOT/mygo"}"
OUT_DIR="${OUT_DIR:-"$ROOT/bin"}"
OUT_BIN="${OUT_BIN:-"$OUT_DIR/mygopls"}"

if [[ ! -x "$MYGO_ROOT/bin/go" ]]; then
  echo "error: missing MyGO go tool at: $MYGO_ROOT/bin/go" >&2
  echo "hint: build MyGO first: cd \"$MYGO_ROOT/src\" && GOROOT_BOOTSTRAP=<your-go> ./make.bash" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

export GOROOT="$MYGO_ROOT"
export PATH="$MYGO_ROOT/bin:$PATH"

pushd "$ROOT/gopls" >/dev/null
  # Ensure we don't accidentally fetch toolchains (Go 1.21+ behavior).
  export GOTOOLCHAIN=local

  # Keep caches inside the repo for reproducibility (and to avoid permission issues).
  export GOPATH="${GOPATH:-"$ROOT/.gopath"}"
  export GOMODCACHE="${GOMODCACHE:-"$GOPATH/pkg/mod"}"
  export GOCACHE="${GOCACHE:-"$ROOT/.gocache"}"
  mkdir -p "$GOPATH" "$GOMODCACHE" "$GOCACHE"

  go env GOROOT >/dev/null
  go build -o "$OUT_BIN" .
popd >/dev/null

echo "built: $OUT_BIN"


