#!/usr/bin/env bash
# test-join-the-core.sh — join-the-core.sh follows the core: a module the core
# adds, and one it moves, reach an app with no change to the app. Also that
# --check fails on drift, that a lone stale replace of a core module goes, that
# the block survives `go mod edit -fmt`, that CRLF files work, and that a core
# replace the script cannot join is refused. Uses only what macOS (bash 3.2,
# BSD awk and sed) has: no GNU-only flags.
set -euo pipefail
S="$(cd "$(dirname "$0")" && pwd)/join-the-core.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/app" "$T/core/newproto"
printf 'module identity-agent-core\n\ngo 1.25.0\n\nreplace example.org/core/newproto => ./newproto\n' > "$T/core/go.mod"
printf 'module app\n\ngo 1.25.0\n\nreplace example.org/core/oldproto => ./stale\n\nreplace identity-agent-core => ./stale\n' > "$T/app/go.mod"
fail() { echo "FAIL: $*" >&2; exit 1; }

bash "$S" gomod "$T/app/go.mod" ../core x.org/addons=./addons
grep -q 'example.org/core/newproto => ../core/newproto' "$T/app/go.mod" || fail "new core module not joined"
grep -q 'identity-agent-core => ../core$' "$T/app/go.mod" || fail "core not joined"
grep -q 'x.org/addons => ./addons' "$T/app/go.mod" || fail "app replace lost"
grep -q "identity-agent-core => ./stale" "$T/app/go.mod" && fail "stale replace of a core module kept"
bash "$S" gomod "$T/app/go.mod" ../core --check x.org/addons=./addons || fail "check fails on a joined app"

# the core moves its module; the app is now behind
mv "$T/core/newproto" "$T/core/proto/newproto" 2>/dev/null || { mkdir -p "$T/core/proto"; mv "$T/core/newproto" "$T/core/proto/newproto"; }
sed -i.bak 's#=> ./newproto#=> ./proto/newproto#' "$T/core/go.mod"
if bash "$S" gomod "$T/app/go.mod" ../core --check x.org/addons=./addons 2>/dev/null; then fail "check passed on drift"; fi
bash "$S" gomod "$T/app/go.mod" ../core x.org/addons=./addons
grep -q 'newproto => ../core/proto/newproto' "$T/app/go.mod" || fail "moved path not followed"

bash "$S" work "$T/core" "$T/go.work" "$T/app" x.org/addons=/a
grep -q 'replace example.org/core/newproto => .*/core/proto/newproto' "$T/go.work" || fail "go.work missed the module"
grep -q '^use ' "$T/go.work" || fail "go.work has no use"

# the block is written as Go formats it: format, and --check still passes
if command -v go >/dev/null 2>&1; then
  ( cd "$T/app" && go mod edit -fmt )
  bash "$S" gomod "$T/app/go.mod" ../core --check x.org/addons=./addons || fail "check fails after go mod edit -fmt"
  bash "$S" gomod "$T/app/go.mod" ../core x.org/addons=./addons
  ( cd "$T/app" && go mod edit -fmt && cp go.mod "$T/fmt.mod" )
  cmp -s "$T/fmt.mod" "$T/app/go.mod" || fail "a rewrite is not what go mod edit -fmt leaves"
else
  echo "skip: no go, so the go mod edit -fmt check did not run"
fi

# a Windows checkout: CRLF in the core's go.mod and in the app's
mkdir -p "$T/crlf/app" "$T/crlf/core"
printf 'module identity-agent-core\r\n\r\ngo 1.25.0\r\n\r\nreplace example.org/core/p => ./p\r\n' > "$T/crlf/core/go.mod"
printf 'module app\r\n\r\ngo 1.25.0\r\n\r\nreplace identity-agent-core => ./stale\r\n' > "$T/crlf/app/go.mod"
bash "$S" gomod "$T/crlf/app/go.mod" ../core || fail "CRLF go.mod refused"
grep -q 'example.org/core/p => ../core/p$' "$T/crlf/app/go.mod" || fail "CRLF core module not joined"
bash "$S" gomod "$T/crlf/app/go.mod" ../core --check || fail "check fails on a joined CRLF app"
# a joined app whose file was checked out with CRLF is still joined
awk '{ printf "%s\r\n", $0 }' "$T/crlf/app/go.mod" > "$T/crlf/app/go.mod.crlf" && mv "$T/crlf/app/go.mod.crlf" "$T/crlf/app/go.mod"
bash "$S" gomod "$T/crlf/app/go.mod" ../core --check || fail "check fails on a CRLF checkout of a joined app"
bash "$S" work "$T/crlf/core" "$T/crlf/go.work" "$T/crlf/app"
grep -q "$(printf '\r')" "$T/crlf/go.work" && fail "go.work carries a CR"
grep -q '^go 1.25.0$' "$T/crlf/go.work" || fail "go.work version wrong with a CRLF core"

# a replace ( ... ) block in the core is read, and in the app a stale one is removed
mkdir -p "$T/blk/app" "$T/blk/core"
printf 'module identity-agent-core\n\ngo 1.25.0\n\nreplace (\n\texample.org/core/a => ./a\n\texample.org/core/b => ./sub/b // c\n)\n' > "$T/blk/core/go.mod"
printf 'module app\n\ngo 1.25.0\n\nreplace (\n\texample.org/core/a => ./stale\n\tother.org/x => ./x\n)\n' > "$T/blk/app/go.mod"
bash "$S" gomod "$T/blk/app/go.mod" ../core
grep -q 'replace example.org/core/a => ../core/a$' "$T/blk/app/go.mod" || fail "block replace a not joined"
grep -q 'replace example.org/core/b => ../core/sub/b$' "$T/blk/app/go.mod" || fail "block replace b not joined"
grep -q 'a => ./stale' "$T/blk/app/go.mod" && fail "stale replace inside an app block kept"
grep -q 'other.org/x => ./x' "$T/blk/app/go.mod" || fail "app's own block replace lost"

# a core replace that cannot be joined is refused, never skipped
refuse() { # NAME LINE
  mkdir -p "$T/r/$1/app" "$T/r/$1/core"
  printf 'module identity-agent-core\n\ngo 1.25.0\n\n%s\n' "$2" > "$T/r/$1/core/go.mod"
  printf 'module app\n\ngo 1.25.0\n' > "$T/r/$1/app/go.mod"
  if bash "$S" gomod "$T/r/$1/app/go.mod" ../core 2>"$T/r/$1/err"; then fail "$1: accepted"; fi
  [ -s "$T/r/$1/err" ] || fail "$1: refused silently"
  if bash "$S" work "$T/r/$1/core" "$T/r/$1/go.work" "$T/r/$1/app" 2>/dev/null; then fail "$1: work mode accepted"; fi
}
refuse versioned 'replace example.org/x v1.2.3 => ./x'
refuse remote 'replace example.org/x => example.org/y v1.0.0'
refuse outside 'replace example.org/x => ../x'
refuse inblock 'replace (
	example.org/x v1.0.0 => ./x
)'
echo "ok: join-the-core follows the core"
