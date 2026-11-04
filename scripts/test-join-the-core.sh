#!/usr/bin/env bash
# test-join-the-core.sh — join-the-core.sh follows the core: a module the core
# adds, and one it moves, reach an app with no change to the app. Also that
# --check fails on drift and that a lone stale replace of a core module goes.
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
echo "ok: join-the-core follows the core"
