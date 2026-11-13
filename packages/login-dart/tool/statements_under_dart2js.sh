#!/usr/bin/env bash
# Runs the sealing key's statement vectors (login-web/test-vectors/seal.json) as
# JavaScript: compiled with dart2js, run with node. `dart test` runs them on the
# native VM only, where `1.0 is int` is false; compiled for the web it is true, so
# a statement spelling "sn":1.0 must be refused by its bytes, not its Dart type.
# Only the statement cases are passed in (a compiler define has a size limit).
# Needs `dart` and `node` on PATH. Run from anywhere.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
vectors="$(node -e 'process.stdout.write((({ rid, relay_log, seal_key, statement_refusals }) => JSON.stringify({ rid, relay_log, seal_key: { statement: seal_key.statement }, statement_refusals }))(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))))' "$here/../login-web/test-vectors/seal.json")"
(cd "$here" && dart pub get --offline >/dev/null 2>&1 || dart pub get >/dev/null)
(cd "$here" && dart compile js -o "$out/statements.js" "-DSTATEMENT_VECTORS=$vectors" tool/statements_under_dart2js.dart)
node "$out/statements.js"
