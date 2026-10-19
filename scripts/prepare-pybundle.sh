#!/usr/bin/env bash
# Prepare a self-contained Python for a desktop app's KERI driver: a venv with the
# driver's requirements (keri + flask) installed, libsodium bundled inside the
# pysodium package, and pysodium patched to load it from there.
#
# Why the patch: under the macOS hardened runtime / App Sandbox, DYLD_* is
# stripped and ctypes.util.find_library returns nothing, so pysodium cannot find a
# brew-installed libsodium. Copying libsodium next to pysodium and teaching
# pysodium to fall back to it makes KERI crypto work from inside the bundle with
# no system libsodium and no environment variables.
#
# Usage:  prepare-pybundle.sh <output-cache-dir> [requirements.txt]
#   <output-cache-dir>  REQUIRED. Where the venv is written. Caller-owned: each
#                       app prepares its OWN cache — there is no shared location.
#   [requirements.txt]  Defaults to this core's driver requirements, resolved
#                       next to this script (../drivers/keri-core/requirements.txt).
# Env equivalents: OUT_DIR (output), REQ (requirements). A positional arg wins.
#
# The app bundles the result at backend/python, where the backend process service
# finds it and runs the driver with it. Note this is a venv: it references the
# BUILD machine's base Python (pyvenv.cfg) and carries no standard library, so it
# only runs where that base Python exists — it is for LOCAL / dev-loop desktop
# builds that run on the build machine, NOT a shippable self-contained app. A
# distributed build needs a genuinely relocatable interpreter (e.g. the astral
# python-build-standalone CPython), not a venv.
#
# macOS only — it bundles libsodium.dylib. The Linux and Windows desktop builds
# bundle their platform's libsodium (.so / .dll) in their own build scripts.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

CACHE="${1:-${OUT_DIR:-}}"
[ -n "$CACHE" ] || { echo "usage: prepare-pybundle.sh <output-cache-dir> [requirements.txt]" >&2; exit 2; }
REQ="${2:-${REQ:-$HERE/../drivers/keri-core/requirements.txt}}"

[ -f "$REQ" ] || { echo "missing requirements file: $REQ" >&2; exit 1; }
LIBSODIUM="$(brew --prefix libsodium 2>/dev/null)/lib/libsodium.dylib"
[ -f "$LIBSODIUM" ] || { echo "libsodium not found (brew install libsodium)" >&2; exit 1; }

echo "== creating venv at $CACHE =="
rm -rf "$CACHE"
python3 -m venv "$CACHE"
"$CACHE/bin/python3" -m pip install --quiet --upgrade pip
"$CACHE/bin/python3" -m pip install -r "$REQ"

echo "== bundling libsodium into pysodium =="
PYSOD_DIR="$("$CACHE/bin/python3" -c 'import os,pysodium;print(os.path.dirname(pysodium.__file__))')"
cp "$LIBSODIUM" "$PYSOD_DIR/libsodium.dylib"
# Patch pysodium to fall back to the bundled dylib (its find_library returns
# nothing once DYLD_* is stripped by the runtime).
python3 - "$PYSOD_DIR/__init__.py" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
if 'os.path.dirname(os.path.abspath(__file__)), \'libsodium.dylib\'' not in s:
    if '\nimport os\n' not in s:
        s = s.replace('import ctypes\n', 'import os\nimport ctypes\n', 1)
    s = s.replace(
        "ctypes.util.find_library('libsodium'))",
        "ctypes.util.find_library('libsodium') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libsodium.dylib'))",
        1)
    open(p, 'w').write(s)
PY

"$CACHE/bin/python3" -c "import pysodium; from keri.core import coring; print('OK: keri+libsodium load from', pysodium.__file__)"
echo "DONE. Cache ready at $CACHE"
