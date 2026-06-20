#!/usr/bin/env bash
# Create Python 3.12+ venv with pinned keri 1.1.17 for hybrid PQC conformance tests.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="${ROOT}/drivers/keri-core/.venv-keri1117"
PY="${PYTHON312:-python3.12}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "Python 3.12+ required (set PYTHON312=...); keri 1.1.17 does not install on 3.9" >&2
  exit 1
fi
"$PY" -m venv "$VENV"
"$VENV/bin/pip" install -q -r "${ROOT}/drivers/keri-core/requirements.txt"
"$VENV/bin/python" -c "import keri; import importlib.metadata as m; assert m.version('keri')=='1.1.17'"
echo "OK: keri $( "$VENV/bin/python" -c "import importlib.metadata as m; print(m.version('keri'))" ) at $VENV"