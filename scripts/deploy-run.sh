#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$WORKSPACE/identity-agent-core/bin/identity-agent-core"

echo "============================================"
echo " IDENTITY AGENT - Deploy Runtime Diagnostics"
echo "============================================"

# Check Go binary
if [ -f "$BINARY" ]; then
    echo "[diag] Go binary: OK ($BINARY)"
else
    echo "[diag] Go binary: MISSING ($BINARY)"
    exit 1
fi

# Check Flutter web build
WEBDIR="$WORKSPACE/identity_agent_ui/build/web"
if [ -f "$WEBDIR/index.html" ]; then
    echo "[diag] Flutter web: OK ($WEBDIR)"
else
    echo "[diag] Flutter web: MISSING ($WEBDIR/index.html)"
fi

# Check Python + deps
echo "[diag] Python path: $(which python3 2>/dev/null || echo 'NOT FOUND')"
echo "[diag] Python version: $(python3 --version 2>/dev/null || echo 'N/A')"
python3 -c "import flask; print('[diag] flask: OK')" 2>/dev/null || echo "[diag] flask: MISSING"
python3 -c "import keri; print('[diag] keri: OK')" 2>/dev/null || echo "[diag] keri: MISSING"

# Check KERI driver script
KERI_SCRIPT="$WORKSPACE/drivers/keri-core/server.py"
if [ -f "$KERI_SCRIPT" ]; then
    echo "[diag] KERI driver script: OK"
else
    echo "[diag] KERI driver script: MISSING ($KERI_SCRIPT)"
fi

# Check libsodium
if [ -f "$WORKSPACE/.sodium_lib_path" ]; then
    SODIUM_LIB=$(cat "$WORKSPACE/.sodium_lib_path")
    export LD_LIBRARY_PATH="${SODIUM_LIB}:${LD_LIBRARY_PATH}"
    echo "[diag] libsodium: $SODIUM_LIB"
else
    echo "[diag] libsodium: using system default"
fi

# Check port
echo "[diag] PORT: ${PORT:-5000}"

echo "============================================"
echo " Starting Identity Agent..."
echo "============================================"

export FLUTTER_WEB_DIR="$WEBDIR"
export KERI_DRIVER_SCRIPT="$KERI_SCRIPT"

exec "$BINARY"
