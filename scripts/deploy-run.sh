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

# Check libsodium
if [ -f "$WORKSPACE/.sodium_lib_path" ]; then
    SODIUM_LIB=$(cat "$WORKSPACE/.sodium_lib_path")
    export LD_LIBRARY_PATH="${SODIUM_LIB}:${LD_LIBRARY_PATH}"
    echo "[diag] libsodium: $SODIUM_LIB"
else
    echo "[diag] libsodium: using system default"
fi

# Check port
echo "[diag] PORT: ${PORT:-5050}"

echo "============================================"
echo " Starting Identity Agent..."
echo "============================================"

export FLUTTER_WEB_DIR="$WEBDIR"

exec "$BINARY"
