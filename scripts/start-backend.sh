#!/bin/sh
set -e

WORKSPACE="/home/runner/workspace"

echo "============================================"
echo " IDENTITY AGENT - Go Core + KERI Driver"
echo "============================================"

echo ""
echo "[1/3] Installing Python dependencies for KERI driver..."
cd "$WORKSPACE"
pip install -q flask 2>/dev/null || pip3 install -q flask 2>/dev/null || echo "      Warning: flask install skipped"
echo "      Python dependencies ready."

echo ""
echo "[2/3] Building Go Core..."
cd "$WORKSPACE/identity-agent-core"
go build -o "$WORKSPACE/bin/identity-agent-core" .
echo "      Go Core built successfully."

echo ""
echo "[3/3] Starting Identity Agent..."
echo "      Go Core:     http://0.0.0.0:${PORT:-5000}/api/health"
echo "      KERI Driver: http://127.0.0.1:${KERI_DRIVER_PORT:-9999}/status"
echo "      UI:          http://0.0.0.0:${PORT:-5000}/"
echo "============================================"
echo ""

cd "$WORKSPACE"

SODIUM_LIB=$(python3 -c "
import ctypes, os
lib = ctypes.CDLL('libsodium.so.26')
for line in open(f'/proc/{os.getpid()}/maps'):
    if 'sodium' in line:
        parts = line.strip().split()
        if len(parts) >= 6:
            print(os.path.dirname(parts[-1]))
            break
" 2>/dev/null)
if [ -n "$SODIUM_LIB" ]; then
    export LD_LIBRARY_PATH="${SODIUM_LIB}:${LD_LIBRARY_PATH}"
    echo "      libsodium: $SODIUM_LIB"
fi

export FLUTTER_WEB_DIR="$WORKSPACE/identity_agent_ui/build/web"
export KERI_DRIVER_SCRIPT="$WORKSPACE/drivers/keri-core/server.py"
exec "$WORKSPACE/bin/identity-agent-core"
