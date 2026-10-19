#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$WORKSPACE/identity-agent-core/bin/identity-agent-core"

echo "============================================"
echo " IDENTITY AGENT - Go Core"
echo "============================================"
echo "      Workspace: $WORKSPACE"

echo ""
echo "[1/2] Go Core binary..."
echo "      Looking for: $BINARY"
ls -la "$WORKSPACE/identity-agent-core/bin/" 2>/dev/null || echo "      WARNING: bin directory does not exist"

if [ -f "$BINARY" ]; then
    echo "      Go Core binary found (pre-built). Skipping build."
else
    echo "      Go Core binary not found. Building..."
    cd "$WORKSPACE/identity-agent-core"
    mkdir -p "$WORKSPACE/identity-agent-core/bin"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags="-s -w" -o "$BINARY" .
    chmod +x "$BINARY"
    echo "      Go Core built successfully."
fi

file "$BINARY" 2>/dev/null || true
ldd "$BINARY" 2>/dev/null || echo "      Binary is statically linked (good for production)"

GO_DEMO="$WORKSPACE/bin/go-demo"
if [ -f "$GO_DEMO" ]; then
    echo "      Go Demo binary found (pre-built). Skipping build."
else
    echo "      Building go-demo sandbox app..."
    mkdir -p "$WORKSPACE/bin"
    cd "$WORKSPACE/sandbox-apps/go-demo"
    CGO_ENABLED=0 go build -buildvcs=false -ldflags="-s -w" -o "$GO_DEMO" .
    chmod +x "$GO_DEMO"
    echo "      Go Demo built: $GO_DEMO"
fi

echo ""
echo "[2/2] Starting Identity Agent..."
echo "      Go Core:     http://0.0.0.0:${PORT:-5050}/api/health"
echo "      UI:          http://0.0.0.0:${PORT:-5050}/"
echo "============================================"
echo ""

cd "$WORKSPACE"

SODIUM_LIB=$(python3 -c "
import ctypes, os
for so_name in ['libsodium.so.26', 'libsodium.so.23', 'libsodium.so']:
    try:
        ctypes.CDLL(so_name)
        for line in open(f'/proc/{os.getpid()}/maps'):
            if 'sodium' in line:
                parts = line.strip().split()
                if len(parts) >= 6:
                    print(os.path.dirname(parts[-1]))
                    raise SystemExit(0)
        break
    except OSError:
        continue
" 2>/dev/null) || true
if [ -n "$SODIUM_LIB" ]; then
    export LD_LIBRARY_PATH="${SODIUM_LIB}:${LD_LIBRARY_PATH}"
    echo "      libsodium: $SODIUM_LIB"
fi

export FLUTTER_WEB_DIR="$WORKSPACE/identity_agent_ui/build/web"
exec "$BINARY"
