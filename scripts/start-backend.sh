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
echo "============================================"
echo ""

cd "$WORKSPACE"

exec "$BINARY"
