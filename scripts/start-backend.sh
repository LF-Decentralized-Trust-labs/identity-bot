#!/bin/sh
set -e

WORKSPACE="/home/runner/workspace"

echo "============================================"
echo " IDENTITY AGENT - Go Core"
echo "============================================"

echo ""
echo "[1/3] Building Go Core..."
cd "$WORKSPACE/identity-agent-core"
go build -o "$WORKSPACE/bin/identity-agent-core" .
echo "      Go Core built successfully."

echo ""
echo "[2/3] Building Flutter Web..."
cd "$WORKSPACE/identity_agent_ui"
flutter build web --release --base-href="/" 2>&1 | tail -3
echo "      Flutter Web built successfully."

echo ""
echo "[3/3] Starting Identity Agent Core on port ${PORT:-5000}..."
echo "      API:  http://0.0.0.0:${PORT:-5000}/api/health"
echo "      UI:   http://0.0.0.0:${PORT:-5000}/"
echo "============================================"
echo ""

cd "$WORKSPACE"
export FLUTTER_WEB_DIR="$WORKSPACE/identity_agent_ui/build/web"
exec "$WORKSPACE/bin/identity-agent-core"
