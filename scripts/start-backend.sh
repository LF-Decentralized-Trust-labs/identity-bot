#!/bin/sh
set -e

WORKSPACE="/home/runner/workspace"

echo "============================================"
echo " IDENTITY AGENT - Go Core"
echo "============================================"

echo ""
echo "[1/2] Building Go Core..."
cd "$WORKSPACE/identity-agent-core"
go build -o "$WORKSPACE/bin/identity-agent-core" .
echo "      Go Core built successfully."

echo ""
echo "[2/2] Starting Identity Agent Core on port ${PORT:-5000}..."
echo "      API:  http://0.0.0.0:${PORT:-5000}/api/health"
echo "      UI:   http://0.0.0.0:${PORT:-5000}/"
echo "============================================"
echo ""

cd "$WORKSPACE"
export FLUTTER_WEB_DIR="$WORKSPACE/identity_agent_ui/build/web"
exec "$WORKSPACE/bin/identity-agent-core"
