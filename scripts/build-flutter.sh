#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================"
echo " IDENTITY AGENT - Build Pipeline"
echo "============================================"
echo "      Workspace: $WORKSPACE"

echo ""
echo "[1/4] Installing Python dependencies for KERI driver..."
cd "$WORKSPACE"
pip install -q flask 2>/dev/null || pip3 install -q flask 2>/dev/null || echo "      Warning: flask install skipped"
echo "      Python dependencies ready."

echo ""
echo "[2/4] Building Flutter Web..."
cd "$WORKSPACE/identity_agent_ui"
flutter clean
flutter pub get
flutter build web --release --base-href="/"
echo "      Flutter Web built successfully."

echo ""
echo "[3/4] Building Go Core (static binary, no CGO)..."
cd "$WORKSPACE/identity-agent-core"
mkdir -p "$WORKSPACE/identity-agent-core/bin"
CGO_ENABLED=0 go build -o "$WORKSPACE/identity-agent-core/bin/identity-agent-core" .
chmod +x "$WORKSPACE/identity-agent-core/bin/identity-agent-core"
echo "      Go Core built successfully."
ls -la "$WORKSPACE/identity-agent-core/bin/identity-agent-core"

echo ""
echo "[4/4] Build complete."
echo "      Flutter Web: $WORKSPACE/identity_agent_ui/build/web/"
echo "      Go Binary:   $WORKSPACE/identity-agent-core/bin/identity-agent-core"
echo "============================================"
