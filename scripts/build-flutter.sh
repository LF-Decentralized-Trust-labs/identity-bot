#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================"
echo " IDENTITY AGENT - Build Pipeline"
echo "============================================"
echo "      Workspace: $WORKSPACE"

echo ""
echo "[1/3] Building Flutter Web..."
cd "$WORKSPACE/identity_agent_ui"
# Ensure TLS certs are available for pub.dev
for cert in /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-bundle.crt; do
  if [ -f "$cert" ]; then
    export SSL_CERT_FILE="$cert"
    export GIT_SSL_CAINFO="$cert"
    echo "      Using cert bundle: $cert"
    break
  fi
done
flutter pub get
flutter build web --release --base-href="/"
echo "      Flutter Web built successfully."

echo ""
echo "[2/3] Building Go Core (static binary, no CGO)..."
GO_BIN="$WORKSPACE/identity-agent-core/bin/identity-agent-core"
cd "$WORKSPACE/identity-agent-core"
mkdir -p "$WORKSPACE/identity-agent-core/bin"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags="-s -w" -o "$GO_BIN" .
chmod +x "$GO_BIN"
echo "      Go Core built successfully."
ls -la "$GO_BIN"

echo ""
echo "[3/3] Build complete."
echo "      Flutter Web: $WORKSPACE/identity_agent_ui/build/web/"
echo "      Go Binary:   $GO_BIN"
echo "============================================"
