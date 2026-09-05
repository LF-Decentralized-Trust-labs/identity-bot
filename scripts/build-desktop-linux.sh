#!/usr/bin/env bash
#
# Build + bundle the Identity Agent Linux desktop release.
#
# The build steps for a Linux release, kept as a script so CI and a developer run
# the same logic. The CALLER is responsible for installing the toolchain first:
#   - Go 1.24.0
#   - Flutter 3.27.3
#   - Python 3.11 (for pip3)
#   - GTK/build system deps: clang cmake ninja-build pkg-config libgtk-3-dev
#     liblzma-dev libstdc++-12-dev libsecret-1-dev
#
# Env:
#   BUILD_NUMBER  optional build number (defaults to 0)
#
# Output: identity-agent-linux-x64.tar.gz in the repo root.
set -euo pipefail

BUILD_NUMBER="${BUILD_NUMBER:-0}"

echo "--- Build Go backend (Linux) ---"
( cd identity-agent-core
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/identity-agent-core .
  file bin/identity-agent-core
  ls -lh bin/identity-agent-core )

echo "--- Get Flutter packages ---"
( cd identity_agent_ui && flutter pub get )

echo "--- Build Flutter Linux app ---"
( cd identity_agent_ui && flutter build linux --release --build-number="$BUILD_NUMBER" )

echo "--- Bundle Go backend and KERI driver with Flutter app ---"
BUNDLE="identity_agent_ui/build/linux/x64/release/bundle"
mkdir -p "$BUNDLE/backend/bin"
cp identity-agent-core/bin/identity-agent-core "$BUNDLE/backend/"
cp -r drivers/keri-core "$BUNDLE/backend/keri-driver"
cp -r manifests "$BUNDLE/backend/manifests"
chmod +x "$BUNDLE/backend/identity-agent-core"
echo "Building go-demo sandbox app..."
( cd sandbox-apps/go-demo
  CGO_ENABLED=0 go build -buildvcs=false -ldflags="-s -w" -o "../../$BUNDLE/backend/bin/go-demo" . )
chmod +x "$BUNDLE/backend/bin/go-demo"
echo "--- Bundle contents ---"
ls -la "$BUNDLE/backend/"

echo "--- Bundle Python packages (Linux) ---"
PKG_DIR="$BUNDLE/backend/python-packages"
pip3 install --target="$PKG_DIR" flask keri==1.1.17
PYTHONPATH="$PKG_DIR" python3 -c "import flask; import keri; print('flask:', flask.__version__); print('keri:', keri.__version__)"
find "$PKG_DIR" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
du -sh "$PKG_DIR"

echo "--- Create tarball archive ---"
tar -czf identity-agent-linux-x64.tar.gz -C "$BUNDLE" .
ls -lh identity-agent-linux-x64.tar.gz
