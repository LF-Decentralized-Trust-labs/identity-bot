#!/usr/bin/env bash
#
# Build + bundle the Identity Agent macOS desktop .app (UNSIGNED).
#
# Mirrors the build/bundle steps of the `macos-release` workflow in
# codemagic.yaml. Signing, notarization and DMG packaging are handled
# separately (sign-notarize-macos.sh) so this build runs green even before
# the Apple signing secrets are configured.
#
# The CALLER installs the toolchain first:
#   - Go 1.24.0
#   - Flutter 3.27.3
#   - Python 3.11 (for pip3)
#
# Env:
#   BUILD_NUMBER  optional build number (defaults to 0)
#
# Output: a built .app at
#   identity_agent_ui/build/macos/Build/Products/Release/Identity Agent.app
set -euo pipefail

BUILD_NUMBER="${BUILD_NUMBER:-0}"

echo "--- Build Go backend (macOS universal) ---"
( cd identity-agent-core
  # CGO_ENABLED=1, and it is load-bearing rather than incidental.
  #
  # Three files in secureenclave are tagged `darwin && cgo`: the Secure Enclave
  # signer, the seed wrapping, and the key-protection detector. Built with cgo
  # off, none of them is compiled in — so the shipped app fell through to the
  # software signer and answered "we have not looked" about its own hardware,
  # on a machine with a Secure Enclave, while `go test` on the same source said
  # `usable`. The tests and the thing users install were different programs.
  #
  # Verify with: CGO_ENABLED=0 go list -f '{{.CgoFiles}}' ./secureenclave
  CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o bin/identity-agent-core-arm64 .
  CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o bin/identity-agent-core-amd64 .
  lipo -create -output bin/identity-agent-core bin/identity-agent-core-arm64 bin/identity-agent-core-amd64
  file bin/identity-agent-core
  ls -lh bin/identity-agent-core )

echo "--- Get Flutter packages ---"
( cd identity_agent_ui && flutter pub get )

echo "--- Build Flutter macOS app ---"
( cd identity_agent_ui && flutter build macos --release --build-number="$BUILD_NUMBER" )

echo "--- Bundle Go backend and KERI driver into .app ---"
APP="identity_agent_ui/build/macos/Build/Products/Release/Identity Agent.app"
RESOURCES="$APP/Contents/Resources"
mkdir -p "$RESOURCES/backend/bin"
cp identity-agent-core/bin/identity-agent-core "$RESOURCES/backend/"
cp -r drivers/keri-core "$RESOURCES/backend/keri-driver"
cp -r manifests "$RESOURCES/backend/manifests"
chmod +x "$RESOURCES/backend/identity-agent-core"
echo "Building go-demo sandbox app..."
( cd sandbox-apps/go-demo
  CGO_ENABLED=0 go build -buildvcs=false -ldflags="-s -w" -o "../../$RESOURCES/backend/bin/go-demo" . )
chmod +x "$RESOURCES/backend/bin/go-demo"
ls -la "$RESOURCES/backend/"

echo "--- Bundle Python packages (macOS) ---"
PKG_DIR="$RESOURCES/backend/python-packages"
pip3 install --target="$PKG_DIR" flask keri==1.1.17
PYTHONPATH="$PKG_DIR" python3 -c "import flask; import keri; print('flask:', flask.__version__); print('keri:', keri.__version__)"
find "$PKG_DIR" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
du -sh "$PKG_DIR"
