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

echo "--- Build the Secure Enclave shim ---"
# WITHOUT THIS THE ENCLAVE CODE SHIPS IN NOTHING, which is the failure this
# whole area keeps producing: the capability is written, proven on hardware, and
# then reaches no artifact because no build script asks for it.
#
# Only CryptoKit exposes the enclave's wrapped key blob and cgo cannot compile
# Swift, so the Swift becomes a static library the core links under a build tag.
# The tag is what selects the signer that can actually keep a key; without it the
# core falls back to the keychain path, which needs an entitlement a bare helper
# cannot carry and therefore refuses.
SEP_OUT="$(pwd)/identity-agent-core/build/sep"
bash scripts/build-sep-shim.sh "$SEP_OUT"
SEP_LDFLAGS="$(bash "$SEP_OUT/sep-ldflags.sh")"

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
  # MACOSX_DEPLOYMENT_TARGET is set because cgo forces external linking, and the
  # system linker otherwise stamps the binary with the OS of whatever machine
  # built it — so a build box running a new macOS produced a binary claiming to
  # need one.
  export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-12.0}"
  CGO_ENABLED=1 CGO_LDFLAGS="$SEP_LDFLAGS" GOOS=darwin GOARCH=arm64 \
    go build -tags sepblob -o bin/identity-agent-core-arm64 .
  CGO_ENABLED=1 CGO_LDFLAGS="$SEP_LDFLAGS" GOOS=darwin GOARCH=amd64 \
    go build -tags sepblob -o bin/identity-agent-core-amd64 .
  lipo -create -output bin/identity-agent-core bin/identity-agent-core-arm64 bin/identity-agent-core-amd64
  file bin/identity-agent-core
  ls -lh bin/identity-agent-core

  # ASKED OF THE BINARY, NOT OF THE BUILD. Every other way this has gone wrong
  # was invisible in a green build: cgo off compiled the enclave out, and the tag
  # unpassed selected a signer that refuses. Both produced a perfectly good
  # binary that could not keep a key, and nothing said so until somebody used it.
  #
  # Combining CGO_ENABLED=0 with the tag still exits zero, so the flags are not
  # the thing to check — the symbol is. The check itself lives beside the shim,
  # so every build path that produces a macOS core asks the same question, and
  # this was already wrong in the copy that lived here: nm piped into `grep -q`
  # dies of SIGPIPE under pipefail and fails a correct binary, depending on
  # where the symbol lands in nm's output.
  bash "$SEP_OUT/sep-assert.sh" bin/identity-agent-core-arm64 bin/identity-agent-core-amd64
  echo "  enclave signer present in both slices" )

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
