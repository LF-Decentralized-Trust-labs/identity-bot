#!/usr/bin/env bash
#
# Build + bundle the Identity Agent macOS desktop .app (UNSIGNED).
#
# The build/bundle steps for a macOS release. Signing, notarization and DMG
# packaging are handled separately (sign-notarize-macos.sh) so this build runs
# green even before the Apple signing secrets are configured.
#
# The CALLER installs the toolchain first:
#   - Go 1.24.0
#   - Flutter 3.27.3
#
# Env:
#   BUILD_NUMBER  optional build number (defaults to 0)
#
# Output: a built .app at
#   identity_agent_ui/build/macos/Build/Products/Release/Identity Agent.app
set -euo pipefail

BUILD_NUMBER="${BUILD_NUMBER:-0}"

# MODE selects the build realm (dev or prod). Prod is the default and is safe: it
# trusts only the production software-update key and keeps every fail-closed gate
# closed. MODE=dev injects the development build-mode constant (the buildmode
# package), so the core trusts the development keys, reports itself a development
# build on /api/health, and relaxes the gates that would otherwise refuse a
# machine that cannot attest. A dev build must never be shipped to a user. See
# docs/adr/043-developer-mode-roots-in-a-separate-trust-anchor.md.
MODE="${MODE:-prod}"
MODE_LDFLAGS=""
case "$MODE" in
  prod) ;;
  dev)  MODE_LDFLAGS="-X identity-agent-core/buildmode.rawMode=dev"
        echo "  MODE=dev — DEVELOPMENT build, not for production" ;;
  *)    echo "  ERROR: MODE must be 'dev' or 'prod' (got '$MODE')" >&2; exit 1 ;;
esac

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
    go build -tags sepblob -ldflags "$MODE_LDFLAGS" -o bin/identity-agent-core-arm64 .
  CGO_ENABLED=1 CGO_LDFLAGS="$SEP_LDFLAGS" GOOS=darwin GOARCH=amd64 \
    go build -tags sepblob -ldflags "$MODE_LDFLAGS" -o bin/identity-agent-core-amd64 .
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

# The KERI engine (keri-go) is compiled into identity-agent-core, so bundling the
# Go backend is all that is needed to establish and run an identity. There is no
# Python involved: keri-go runs in-process and is the only KERI engine.
echo "--- Bundle Go backend into .app ---"
APP="identity_agent_ui/build/macos/Build/Products/Release/Identity Agent.app"
RESOURCES="$APP/Contents/Resources"
mkdir -p "$RESOURCES/backend/bin"
cp identity-agent-core/bin/identity-agent-core "$RESOURCES/backend/"
cp -r manifests "$RESOURCES/backend/manifests"
chmod +x "$RESOURCES/backend/identity-agent-core"
echo "Building go-demo sandbox app..."
( cd sandbox-apps/go-demo
  CGO_ENABLED=0 go build -buildvcs=false -ldflags="-s -w" -o "../../$RESOURCES/backend/bin/go-demo" . )
chmod +x "$RESOURCES/backend/bin/go-demo"
ls -la "$RESOURCES/backend/"
