#!/usr/bin/env bash
#
# Build + bundle the Identity Agent Linux desktop release.
#
# The build steps for a Linux release, kept as a script so CI and a developer run
# the same logic. The CALLER is responsible for installing the toolchain first:
#   - Go 1.24.0
#   - Flutter 3.27.3
#   - GTK/build system deps: clang cmake ninja-build pkg-config libgtk-3-dev
#     liblzma-dev libstdc++-12-dev libsecret-1-dev
#
# Env:
#   BUILD_NUMBER  optional build number (defaults to 0)
#
# Output: identity-agent-linux-x64.tar.gz in the repo root.
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

echo "--- Build Go backend (Linux) ---"
( cd identity-agent-core
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$MODE_LDFLAGS" -o bin/identity-agent-core .
  file bin/identity-agent-core
  ls -lh bin/identity-agent-core )

echo "--- Get Flutter packages ---"
( cd identity_agent_ui && flutter pub get )

echo "--- Build Flutter Linux app ---"
( cd identity_agent_ui && flutter build linux --release --build-number="$BUILD_NUMBER" )

# The KERI engine (keri-go) is compiled into identity-agent-core, so bundling the
# Go backend is all that is needed to establish and run an identity. There is no
# Python involved: keri-go runs in-process and is the only KERI engine.
echo "--- Bundle Go backend with Flutter app ---"
BUNDLE="identity_agent_ui/build/linux/x64/release/bundle"
mkdir -p "$BUNDLE/backend/bin"
cp identity-agent-core/bin/identity-agent-core "$BUNDLE/backend/"
cp -r manifests "$BUNDLE/backend/manifests"
chmod +x "$BUNDLE/backend/identity-agent-core"
echo "Building go-demo sandbox app..."
( cd sandbox-apps/go-demo
  CGO_ENABLED=0 go build -buildvcs=false -ldflags="-s -w" -o "../../$BUNDLE/backend/bin/go-demo" . )
chmod +x "$BUNDLE/backend/bin/go-demo"
echo "--- Bundle contents ---"
ls -la "$BUNDLE/backend/"

echo "--- Create tarball archive ---"
tar -czf identity-agent-linux-x64.tar.gz -C "$BUNDLE" .
ls -lh identity-agent-linux-x64.tar.gz
