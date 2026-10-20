#!/usr/bin/env bash
# build-agent-host.sh — build agent-host, the program that makes a machine an AI
# agent's body, for this machine's operating system (macOS or Linux; Windows is
# build-agent-host.ps1).
#
#   bash scripts/build-agent-host.sh            # -> identity-agent-core/bin/agent-host
#
# On macOS the build links the Secure Enclave shim, exactly as the desktop
# backend does, so the machine key is held in the Secure Enclave. Built without
# it, agent-host still runs — on a key file, at the software grade — and says so
# when it enrols; this script refuses to produce that by accident.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="identity-agent-core/bin/agent-host"
mkdir -p identity-agent-core/bin

case "$(uname -s)" in
  Darwin)
    SEP_OUT="$(pwd)/identity-agent-core/build/sep"
    bash scripts/build-sep-shim.sh "$SEP_OUT"
    SEP_LDFLAGS="$(bash "$SEP_OUT/sep-ldflags.sh")"
    ( cd identity-agent-core
      CGO_ENABLED=1 CGO_LDFLAGS="$SEP_LDFLAGS" GOOS=darwin GOARCH=arm64 \
        go build -tags sepblob -o bin/agent-host-arm64 ./cmd/agent-host
      CGO_ENABLED=1 CGO_LDFLAGS="$SEP_LDFLAGS" GOOS=darwin GOARCH=amd64 \
        go build -tags sepblob -o bin/agent-host-amd64 ./cmd/agent-host )
    # The flags can be wrong and the build still succeed, leaving a binary with
    # no Secure Enclave code in it. Check each architecture's binary, as the
    # desktop build does, before combining them.
    bash "$SEP_OUT/sep-assert.sh" identity-agent-core/bin/agent-host-arm64 identity-agent-core/bin/agent-host-amd64
    lipo -create -output "$OUT" identity-agent-core/bin/agent-host-arm64 identity-agent-core/bin/agent-host-amd64
    rm -f identity-agent-core/bin/agent-host-arm64 identity-agent-core/bin/agent-host-amd64
    ;;
  Linux)
    ( cd identity-agent-core && CGO_ENABLED=0 go build -o bin/agent-host ./cmd/agent-host )
    ;;
  *)
    echo "build-agent-host.sh builds on macOS or Linux; on Windows run scripts/build-agent-host.ps1" >&2
    exit 1
    ;;
esac
echo "built $OUT"
