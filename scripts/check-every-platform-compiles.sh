#!/usr/bin/env bash
#
# Does the core still build for every platform it claims to?
#
# A runtime test cannot answer this. Which per-platform file is selected is a
# build-tag question, and the ways it goes wrong are invisible from inside a
# running program: two files matching one operating system, or none matching, or
# a file that stopped compiling on a platform nobody develops on. Each is a
# silent failure on the machine that is not in front of you.
#
# It matters most for where an identity may be founded, which is answered by one
# file per platform. A gap there is not a build error on the machine that has
# the gap — it is a machine that answers nothing, or answers twice.
#
#   scripts/check-every-platform-compiles.sh
#
# Exit 0  every platform builds
# Exit 1  one did not, and which is printed
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../identity-agent-core" || exit 1

FAILED=0

# iOS links against Apple frameworks, so it needs cgo — which is also how it is
# actually built. Everything else is checked without, which is how it ships.
check() {
  local os="$1" arch="$2" cgo="$3"
  printf '  %-8s %-6s ' "$os" "$arch"
  if CGO_ENABLED="$cgo" GOOS="$os" GOARCH="$arch" go vet ./... >/tmp/vet-$os.log 2>&1; then
    printf 'ok\n'
  else
    printf 'FAILED\n'
    sed 's/^/      /' /tmp/vet-$os.log | head -20
    FAILED=1
  fi
}

printf 'Building the core for every platform it claims to run on\n'
check darwin  arm64 1
check darwin  amd64 1
check windows amd64 0
check linux   amd64 0
check linux   arm64 0
check ios     arm64 1
check android arm64 0

if [ "$FAILED" -eq 1 ]; then
  printf '\nA platform this claims to support does not build.\n'
  exit 1
fi

printf '\nEvery platform builds.\n'
