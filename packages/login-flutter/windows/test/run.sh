#!/usr/bin/env bash
# Runs the Windows front end's TPM code against a software TPM (the reference
# implementation of the TPM 2.0 library) and checks what it makes with the
# Identity Agent's own verifier. Needs a C++17 compiler, Go, and OpenSSL
# headers (the simulator is C: pass CGO_CFLAGS / CGO_LDFLAGS if they are not
# on the default path). See the driver's header for what this does and does not show.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
g++ -std=c++17 -Wall -Wextra -O1 "$here/tpm2_cli.cpp" "$here/../tpm2.cpp" -o "$out/tpm2_cli"
cd "$here/../../../../identity-agent-core/secureenclave/testdata/tpmsim"
GOFLAGS=-mod=mod go run ./driver -cli "$out/tpm2_cli"
