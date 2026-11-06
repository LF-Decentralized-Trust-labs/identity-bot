#!/usr/bin/env bash
#
# Sign the core binary a desktop app bundles, and print its SHA-256.
#
# An app runs its bundled core as `keymath` only when the binary is the one it
# was built with and is signed by the app's own signer (ADR-061, section 7;
# agent_client's TheCoresKeyMath). So a build signs the core FIRST, builds the
# app with the hash this prints as
#   --dart-define=IDENTITY_AGENT_CORE_SHA256=<hash>
# then bundles the binary unchanged and signs the app around it, with the same
# identity, never signing the binary again: that would change its bytes.
#
# Usage: sign-the-core-for-an-app.sh <binary>
#   SIGN_IDENTITY  the codesign identity. Default: the first Apple Development
#                  identity in the keychain. "-" signs ad-hoc, which names no
#                  team, so an app built that way signs no key events; it is
#                  said so on standard error.
#
# Prints the hash alone on standard output; everything else goes to standard
# error. macOS only: a Windows build signs with signtool and hashes the signed
# .exe the same way, in the order above.
set -euo pipefail

BIN="${1:?usage: sign-the-core-for-an-app.sh <binary>}"
[ -f "$BIN" ] || { echo "sign-the-core-for-an-app: no binary at $BIN" >&2; exit 1; }
[ "$(uname -s)" = "Darwin" ] || { echo "sign-the-core-for-an-app: macOS only (see the header for Windows)" >&2; exit 1; }

IDENTITY="${SIGN_IDENTITY:-}"
if [ -z "$IDENTITY" ]; then
  IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null |
    sed -n 's/.*"\(Apple Development: [^"]*\)".*/\1/p' | head -1)"
fi
if [ -z "$IDENTITY" ] || [ "$IDENTITY" = "-" ]; then
  IDENTITY="-"
  echo "WARNING: signing the core ad-hoc. An app built with it signs no key events:" >&2
  echo "         it runs no core that a team did not sign. Set SIGN_IDENTITY." >&2
fi

codesign --force --sign "$IDENTITY" "$BIN" >&2
codesign --verify --strict "$BIN" >&2
shasum -a 256 "$BIN" | awk '{print $1}'
