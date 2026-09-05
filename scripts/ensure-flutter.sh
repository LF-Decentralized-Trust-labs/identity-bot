#!/bin/sh
# Ensure a working Flutter SDK is available for deployment builds.
#
# The Nix-provided Flutter has a statically-linked BoringSSL that cannot
# validate pub.dev's TLS certificate in Replit's deployment builder (the
# builder's cert bundle is stale and the filesystem is read-only).
# This script detects the TLS issue and falls back to the official Flutter
# SDK from Google, which ships with its own working root certificates.
#
# This script is ONLY used by Replit build scripts. Local dev and other CI
# systems are unaffected.

FLUTTER_VERSION="3.41.4"
FLUTTER_CHANNEL="stable"
FLUTTER_CACHE="/tmp/flutter_sdk"

# Quick TLS health check: can flutter/dart reach pub.dev?
echo "      [flutter] Testing TLS to pub.dev..."
if flutter pub deps 2>&1 | grep -q "TLS error"; then
  TLS_OK=false
  echo "      [flutter] TLS FAILED with Nix Flutter — will use official SDK"
elif flutter pub deps >/dev/null 2>&1; then
  TLS_OK=true
  echo "      [flutter] TLS OK — using Nix Flutter"
else
  # Could be first run or other issue; check specifically for TLS
  if flutter pub get --dry-run 2>&1 | grep -qi "tls\|certificate\|ssl"; then
    TLS_OK=false
    echo "      [flutter] TLS FAILED with Nix Flutter — will use official SDK"
  else
    TLS_OK=true
    echo "      [flutter] Using Nix Flutter (no TLS issue detected)"
  fi
fi

if [ "$TLS_OK" = "true" ]; then
  return 0 2>/dev/null || exit 0
fi

# Download official Flutter SDK
if [ -x "$FLUTTER_CACHE/flutter/bin/flutter" ]; then
  echo "      [flutter] Official SDK already cached at $FLUTTER_CACHE"
else
  echo "      [flutter] Downloading Flutter $FLUTTER_VERSION ($FLUTTER_CHANNEL)..."
  ARCHIVE_URL="https://storage.googleapis.com/flutter_infra_release/releases/${FLUTTER_CHANNEL}/linux/flutter_linux_${FLUTTER_VERSION}-${FLUTTER_CHANNEL}.tar.xz"

  # Use the Nix cert for curl (curl uses OpenSSL, not BoringSSL, so this works)
  CURL_CERT_FLAG=""
  for cert in "$NIX_SSL_CERT_FILE" \
              /nix/store/*-nss-cacert-*/etc/ssl/certs/ca-bundle.crt \
              /etc/ssl/certs/ca-certificates.crt; do
    if [ -f "$cert" ]; then
      CURL_CERT_FLAG="--cacert $cert"
      break
    fi
  done

  mkdir -p "$FLUTTER_CACHE"
  if curl -L $CURL_CERT_FLAG -o /tmp/flutter_sdk.tar.xz "$ARCHIVE_URL"; then
    tar xf /tmp/flutter_sdk.tar.xz -C "$FLUTTER_CACHE"
    rm -f /tmp/flutter_sdk.tar.xz
    echo "      [flutter] Official SDK installed to $FLUTTER_CACHE/flutter"
  else
    echo "      [flutter] ERROR: Failed to download Flutter SDK"
    echo "      [flutter] URL: $ARCHIVE_URL"
    exit 1
  fi
fi

# Prepend official Flutter to PATH (overrides Nix flutter)
export PATH="$FLUTTER_CACHE/flutter/bin:$PATH"
echo "      [flutter] PATH updated — using: $(which flutter)"

# Suppress analytics and first-run banner
flutter config --no-analytics >/dev/null 2>&1 || true
