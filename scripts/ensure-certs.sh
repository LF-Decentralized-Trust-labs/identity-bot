#!/bin/sh
# Detect and export the TLS CA certificate bundle for Dart/Flutter pub.dev access.
# Nix environments store certs in the Nix store, not at standard Linux paths.
# The Dart VM's BoringSSL needs SSL_CERT_FILE to find them.
#
# IMPORTANT: DART_VM_OPTIONS="--root-certs-file=..." only applies to the
# top-level Dart VM. `flutter pub get` spawns a SEPARATE dart subprocess
# that does NOT inherit VM flags. So we also symlink the cert bundle to
# /etc/ssl/certs/ca-certificates.crt (the path Dart's BoringSSL checks
# on Linux) as the most reliable fix for Nix environments.

echo "      [cert] Detecting CA bundle..."

CERT=""

# Check if SSL_CERT_FILE is already valid
if [ -n "$SSL_CERT_FILE" ] && [ -f "$SSL_CERT_FILE" ]; then
  CERT="$SSL_CERT_FILE"
  echo "      [cert] SSL_CERT_FILE already valid: $CERT"
fi

# 1. Nix-provided cert bundle (preferred in Replit/Nix environments)
if [ -z "$CERT" ] && [ -n "$NIX_SSL_CERT_FILE" ] && [ -f "$NIX_SSL_CERT_FILE" ]; then
  CERT="$NIX_SSL_CERT_FILE"
  echo "      [cert] Found via NIX_SSL_CERT_FILE"
fi

# 2. Nix store: use a fast glob instead of slow find
if [ -z "$CERT" ]; then
  for f in /nix/store/*-nss-cacert-*/etc/ssl/certs/ca-bundle.crt; do
    if [ -f "$f" ]; then
      CERT="$f"
      echo "      [cert] Found via Nix store glob"
      break
    fi
  done
fi

# 3. Standard Linux paths (non-Nix)
if [ -z "$CERT" ]; then
  for p in /etc/ssl/certs/ca-certificates.crt \
           /etc/ssl/certs/ca-bundle.crt \
           /etc/pki/tls/certs/ca-bundle.crt; do
    if [ -f "$p" ]; then
      CERT="$p"
      echo "      [cert] Found at standard path"
      break
    fi
  done
fi

if [ -n "$CERT" ]; then
  export SSL_CERT_FILE="$CERT"
  export GIT_SSL_CAINFO="$CERT"

  # Place the cert where Dart's BoringSSL looks on Linux.
  # This is the only reliable way to fix TLS in Nix-built Dart because:
  # - SSL_CERT_FILE is ignored by the statically-linked BoringSSL
  # - DART_VM_OPTIONS only affects the top-level process, not subprocesses
  # - flutter pub get spawns dart pub as a separate process
  STANDARD_CERT="/etc/ssl/certs/ca-certificates.crt"
  if [ ! -f "$STANDARD_CERT" ]; then
    mkdir -p /etc/ssl/certs 2>/dev/null
    if ln -sf "$CERT" "$STANDARD_CERT" 2>/dev/null; then
      echo "      [cert] Symlinked to $STANDARD_CERT"
    elif cp "$CERT" "$STANDARD_CERT" 2>/dev/null; then
      echo "      [cert] Copied to $STANDARD_CERT"
    else
      echo "      [cert] WARNING: Cannot write to $STANDARD_CERT (no permissions)"
    fi
  fi

  echo "      [cert] Using: $CERT"
else
  echo "      [cert] WARNING: No CA certificate bundle found"
  echo "      [cert] Attempting pub.dev without explicit cert (may fail)"
fi
