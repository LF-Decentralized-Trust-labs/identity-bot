#!/bin/sh
# Detect and export the TLS CA certificate bundle for Dart/Flutter pub.dev access.
# Nix environments store certs in the Nix store, not at standard Linux paths.
# Dart's BoringSSL is statically linked and only checks hardcoded paths like
# /etc/ssl/certs/ca-certificates.crt — it ignores SSL_CERT_FILE and
# DART_VM_OPTIONS. The deployment builder may have an OUTDATED cert bundle
# at that path. We must overwrite it with the fresh Nix-provided certs.

echo "      [cert] Detecting CA bundle..."

NIX_CERT=""

# 1. Nix-provided cert bundle (preferred in Replit/Nix environments)
if [ -n "$NIX_SSL_CERT_FILE" ] && [ -f "$NIX_SSL_CERT_FILE" ]; then
  NIX_CERT="$NIX_SSL_CERT_FILE"
  echo "      [cert] Found via NIX_SSL_CERT_FILE"
fi

# 2. Nix store: use a fast glob instead of slow find
if [ -z "$NIX_CERT" ]; then
  for f in /nix/store/*-nss-cacert-*/etc/ssl/certs/ca-bundle.crt; do
    if [ -f "$f" ]; then
      NIX_CERT="$f"
      echo "      [cert] Found via Nix store glob"
      break
    fi
  done
fi

# If we found a Nix cert, ALWAYS overwrite the standard path.
# The deployment builder's existing cert bundle may be outdated and unable
# to validate pub.dev's certificate chain.
STANDARD_CERT="/etc/ssl/certs/ca-certificates.crt"
if [ -n "$NIX_CERT" ]; then
  echo "      [cert] Nix cert: $NIX_CERT"
  mkdir -p /etc/ssl/certs 2>/dev/null
  if cp -f "$NIX_CERT" "$STANDARD_CERT" 2>/dev/null; then
    echo "      [cert] Overwrote $STANDARD_CERT with Nix cert bundle"
  elif ln -sf "$NIX_CERT" "$STANDARD_CERT" 2>/dev/null; then
    echo "      [cert] Symlinked $STANDARD_CERT -> Nix cert bundle"
  else
    echo "      [cert] WARNING: Cannot write to $STANDARD_CERT (no permissions)"
    echo "      [cert] Dart may use an outdated cert bundle and fail TLS"
  fi
  export SSL_CERT_FILE="$NIX_CERT"
  export GIT_SSL_CAINFO="$NIX_CERT"
  echo "      [cert] SSL_CERT_FILE=$NIX_CERT"
elif [ -f "$STANDARD_CERT" ]; then
  echo "      [cert] Using existing: $STANDARD_CERT"
  export SSL_CERT_FILE="$STANDARD_CERT"
  export GIT_SSL_CAINFO="$STANDARD_CERT"
else
  # Check other standard paths
  for p in /etc/ssl/certs/ca-bundle.crt \
           /etc/pki/tls/certs/ca-bundle.crt; do
    if [ -f "$p" ]; then
      export SSL_CERT_FILE="$p"
      export GIT_SSL_CAINFO="$p"
      echo "      [cert] Using: $p"
      return 0 2>/dev/null || true
    fi
  done
  echo "      [cert] WARNING: No CA certificate bundle found"
fi
