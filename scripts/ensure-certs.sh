#!/bin/sh
# Detect and export the TLS CA certificate bundle for Dart/Flutter pub.dev access.
# Nix environments store certs in the Nix store, not at standard Linux paths.
# The Dart VM's BoringSSL needs SSL_CERT_FILE to find them.

echo "      [cert] Detecting CA bundle..."

if [ -n "$SSL_CERT_FILE" ] && [ -f "$SSL_CERT_FILE" ]; then
  echo "      [cert] SSL_CERT_FILE already valid: $SSL_CERT_FILE"
  return 0 2>/dev/null || true
fi

CERT=""

# 1. Nix-provided cert bundle (preferred in Replit/Nix environments)
if [ -n "$NIX_SSL_CERT_FILE" ] && [ -f "$NIX_SSL_CERT_FILE" ]; then
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
  echo "      [cert] Using: $CERT"
else
  echo "      [cert] WARNING: No CA certificate bundle found"
  echo "      [cert] Attempting pub.dev without explicit cert (may fail)"
fi
