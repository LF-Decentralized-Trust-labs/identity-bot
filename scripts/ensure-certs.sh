#!/bin/sh
# Detect and export the TLS CA certificate bundle for Dart/Flutter pub.dev access.
# Nix environments store certs in the Nix store, not at standard Linux paths.
# The Dart VM's BoringSSL needs SSL_CERT_FILE to find them.

if [ -n "$SSL_CERT_FILE" ] && [ -f "$SSL_CERT_FILE" ]; then
  # Already set and valid — nothing to do
  return 0 2>/dev/null || true
fi

CERT=""

# 1. Nix-provided cert bundle (preferred in Replit/Nix environments)
if [ -z "$CERT" ] && [ -n "$NIX_SSL_CERT_FILE" ] && [ -f "$NIX_SSL_CERT_FILE" ]; then
  CERT="$NIX_SSL_CERT_FILE"
fi

# 2. Search the Nix store for cacert bundle
if [ -z "$CERT" ]; then
  CERT=$(find /nix/store -maxdepth 4 -name 'ca-bundle.crt' -path '*/etc/ssl/certs/*' 2>/dev/null | head -1)
fi

# 3. Standard Linux paths (non-Nix)
if [ -z "$CERT" ]; then
  for p in /etc/ssl/certs/ca-certificates.crt \
           /etc/ssl/certs/ca-bundle.crt \
           /etc/pki/tls/certs/ca-bundle.crt; do
    [ -f "$p" ] && CERT="$p" && break
  done
fi

if [ -n "$CERT" ]; then
  export SSL_CERT_FILE="$CERT"
  export GIT_SSL_CAINFO="$CERT"
  echo "      TLS cert bundle: $CERT"
else
  echo "      WARNING: No CA certificate bundle found — pub.dev TLS may fail"
fi
