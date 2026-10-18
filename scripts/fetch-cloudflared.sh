#!/usr/bin/env bash
#
# Fetch a pinned cloudflared binary for a target OS/arch into an output path.
#
# An Identity Agent founds before it has an identity, and the only address it can
# be reached at that early is a Cloudflare quick tunnel — which needs cloudflared
# present. A desktop app launched from the GUI has no cloudflared on its PATH, so
# the desktop builds bundle it beside the backend binary, where the core's tunnel
# lookup now searches (see identity-agent-core/tunnel/manager.go searchDirs).
#
# Usage: fetch-cloudflared.sh <darwin|linux> <arm64|amd64|universal> <out-path>
#   CLOUDFLARED_VERSION  the pinned release (default below)
#   CLOUDFLARED_CACHE    download cache dir (default ~/.cache/cloudflared-bundle)
#
# Windows builds fetch cloudflared-windows-amd64.exe directly in PowerShell; this
# script covers the two POSIX desktops.
set -euo pipefail

CLOUDFLARED_VERSION="${CLOUDFLARED_VERSION:-2026.6.1}"
OS="${1:?usage: fetch-cloudflared.sh <darwin|linux> <arm64|amd64|universal> <out-path>}"
ARCH="${2:?missing arch}"
OUT="${3:?missing out-path}"

BASE="https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}"
CACHE="${CLOUDFLARED_CACHE:-$HOME/.cache/cloudflared-bundle}/${CLOUDFLARED_VERSION}"
mkdir -p "$CACHE" "$(dirname "$OUT")"

# fetch_one <os> <arch> <dest>: download (and extract, for darwin .tgz) one binary.
fetch_one() {
  local os="$1" arch="$2" dest="$3" asset
  case "$os" in
    darwin) asset="cloudflared-darwin-${arch}.tgz" ;;
    linux)  asset="cloudflared-linux-${arch}" ;;
    *) echo "ERROR: unsupported OS '$os' (darwin|linux)" >&2; exit 1 ;;
  esac
  local cached="$CACHE/$asset"
  if [ ! -s "$cached" ]; then
    echo "  downloading $asset ($CLOUDFLARED_VERSION)"
    curl -fsSL -o "$cached.part" "$BASE/$asset"
    mv "$cached.part" "$cached"
  fi
  if [[ "$asset" == *.tgz ]]; then
    local td; td="$(mktemp -d)"
    tar -xzf "$cached" -C "$td" cloudflared
    mv "$td/cloudflared" "$dest"
    rm -rf "$td"
  else
    cp "$cached" "$dest"
  fi
  chmod +x "$dest"
}

if [ "$OS" = "darwin" ] && [ "$ARCH" = "universal" ]; then
  tmp="$(mktemp -d)"
  fetch_one darwin arm64 "$tmp/cf-arm64"
  fetch_one darwin amd64 "$tmp/cf-amd64"
  lipo -create -output "$OUT" "$tmp/cf-arm64" "$tmp/cf-amd64"
  chmod +x "$OUT"
  rm -rf "$tmp"
else
  fetch_one "$OS" "$ARCH" "$OUT"
fi

echo "cloudflared $CLOUDFLARED_VERSION ($OS/$ARCH) -> $OUT ($(ls -lh "$OUT" | awk '{print $5}'))"
