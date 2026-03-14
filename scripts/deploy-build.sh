#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================"
echo " IDENTITY AGENT - Deployment Build"
echo "============================================"

echo ""
echo "[1/4] Installing Python dependencies..."
if pip install -q flask keri 2>/dev/null; then
    echo "      Python dependencies installed via pip."
elif pip3 install -q flask keri 2>/dev/null; then
    echo "      Python dependencies installed via pip3."
else
    echo "      ERROR: Failed to install Python dependencies (flask, keri)."
    echo "      The KERI driver requires these packages to function."
    exit 1
fi
python3 -c "import flask; import keri" 2>/dev/null || {
    echo "      ERROR: Python dependency verification failed."
    exit 1
}
echo "      Python dependencies verified."

echo ""
echo "[2/4] Building Flutter Web..."
cd "$WORKSPACE/identity_agent_ui"
# Ensure TLS certs are available for pub.dev (critical in Nix/Replit environments)
. "$SCRIPT_DIR/ensure-certs.sh"
flutter pub get
flutter build web --release --base-href="/"
echo "      Flutter Web built successfully."

echo ""
echo "[3/4] Building Go Core (static binary, no CGO)..."
GO_BIN="$WORKSPACE/identity-agent-core/bin/identity-agent-core"
cd "$WORKSPACE/identity-agent-core"
mkdir -p "$WORKSPACE/identity-agent-core/bin"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags="-s -w" -o "$GO_BIN" .
chmod +x "$GO_BIN"
echo "      Go Core built successfully."
ls -la "$GO_BIN"

echo ""
echo "[4/4] Detecting libsodium..."
SODIUM_LIB=$(python3 -c "
import ctypes, os
for so_name in ['libsodium.so.26', 'libsodium.so.23', 'libsodium.so']:
    try:
        ctypes.CDLL(so_name)
        for line in open(f'/proc/{os.getpid()}/maps'):
            if 'sodium' in line:
                parts = line.strip().split()
                if len(parts) >= 6:
                    print(os.path.dirname(parts[-1]))
                    raise SystemExit(0)
        break
    except OSError:
        continue
" 2>/dev/null) || true
if [ -n "$SODIUM_LIB" ]; then
    echo "      libsodium: $SODIUM_LIB"
    echo "$SODIUM_LIB" > "$WORKSPACE/.sodium_lib_path"
else
    echo "      libsodium: using system default"
fi

echo ""
echo "============================================"
echo " Build complete."
echo "      Flutter Web: $WORKSPACE/identity_agent_ui/build/web/"
echo "      Go Binary:   $GO_BIN"
echo "============================================"
