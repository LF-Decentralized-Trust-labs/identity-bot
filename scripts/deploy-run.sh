#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$WORKSPACE/identity-agent-core/bin/identity-agent-core"

if [ -f "$WORKSPACE/.sodium_lib_path" ]; then
    SODIUM_LIB=$(cat "$WORKSPACE/.sodium_lib_path")
    export LD_LIBRARY_PATH="${SODIUM_LIB}:${LD_LIBRARY_PATH}"
fi

export FLUTTER_WEB_DIR="$WORKSPACE/identity_agent_ui/build/web"
export KERI_DRIVER_SCRIPT="$WORKSPACE/drivers/keri-core/server.py"

exec "$BINARY"
