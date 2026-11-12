#!/usr/bin/env bash
#
# Probe: does a logged-in identity reopen after its core is killed, with nobody
# present, and does a logged-out one stay locked? (ADR-074 sections 1 and 2.)
#
# This runs the real core as a real process and kills it with SIGKILL, which is
# what an operating system does to a phone's app. It proves the core's own
# behaviour across a kill. It does NOT prove anything about a hardware key: it
# builds a development core, which on a machine with no platform wrapper holds
# the key unwrapped, and says so (hardware_layer false). The same steps on a
# real iOS or Android device, and on a Mac and a Windows PC, are what settle the
# per-platform claims in ADR-074 section 3.
#
#   scripts/probe-a-killed-core-reopens.sh
#
# LINUX ONLY. IDENTITY_AGENT_GATE_MODE=root-device is honoured only on Linux: a
# Mac or Windows core ignores it and is always a controller, whose log-in needs a
# voucher this script does not sign, so on a Mac it fails at "a passing log-in
# opens it". The portable version of the same kill and reopen, against a real
# child process killed by the operating system, is
# TestAKilledCoreReopensWhenLoggedInAndStaysLockedWhenNot in
# identity-agent-core/server, which runs on macOS, Linux and Windows.
#
# Exit 0 every step held; exit 1 one did not, and which is printed.
set -uo pipefail

if [ "$(uname -s)" != Linux ]; then
  echo "this probe runs on Linux only; on this OS run: go test -run TestAKilledCoreReopens ./identity-agent-core/server" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'kill "${pid:-0}" 2>/dev/null; rm -rf "$work"' EXIT
secret="probe-owner-secret-$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
port=$((20000 + RANDOM % 20000))

(cd "$root/identity-agent-core" && go build -ldflags "-X identity-agent-core/buildmode.rawMode=dev" -o "$work/core" .) || { echo "build failed"; exit 1; }

fail=0
start() {
  IDENTITY_AGENT_GATE_MODE=root-device IDENTITY_AGENT_LOCAL_OWNER_SECRET="$secret" AGENT_DATA_DIR="$work/profile-a" PORT="$port" "$work/core" >"$work/core.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 50); do
    curl -fs -H "X-Local-Owner-Secret: $secret" "http://127.0.0.1:$port/api/lock/state" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "the core did not come up"; cat "$work/core.log"; exit 1
}
api() { curl -s -H "X-Local-Owner-Secret: $secret" -H 'Content-Type: application/json' -X "$1" "http://127.0.0.1:$port$2" ${3:+-d "$3"}; }
state() { api GET /api/lock/state | python3 -c 'import sys,json; print(json.load(sys.stdin)["state"])'; }
expect() { # name got want
  if [ "$2" = "$3" ]; then printf '  ok    %s\n' "$1"; else printf '  FAIL  %s: got %s, want %s\n' "$1" "$2" "$3"; fail=1; fi
}
login() {
  api POST /api/lock/unlock "{\"profile\":\"profile-a\",\"level\":\"verified\",\"score\":80,\"at\":\"$(date -u +%FT%TZ)\",\"nonce\":\"probe-nonce-$RANDOM$RANDOM$RANDOM\"}" >/dev/null
}

start
expect "a new identity is open" "$(state)" open
kill -9 "$pid"; wait "$pid" 2>/dev/null
start
expect "killed while logged in, it reopens with nobody present" "$(state)" open
api POST /api/lock/lock >/dev/null
expect "after log-out it is locked" "$(state)" locked
kill -9 "$pid"; wait "$pid" 2>/dev/null
start
expect "killed while logged out, it stays locked" "$(state)" locked
expect "a locked core refuses an ordinary route" "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Local-Owner-Secret: $secret" "http://127.0.0.1:$port/api/identity")" 423
expect "an unlock with no owner proof is refused" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port/api/lock/unlock")" 403
expect "a locked core still answers the public health probe" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/api/health")" 200
login
expect "a passing log-in opens it" "$(state)" open
echo "  note  hardware_layer: $(api GET /api/lock/state | python3 -c 'import sys,json; print(json.load(sys.stdin)["hardware_layer"])') (false means this probe says nothing about a hardware key)"
exit $fail
