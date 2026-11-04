#!/usr/bin/env bash
# join-the-core.sh — the one way an app's Go module is joined to the core.
#
# The core is the module `identity-agent-core` plus the modules its own go.mod
# replaces onto sub-directories (today relayproto and witnessproto). The core
# owns that list, so it is read from the core's go.mod here and written nowhere
# else: a new core module, or a moved path, changes the core's go.mod and every
# app picks it up. An app never names a core module itself.
#
#   join-the-core.sh work CORE OUT APP_DIR [MODULE=PATH ...]
#       Write a go.work at OUT that uses APP_DIR and replaces the core and its
#       modules with the checkout at CORE (the directory holding the core's
#       go.mod). Build with GOWORK=OUT. Each MODULE=PATH adds the app's own
#       replace (its add-ons, say) after the core's. Used by Individual.
#
#   join-the-core.sh gomod GOMOD CORE_REL [--check] [MODULE=PATH ...]
#       Make the replace directives in GOMOD (an app's go.mod) the core's, with
#       CORE_REL the core checkout as a path from GOMOD's directory. They are
#       kept in one marked block; any other replace of a module the block owns
#       is removed so a stale one cannot shadow it. With --check nothing is
#       written: exit 1 if GOMOD differs from what would be written. Used by
#       Organization, and --check by release-pipeline before it builds it.
#
# Paths are written as bash sees them (Git Bash on Windows included); a caller
# that hands the result to go.exe converts them, as release-pipeline's
# build-individual-backend.sh does for the go.work.
set -euo pipefail

CORE_MODULE="identity-agent-core"
BEGIN="// BEGIN join-the-core: written by identity-bot/scripts/join-the-core.sh, do not edit"
END="// END join-the-core"

die() { echo "join-the-core: $*" >&2; exit 1; }

# core_replaces COREDIR PREFIX — "module => PREFIX/relative" for the core itself
# and for every module the core's go.mod replaces onto a directory under it.
core_replaces() {
  local core="$1" prefix="$2"
  [ -f "$core/go.mod" ] || die "no core at $core (no go.mod)"
  [ "$(awk '/^module /{print $2; exit}' "$core/go.mod")" = "$CORE_MODULE" ] ||
    die "$core/go.mod is not the module $CORE_MODULE"
  printf '%s => %s\n' "$CORE_MODULE" "$prefix"
  awk -v p="$prefix" '
    $1 == "replace" && $3 == "=>" && $4 ~ /^\.\// { sub(/^\.\//, "", $4); printf "%s => %s/%s\n", $2, p, $4 }
  ' "$core/go.mod"
}

# with_extras COREDIR PREFIX [MODULE=PATH ...] — core replaces, then the app's.
with_extras() {
  local core="$1" prefix="$2"; shift 2
  core_replaces "$core" "$prefix"
  local e
  for e in "$@"; do
    case "$e" in *=*) printf '%s => %s\n' "${e%%=*}" "${e#*=}" ;; *) die "expected MODULE=PATH, got '$e'" ;; esac
  done
}

mode="${1:-}"; [ $# -gt 0 ] && shift
case "$mode" in
work)
  [ $# -ge 3 ] || die "usage: join-the-core.sh work CORE OUT APP_DIR [MODULE=PATH ...]"
  CORE="$(cd "$1" && pwd)"; OUT="$2"; APP="$3"; shift 3
  GOVERSION="$(awk '/^go /{print $2; exit}' "$CORE/go.mod")"
  {
    printf 'go %s\n\nuse %s\n\n' "$GOVERSION" "$APP"
    with_extras "$CORE" "$CORE" "$@" | sed 's/^/replace /'
  } > "$OUT"
  ;;
gomod)
  [ $# -ge 2 ] || die "usage: join-the-core.sh gomod GOMOD CORE_REL [--check] [MODULE=PATH ...]"
  GOMOD="$1"; REL="$2"; shift 2
  check=0; extras=()
  for a in "$@"; do if [ "$a" = "--check" ]; then check=1; else extras+=("$a"); fi; done
  [ -f "$GOMOD" ] || die "no go.mod at $GOMOD"
  CORE="$(cd "$(dirname "$GOMOD")/$REL" && pwd)" || die "no core at $(dirname "$GOMOD")/$REL"
  lines="$(with_extras "$CORE" "${REL%/}" ${extras[@]+"${extras[@]}"})"
  mods="$(printf '%s\n' "$lines" | awk '{print $1}')"
  tmp="$(mktemp)"; trap 'rm -f "$tmp" "$tmp.new"' EXIT
  # Drop the old block and any lone replace of a module the block now owns,
  # squeeze blank runs, drop trailing blanks; then append the block.
  awk -v mods="$mods" -v begin="$BEGIN" -v end="$END" '
    BEGIN { n = split(mods, m, "\n"); for (i = 1; i <= n; i++) own[m[i]] = 1 }
    $0 == begin { skip = 1; next }
    skip { if ($0 == end) skip = 0; next }
    $1 == "replace" && ($2 in own) { next }
    /^[ \t]*$/ { blank++; next }
    { if (blank > 0 && started) print ""; blank = 0; started = 1; print }
  ' "$GOMOD" > "$tmp"
  {
    cat "$tmp"; printf '\n%s\n' "$BEGIN"
    printf '%s\n' "$lines" | sed 's/^/replace /'
    printf '%s\n' "$END"
  } > "$tmp.new"; mv "$tmp.new" "$tmp"
  if [ "$check" = 1 ]; then
    cmp -s "$tmp" "$GOMOD" || {
      echo "join-the-core: $GOMOD does not join the core as the core says it should:" >&2
      diff -u "$GOMOD" "$tmp" >&2 || true
      echo "  fix: bash <core>/scripts/join-the-core.sh gomod $GOMOD $REL" >&2
      exit 1
    }
  else
    cmp -s "$tmp" "$GOMOD" || cp "$tmp" "$GOMOD"
  fi
  ;;
*) die "usage: join-the-core.sh work|gomod ..." ;;
esac
