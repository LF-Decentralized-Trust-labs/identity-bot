#!/usr/bin/env bash
# Fails if the image root in $1 could change itself after it was built.
#
# A sealed image is measured: the number a verifier checks says "this exact image, unmodified". Anything in the
# image that installs updates in place, or restarts services behind the agent, makes that number stop describing the
# machine, and an update must arrive as a new measured image instead. Debian's minbase does not carry
# unattended-upgrades or needrestart (the packages that do this on an ordinary machine), so this is not a problem
# today; this check is what keeps it that way if a package list or a base image ever changes.
#
# Fails on: the packages unattended-upgrades or needrestart installed; their programs on disk; any enabled apt
# timer or apt-daily service; apt's periodic settings turned on (APT::Periodic::*), which is what makes an ordinary
# machine fetch or install updates by itself.
set -uo pipefail
ROOT=${1:?usage: check-no-self-update.sh IMAGE_ROOT}
[ -d "$ROOT/etc" ] || { echo "check-no-self-update: $ROOT is not an image root" >&2; exit 2; }
bad=0
found() { echo "self-updating image: $*" >&2; bad=1; }
for pkg in unattended-upgrades needrestart; do
  if [ -r "$ROOT/var/lib/dpkg/status" ] && awk -v p="$pkg" '$1=="Package:"{cur=$2} $1=="Status:" && cur==p && $0 ~ /installed/ && $0 !~ /not-installed|config-files/ {f=1} END{exit !f}' "$ROOT/var/lib/dpkg/status"; then
    found "package $pkg is installed"
  fi
done
for f in usr/bin/unattended-upgrade usr/sbin/needrestart etc/needrestart etc/apt/apt.conf.d/50unattended-upgrades; do
  [ ! -e "$ROOT/$f" ] || found "$f is present"
done
# an enabled timer is a symlink (or file) under a *.wants directory
while IFS= read -r l; do found "enabled: ${l#"$ROOT"/}"; done < <(find "$ROOT/etc/systemd/system" -path '*.wants/*' \( -name 'apt-daily*' -o -name 'unattended-upgrades*' \) 2>/dev/null | sort)
for f in "$ROOT"/etc/systemd/system/*.timer; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  case $(basename "$f") in apt-daily*|unattended-upgrades*) found "timer ${f#"$ROOT"/}";; esac
done
if [ -d "$ROOT/etc/apt/apt.conf.d" ]; then
  # a setting of 0 or "never" is fine; any other value turns the periodic work on
  while IFS= read -r l; do found "apt.conf.d: $l"; done < <(grep -rhE '^[^#/]*APT::Periodic::[A-Za-z-]+[[:space:]]+"?[1-9a-zA-Z]' "$ROOT/etc/apt/apt.conf.d" 2>/dev/null | grep -vE '"0"|"never"' | head -5)
fi
exit $bad
