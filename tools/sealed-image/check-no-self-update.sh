#!/usr/bin/env bash
# Fails if the image root in $1 could change itself after it was built.
#
# A sealed image is measured: the number a verifier checks says "this exact image, unmodified". Anything in the
# image that installs updates in place, or restarts services behind the Identity Agent, makes that number stop describing the
# machine, and an update must arrive as a new measured image instead. Debian's minbase does not carry
# unattended-upgrades or needrestart (the packages that do this on an ordinary machine), so this is not a problem
# today; this check keeps them out if a package list or a base image ever changes.
#
# Fails on: the packages unattended-upgrades or needrestart installed; their programs on disk; any enabled apt-daily
# or unattended-upgrades timer or service, in /etc or shipped enabled in /usr/lib or /lib; apt's periodic settings
# turned on (APT::Periodic::*), which is what makes an ordinary machine fetch or install updates by itself. It
# looks for these by name, so a self-updater under another name is not caught.
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
# an enabled timer is a symlink (or file) under a *.wants directory: the admin's in /etc, or one a package ships
# enabled in /usr/lib or /lib (the same place on a merged-/usr root, so -H follows that link)
while IFS= read -r l; do found "enabled: ${l#"$ROOT"/}"; done < <(
  for d in etc/systemd/system usr/lib/systemd/system lib/systemd/system; do
    [ -d "$ROOT/$d" ] && find -H "$ROOT/$d" -path '*.wants/*' \( -name 'apt-daily*' -o -name 'unattended-upgrades*' \) 2>/dev/null
  done | sort -u)
for f in "$ROOT"/etc/systemd/system/*.timer; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  case $(basename "$f") in apt-daily*|unattended-upgrades*) found "timer ${f#"$ROOT"/}";; esac
done
if [ -d "$ROOT/etc/apt" ]; then
  # Each APT::Periodic setting's own value is read: "0" (or "never", "false", empty) leaves the periodic work off,
  # anything else turns it on. The block form (APT { Periodic { ... } }) is refused outright rather than parsed.
  while IFS= read -r l; do found "apt periodic setting: $l"; done < <(
    grep -rhE '^[[:space:]]*APT::Periodic::[A-Za-z-]+[[:space:]]+"[^"]*"' "$ROOT/etc/apt/apt.conf" "$ROOT/etc/apt/apt.conf.d" 2>/dev/null |
      while IFS= read -r line; do
        v=${line#*\"}; v=${v%%\"*}
        case $v in (0|never|false|"") ;; (*) printf '%s\n' "$line" ;; esac
      done | head -5)
  while IFS= read -r l; do found "apt periodic block (write each as APT::Periodic::Name instead): $l"; done < <(
    grep -rhE '^[^#/]*Periodic[[:space:]]*\{' "$ROOT/etc/apt/apt.conf" "$ROOT/etc/apt/apt.conf.d" 2>/dev/null | head -5)
fi
exit $bad
