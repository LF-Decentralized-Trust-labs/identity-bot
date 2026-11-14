#!/usr/bin/env bash
# The check passes on a clean minimal root and fails, naming what it found, for each way an image could update itself.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd); T=$(mktemp -d); trap 'rm -rf "$T"' EXIT; fail=0
clean() { rm -rf "$T/r"; mkdir -p "$T/r/etc/apt/apt.conf.d" "$T/r/etc/systemd/system/multi-user.target.wants" "$T/r/var/lib/dpkg" "$T/r/usr/bin"
  printf 'Package: systemd\nStatus: install ok installed\n\nPackage: apt\nStatus: install ok installed\n' > "$T/r/var/lib/dpkg/status"; }
expect() { # label want(0|1) [grep pattern in stderr]
  out=$("$here/check-no-self-update.sh" "$T/r" 2>&1); rc=$?
  if [ "$rc" = "$2" ] && { [ -z "${3:-}" ] || grep -q -- "$3" <<<"$out"; }; then echo "ok   $1"; else echo "FAIL $1 (rc=$rc): $out"; fail=1; fi; }
clean; expect "a clean root passes" 0
clean; printf 'Package: unattended-upgrades\nStatus: install ok installed\n' >> "$T/r/var/lib/dpkg/status"; expect "unattended-upgrades installed" 1 "package unattended-upgrades"
clean; printf 'Package: needrestart\nStatus: install ok installed\n' >> "$T/r/var/lib/dpkg/status"; expect "needrestart installed" 1 "package needrestart"
clean; printf 'Package: needrestart\nStatus: deinstall ok config-files\n' >> "$T/r/var/lib/dpkg/status"; expect "a removed package (config files only) is not an install" 0
clean; printf 'Package: needrestart\nStatus: deinstall ok not-installed\n' >> "$T/r/var/lib/dpkg/status"; expect "a package not installed passes" 0
clean; touch "$T/r/usr/bin/unattended-upgrade"; expect "the unattended-upgrade program on disk" 1 "unattended-upgrade is present"
clean; mkdir -p "$T/r/etc/needrestart"; expect "a needrestart directory" 1 "etc/needrestart"
clean; ln -s /lib/systemd/system/apt-daily.timer "$T/r/etc/systemd/system/multi-user.target.wants/apt-daily.timer"; expect "an enabled apt-daily timer" 1 "enabled: etc/systemd/system/multi-user.target.wants/apt-daily.timer"
clean; mkdir -p "$T/r/etc/systemd/system/timers.target.wants"; ln -s /x "$T/r/etc/systemd/system/timers.target.wants/apt-daily-upgrade.timer"; expect "an enabled apt-daily-upgrade timer" 1 "apt-daily-upgrade"
clean; touch "$T/r/etc/systemd/system/apt-daily.timer"; expect "an apt timer unit placed in etc" 1 "timer etc/systemd/system/apt-daily.timer"
clean; echo 'APT::Periodic::Unattended-Upgrade "1";' > "$T/r/etc/apt/apt.conf.d/20auto"; expect "periodic unattended upgrade on" 1 "apt.conf.d"
clean; echo 'APT::Periodic::Update-Package-Lists "1";' > "$T/r/etc/apt/apt.conf.d/20auto"; expect "periodic list update on" 1 "apt.conf.d"
clean; echo 'APT::Periodic::Unattended-Upgrade "0";' > "$T/r/etc/apt/apt.conf.d/20auto"; expect "periodic set to 0 passes" 0
clean; echo '// APT::Periodic::Unattended-Upgrade "1";' > "$T/r/etc/apt/apt.conf.d/20auto"; expect "a commented setting passes" 0
clean; echo 'APT::Periodic::Unattended-Upgrade "true";' > "$T/r/etc/apt/apt.conf.d/20auto"; expect "periodic set to true" 1 "apt.conf.d"
rm -rf "$T/r"; expect "not an image root is refused, not passed" 2 "not an image root"
exit $fail
