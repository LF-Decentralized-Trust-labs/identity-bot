#!/usr/bin/env bash
# Build the measured base image every sealed instance overlays.
#
# One image, built once, measured once. That is what makes an attestation
# measurement mean anything: every instance starts from provably the same bytes,
# so a report saying "this measurement" says "this exact image, unmodified".
#
# Produces a qcow2 containing a minimal Debian, one agent binary (the OSS core
# for an individual image, the org backend for an organisation one),
# and a systemd unit that starts the agent on :5050 with its first-boot pairing
# offer reachable. Run as root on a machine with the tools listed in README.md.
set -euo pipefail

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

AGENT_BINARY=${AGENT_BINARY:-}
# WEB_BUNDLE is the front end this instance serves to a browser: the directory
# a `flutter build web` produced, or the tarball of one.
#
# Optional, and its absence is a real state rather than a mistake — an instance
# with no bundle answers with a placeholder saying so, which is what every
# instance did before this existed. But an instance somebody reaches from a
# browser needs it, and that is the whole point of a hosted agent.
WEB_BUNDLE=${WEB_BUNDLE:-}
# BUILD_NAME is what this software is CALLED, for the screens that have to tell
# somebody what their agent is actually running.
#
# Optional, and it goes INSIDE the image, which is the whole point: the name is
# covered by the measurement, so an instance cannot claim to be running
# something it is not without producing a different measurement and failing the
# comparison every client makes. A name supplied at launch would instead be a
# label whoever operates the hardware could set to anything, which is precisely
# the party a sealed instance exists to be safe from.
#
# Without it a person is shown ninety-six characters of hex and no way to know
# what it is a measurement OF — a fact rather than a useful one.
BUILD_NAME=${BUILD_NAME:-}
# ENTITY_TYPE is whether this image serves a person or an organisation.
#
# UNLIKE BUILD_NAME, THIS ONE IS BEHAVIOUR. The agent uses it to decide who may
# witness and watch for it, because peers of that kind are the ones it enrols.
# Without it the agent falls back to a profile that is empty until onboarding
# finishes, and until then it enrols no witness and no watcher at all — it says
# so on every boot, into a console nobody outside the machine reads.
#
# On a personal computer the application sets this when it starts the agent. In
# a sealed instance there is no application to do that: systemd starts the
# agent, so the image has to carry it. That is the whole gap this closes.
#
# Which kind an image serves is already decided by AGENT_BINARY, and this must
# agree with it — but the build cannot check that, because a binary is opaque.
# So it is stated, validated against the two values that exist, and covered by
# the measurement like everything else in here.
ENTITY_TYPE=${ENTITY_TYPE:-}
OUT=${OUT:-./base.qcow2}
# VERITY=1 builds a read-only system image whose every block is covered by a
# hash on the measured command line. Opt-in while it is being proven; the
# default path is unchanged.
VERITY=${VERITY:-0}
SIZE=${SIZE:-2G}
SUITE=${SUITE:-bookworm}
# Every timestamp this build writes down. Fixed rather than "now", because a
# clock is an input that changes the output bytes, and one that changes on its
# own is the hardest kind to notice. Exported, so it reaches the tools that
# honour it rather than only the code in this file.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1700000000}
# Fixed identifiers for the system filesystem. They are arbitrary and they are
# meant to be: what matters is that every build writes the SAME arbitrary value
# rather than a fresh random one, because a random one alone makes two identical
# builds produce different root hashes. Do not "improve" these to something
# generated — that reintroduces exactly the problem they exist to remove.
FIXED_FS_UUID=${FIXED_FS_UUID:-c0ffee00-0000-4000-8000-000000000001}
FIXED_HASH_SEED=${FIXED_HASH_SEED:-c0ffee00-0000-4000-8000-000000000002}
FIXED_VERITY_SALT=${FIXED_VERITY_SALT:-c0ffee0000000000000000000000000000000000000000000000000000000003}
# The verity superblock carries a UUID that veritysetup also randomises per run.
# It does NOT enter the root hash — the measurement reproduced without pinning
# it — but the image file did not, and a reader who compares the file rather
# than the hash would see a difference with no explanation.
FIXED_VERITY_UUID=${FIXED_VERITY_UUID:-c0ffee00-0000-4000-8000-000000000004}
# Not /tmp: debootstrap creates device nodes in the root it builds, a tmpfs is commonly
# mounted `nodev`, and the resulting error names a permissions problem that is
# not there. WORKROOT overrides it.
WORKROOT=${WORKROOT:-/var/tmp}
WORK=$(mktemp -d "$WORKROOT/sealed-image.XXXXXX")

# Put the host's temp directory back the way we found it.
#
# Something in this build — not identified, and not for want of looking:
# debootstrap and virt-make-fs were each run in isolation and neither does it —
# leaves the host's TMPDIR at mode 0700 root-only. Observed after three
# consecutive builds, timestamped to the minute each finished.
#
# The consequence is out of all proportion to the cause. A 0700 temp directory
# breaks every other user on the machine: no scp into it, no editor swap files,
# no build caches, and anything with a hardcoded path fails with a permission
# error that points nowhere near a base-image build that finished an hour ago.
# The script cleans up after itself rather than assuming it owns the machine
# it runs on.
#
# Restoring is the right shape of fix even once the cause is known: a build
# should be responsible for the state it leaves behind, whichever of its tools
# disturbed it.
TMPROOT=${TMPDIR:-/tmp}
TMPROOT_MODE=$(stat -c %a "$TMPROOT" 2>/dev/null || echo 1777)
restore_tmp() {
  local now
  now=$(stat -c %a "$TMPROOT" 2>/dev/null || echo "$TMPROOT_MODE")
  if [[ "$now" != "$TMPROOT_MODE" ]]; then
    chmod "$TMPROOT_MODE" "$TMPROOT" 2>/dev/null &&
      echo "  restored $TMPROOT from mode $now to $TMPROOT_MODE" >&2
  fi
}
trap 'rm -rf "$WORK"; restore_tmp' EXIT

[[ $EUID -eq 0 ]] || fail "run as root"
[[ -n "$AGENT_BINARY" ]] || fail "set AGENT_BINARY to a linux/amd64 agent build. Whichever build goes in, it serves the same contract on :5050, so the image is identical apart from which binary is inside it — which is the whole reason each one needs its own image and its own measurement"
[[ -x "$AGENT_BINARY" ]] || fail "AGENT_BINARY is not executable: $AGENT_BINARY"

case "$ENTITY_TYPE" in
  ""|individual|organization) ;;
  *) fail "ENTITY_TYPE must be 'individual' or 'organization' (got: $ENTITY_TYPE). The agent enrols witnesses and watchers among peers of its own kind, and a value it does not recognise leaves it with none" ;;
esac

file "$AGENT_BINARY" | grep -q 'ELF 64-bit' || fail "AGENT_BINARY is not a Linux binary — build with GOOS=linux GOARCH=amd64"

# Does this binary answer the subcommand the image is about to depend on?
#
# The unit written further down runs `identity-agent-core seal-volume` before
# anything mounts the data volume. A binary that does not dispatch that
# subcommand does not fail there in any way that says so: it ignores the
# arguments, starts a full server against a read-only root, and exits — after
# which the state mount fails on its dependency and the Identity Agent crash-loops
# against a database it cannot open. The volume is simply never encrypted, and
# nothing in the visible error mentions a volume.
#
# That happened, to a binary built from an overlay of this core that
# implemented everything except the dispatch. This is the only place that sees
# every binary going into an image, whatever built it, so this is where the
# question gets asked. A correct binary refuses a device that does not exist,
# quickly; a non-dispatching one tries to serve and gets killed by the timeout.
#
# -k matters and was learned the hard way. A binary that does not dispatch
# starts a server, and a server does not stop for SIGTERM promptly enough to
# be relied on — the first version of this check hung until it was killed by
# hand. -k follows with SIGKILL, and the output goes to a file rather than
# through a command substitution, which would wait on the pipe regardless of
# what happened to the process holding it.
probe="$WORK/seal-volume-probe"
timeout -k 2 10 "$AGENT_BINARY" seal-volume /nonexistent-probe-device >"$probe" 2>&1 </dev/null || true
grep -qi 'no volume at' "$probe" || fail "AGENT_BINARY does not answer 'seal-volume', so an image built from it would never encrypt its data volume — and would fail later, somewhere else, in a way that does not mention the volume. Whatever embeds this core must dispatch the volume commands (identity-agent-core/volume.Handle). It answered: $(head -c 200 "$probe")"

# The web bundle is checked HERE, before anything expensive runs.
#
# Everything below this point bootstraps a root filesystem, which takes minutes.
# A bundle that is the wrong shape should cost a second, not a build — the first
# version of this validated after the bootstrap, which meant finding out at the
# end.
WEB_SRC=""
WEB_DIGEST=""
if [[ -n "$WEB_BUNDLE" ]]; then
  WEB_SRC="$WEB_BUNDLE"
  if [[ -f "$WEB_BUNDLE" ]]; then
    WEB_SRC="$(mktemp -d)"
    tar -xzf "$WEB_BUNDLE" -C "$WEB_SRC" || fail "WEB_BUNDLE is a file but not a readable tarball: $WEB_BUNDLE"
  fi
  [[ -d "$WEB_SRC" ]] || fail "WEB_BUNDLE is neither a directory nor a tarball: $WEB_BUNDLE"
  [[ -f "$WEB_SRC/index.html" ]] || fail "WEB_BUNDLE has no index.html — that is not a built web bundle: $WEB_BUNDLE"
  # A bundle that cannot boot the app is worse than none: the agent serves it,
  # the browser gets a blank page, and nothing says why.
  [[ -f "$WEB_SRC/main.dart.js" ]] || fail "WEB_BUNDLE has no main.dart.js — the app did not compile into it: $WEB_BUNDLE"
  # A service worker outlives the page that installed it, so a cached one keeps
  # serving the previous app after this image is replaced — invisibly, and to
  # exactly the people who used it before.
  if [[ -s "$WEB_SRC/flutter_service_worker.js" ]]; then
    fail "WEB_BUNDLE contains a non-empty service worker, so it would cache itself and keep serving an old app after this image is updated. Build it with --pwa-strategy=none"
  fi
  WEB_DIGEST=$(cd "$WEB_SRC" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
  echo "  web bundle accepted: sha256 $WEB_DIGEST"
fi

# Checked here rather than where each is first used, because the ones that come
# late come after ten minutes of bootstrapping, and a build that fails at the
# end for a missing package is a build nobody runs twice.
for t in debootstrap file cpio gzip truncate; do
  command -v "$t" >/dev/null || fail "missing $t (apt-get install debootstrap file cpio gzip coreutils)"
done
if [[ "$VERITY" == "1" ]]; then
  for t in mke2fs veritysetup debugfs; do
    command -v "$t" >/dev/null || fail "missing $t (apt-get install e2fsprogs cryptsetup-bin)"
  done
else
  command -v virt-make-fs >/dev/null || fail "missing virt-make-fs (apt-get install libguestfs-tools)"
fi

# Two different causes produce the same symptom, and naming only one sends
# somebody looking in the wrong place. A tmpfs mounted nodev cannot hold device
# nodes at all; a container without CAP_MKNOD cannot create them anywhere, on
# any filesystem. The mount options are printed so the reader can tell which
# they are looking at — if nodev is absent, it is the capability.
mknod "$WORK/probe-dev" c 1 3 2>/dev/null ||
  fail "cannot create device nodes under $WORKROOT, and debootstrap needs them.
     Mounted: $(findmnt -no FSTYPE,OPTIONS --target "$WORKROOT" 2>/dev/null)
     If those options include nodev, point WORKROOT= at an ordinary filesystem.
     If they do not, this process lacks CAP_MKNOD — in a container, run it with
     privileges that include that capability rather than changing WORKROOT."
rm -f "$WORK/probe-dev"

say "Bootstrapping a minimal $SUITE root"
debootstrap --variant=minbase \
  --include=systemd,systemd-sysv,ca-certificates,dbus,linux-image-amd64,initramfs-tools,cryptsetup-bin,dmsetup,e2fsprogs \
  "$SUITE" "$WORK/root" >/dev/null

# Write the package sources rather than keeping whatever debootstrap left.
#
# Found by building the same image on two distributions and comparing: of 4,494
# files, exactly one differed, and the difference was http versus https on this
# single line. Debian's debootstrap and Ubuntu's disagree about the default, so
# the image recorded which machine had built it — the one thing an image whose
# whole purpose is to be identical everywhere must not do.
#
# It should be written down anyway. The sources an image carries are a decision
# about where it will get updates from, and a decision is something you state
# rather than inherit from whichever tool happened to run.
printf 'deb https://deb.debian.org/debian %s main\n' "$SUITE" > "$WORK/root/etc/apt/sources.list"

say "Installing the agent"
install -D -m 0755 "$AGENT_BINARY" "$WORK/root/usr/local/bin/identity-agent-core"

# The front end goes inside the image, which means inside the measurement.
#
# That is the correct consequence and worth being deliberate about: the bundle
# is code the agent serves to a browser, so it belongs to what this instance is,
# and a change to it must change what the instance measures. The alternative --
# mounting it from the host -- would let the operator swap the interface a
# person types their details into without the measurement moving.
#
# This image used to mount one thing that way. It no longer does: everything
# the Identity Agent needs is now inside what it measures.
if [[ -n "$WEB_BUNDLE" ]]; then
  mkdir -p "$WORK/root/usr/share/identity-agent/web"
  cp -a "$WEB_SRC/." "$WORK/root/usr/share/identity-agent/web/"
  # Read-only at runtime. The agent serves these; nothing should write them.
  chmod -R a-w "$WORK/root/usr/share/identity-agent/web"
  echo "  web bundle: $(find "$WEB_SRC" -type f | wc -l | tr -d ' ') files, sha256 $WEB_DIGEST"
else
  echo "  web bundle: none — a browser will get the placeholder page"
fi
install -d -m 0700 "$WORK/root/var/lib/identity-agent"

# Where the agent's identity lives, on a writable volume of its own.
#
# A verified root filesystem is read-only by construction — that is what makes
# it verifiable — but an agent's keys must survive a restart, so they cannot
# live on it and cannot live in memory. One small volume per instance carries
# exactly what must persist and nothing else.
#
# nofail because an image built without verity has no second volume and boots
# perfectly well from its own writable root. The mount is what changes between
# the two shapes; nothing else has to know which one it is on.
# Encrypting the volume before anything mounts it.
#
# The key comes from the processor, derived from this software's measurement,
# so only this software can open the volume — and the machine's operator cannot
# ask for it at all. Nothing is stored: the key is asked for again on the next
# boot, so there is no wrapped blob for anyone to find or to roll back.
#
# What this protects is the disk, at rest and in the operator's hands. It does
# not protect against an operator who launches this exact software and lets it
# decrypt the volume itself; that is a harder problem and is not claimed here.
cat > "$WORK/root/etc/systemd/system/seal-volume.service" <<'SEAL'
[Unit]
Description=Encrypt the agent's data volume to this machine
After=dev-vdb.device
Wants=dev-vdb.device
Before=var-lib-identity\x2dagent.mount
ConditionPathExists=/dev/vdb

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/identity-agent-core seal-volume /dev/vdb tenant-data

[Install]
WantedBy=multi-user.target
SEAL
ln -sf /etc/systemd/system/seal-volume.service \
  "$WORK/root/etc/systemd/system/multi-user.target.wants/seal-volume.service"

cat > "$WORK/root/etc/systemd/system/var-lib-identity\\x2dagent.mount" <<'MOUNT'
[Unit]
Description=Identity agent state
Before=identity-agent.service
After=seal-volume.service
Requires=seal-volume.service

[Mount]
What=/dev/mapper/tenant-data
Where=/var/lib/identity-agent
Type=ext4
Options=rw,noatime,nofail

[Install]
WantedBy=multi-user.target
MOUNT
ln -sf "/etc/systemd/system/var-lib-identity\\x2dagent.mount" \
  "$WORK/root/etc/systemd/system/multi-user.target.wants/var-lib-identity\\x2dagent.mount"

# systemd writes in a few places whatever the agent does. On a read-only root
# these become memory rather than disk: none of it needs to outlive the
# instance, and an empty machine-id makes systemd generate a transient one
# instead of failing to write a permanent one.
cat > "$WORK/root/etc/fstab" <<'FSTAB'
tmpfs /tmp     tmpfs rw,nosuid,nodev,size=64M 0 0
tmpfs /var/log tmpfs rw,nosuid,nodev,size=16M 0 0
FSTAB
: > "$WORK/root/etc/machine-id"

# The agent starts itself. Nothing reaches in to incept it and nothing can:
# a provider that could hand an instance its keys would be a provider that had
# them. The instance mints its own pairwise AID on the first pairing request.
# Mount the shared runtime, then check it is what we expect BEFORE anything
# runs from it. The provider says where a resource is; only this image says
# what it is allowed to be, and a mismatch is fatal rather than a warning.
# A .mount unit's filename must be the escaped mount point, or systemd calls
# it a bad unit file and everything depending on it never runs.

install -D -m 0644 /dev/stdin "$WORK/root/etc/tmpfiles.d/cryptsetup-lock.conf" <<'TMPF'
# cryptsetup's lock directory, created before the agent starts.
#
# ReadWritePaths refuses a path that does not exist, so without this the unit
# fails to start rather than merely failing to lock — and a verified read-only
# root cannot create it at boot.
d /run/cryptsetup 0700 root root -
TMPF

cat > "$WORK/root/etc/systemd/system/identity-agent.service" <<'UNIT'
[Unit]
Description=Identity Agent (sealed instance)
After=network-online.target
Wants=network-online.target

[Service]
Environment=AGENT_DATA_DIR=/var/lib/identity-agent
Environment=PORT=5050
# Measured on the host: the Go agent idles at 60MB without these and 29MB with
# them, and stayed healthy through inception, profile writes and a full
# adoption. Most of the difference was heap the collector had no reason to
# return — which is the right default on a machine with memory to spare and the
# wrong one on a small guest.
Environment=GOMEMLIMIT=40MiB
Environment=GOGC=50
# This instance is only ever reached through the proxy in front of it, so the
# proxy is the only party that knows the name, the scheme and the path prefix a
# person actually used. Without this the agent guesses from a local interface
# and publishes an address in its OOBI that resolves nowhere.
#
# Safe to state HERE and nowhere else: an instance is not directly reachable, so
# nothing can reach it with forwarding headers of its own choosing. An agent
# somebody can reach directly must not set this.
Environment=TRUST_FORWARDED_HEADERS=1
Environment="AGENT_BUILD_NAME=__BUILD_NAME__"
Environment="IDENTITY_AGENT_ENTITY_TYPE=__ENTITY_TYPE__"
ExecStart=/usr/local/bin/identity-agent-core
Restart=always
RestartSec=2
# The agent is the only thing this VM is for.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/identity-agent
# cryptsetup takes a per-device lock under /run/cryptsetup, and ProtectSystem=strict
# makes every path read-only except /dev, /proc and /sys — so without this the agent
# can read the volume it is running on but cannot lock it, and every cryptsetup call
# it makes fails with "Failed to acquire read lock on device".
#
# What that broke: adding the owner's recovery key slot at adoption. The volume
# stayed encrypted to the launch measurement and to nothing else, so a firmware
# update that moved the measurement would have locked the instance out of its own
# disk for good — the exact loss the recovery slot exists to prevent. Adoption
# still reported success, because this is not fatal to adoption.
#
# Not solved by skipping the lock. The read is only the first step; adding a key
# slot and writing the header token are writes, and a write without the lock is
# how two processes corrupt a LUKS header between them.
ReadWritePaths=/run/cryptsetup
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
# Substituted rather than interpolated, because the heredoc above is quoted so
# that systemd's own $-syntax survives it intact.
#
# A build that names nothing drops the line entirely: an agent that does not
# know what it is says so, and a screen showing an empty name would look like a
# fact rather than a gap.
if [[ -n "$BUILD_NAME" ]]; then
  # A name is written into a unit file, so a newline in it would forge further
  # directives — and this value comes from whoever invokes the build. A double
  # quote would end the quoted value early and do the same thing on one line.
  [[ "$BUILD_NAME" != *$'\n'* ]] || fail "BUILD_NAME must be a single line"
  [[ "$BUILD_NAME" != *'"'* ]] || fail "BUILD_NAME must not contain a double quote"
  BUILD_NAME_ESC=${BUILD_NAME//&/\\&}
  sed -i "s|__BUILD_NAME__|${BUILD_NAME_ESC//|/\\|}|" \
    "$WORK/root/etc/systemd/system/identity-agent.service"
  echo "  build name: $BUILD_NAME"
else
  sed -i '/^Environment="AGENT_BUILD_NAME=__BUILD_NAME__"$/d' \
    "$WORK/root/etc/systemd/system/identity-agent.service"
fi
# The kind. Validated above, so no escaping is needed here: the only values that
# reach this point are two literal words.
if [[ -n "$ENTITY_TYPE" ]]; then
  sed -i "s|__ENTITY_TYPE__|$ENTITY_TYPE|" \
    "$WORK/root/etc/systemd/system/identity-agent.service"
  echo "  entity type: $ENTITY_TYPE"
else
  sed -i '/^Environment="IDENTITY_AGENT_ENTITY_TYPE=__ENTITY_TYPE__"$/d' \
    "$WORK/root/etc/systemd/system/identity-agent.service"
  echo "  WARNING: no ENTITY_TYPE, so this image will not know whether it serves"
  echo "           a person or an organisation, and will enrol no witness or watcher"
fi
# The browser front end, only where one was actually installed.
#
# Set unconditionally, this named a directory that a default build never
# creates: the image declared a front end it did not have. Worse in the other
# direction — an instance reached through a proxy that terminates TLS cannot
# protect a browser at all, because the application itself arrives from the
# machine it is meant to be protecting the user against, and a browser cannot
# check that what it downloaded is genuine. So the default is no browser front
# end, and turning it on is a deliberate act by whoever builds the image.
#
# Note this is NOT a runtime setting. The bundle is inside the measured image,
# so an image with a browser front end and one without have different launch
# measurements. Turning it on or off later is a rebuild, a new measurement, and
# the same owner-approval step as any other change to the software — which also
# means whether a given instance serves a browser front end is a fact anybody
# can verify from its measurement, rather than a setting nobody can audit.
if [[ -n "$WEB_SRC" ]]; then
  sed -i 's|^ExecStart=|Environment=FLUTTER_WEB_DIR=/usr/share/identity-agent/web\nExecStart=|' \
    "$WORK/root/etc/systemd/system/identity-agent.service"
  echo "  browser front end: INCLUDED (this image serves one)"
else
  echo "  browser front end: none (set WEB_BUNDLE= to include one)"
fi

ln -sf /etc/systemd/system/identity-agent.service \
  "$WORK/root/etc/systemd/system/multi-user.target.wants/identity-agent.service"

# The guest gets its address by DHCP from QEMU's user-mode network. Without
# this a minimal Debian brings up no interface at all, so the agent starts,
# listens on localhost inside the VM, and nothing outside can ever reach it —
# which is indistinguishable from a slow boot to whatever is waiting for it.
install -D -m 0644 /dev/stdin "$WORK/root/etc/systemd/network/10-any.network" <<'NET'
[Match]
Name=en*

[Network]
DHCP=yes
NET
chroot "$WORK/root" systemctl enable systemd-networkd >/dev/null 2>&1 || \
  ln -sf /lib/systemd/system/systemd-networkd.service \
    "$WORK/root/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"

# Deterministic where it can be: an image that differs run to run cannot be
# pinned to a measurement anybody checks.
rm -rf "$WORK/root/var/cache/apt" "$WORK/root/var/lib/apt/lists"
: > "$WORK/root/etc/machine-id"
: > "$WORK/root/etc/hostname"
rm -f "$WORK/root/etc/ssh/ssh_host_"* 2>/dev/null || true


# Name resolution. Without this a guest resolves nothing.
#
# debootstrap leaves a resolv.conf pointing at systemd-resolved's stub on
# 127.0.0.53, and resolved does not run in an image this small. So every
# outbound lookup failed with "connection refused" from inside the guest —
# invisible for a long time, because instances are REACHED inbound through a
# port forward and answer perfectly well. Nothing exercised outbound DNS until
# an agent tried to fetch its own attestation certificate.
#
# It is not only certificates: resolving a peer's OOBI, reaching a witness, and
# anything else the agent addresses by name were all broken the same way.
#
# 10.0.2.3 is the resolver QEMU's user-mode networking provides, at a fixed
# address that is part of that networking's contract. A real file rather than a
# symlink into /run, because nothing here populates /run.
say "Configuring name resolution"
rm -f "$WORK/root/etc/resolv.conf"
cat > "$WORK/root/etc/resolv.conf" <<'RESOLV'
# The resolver the host's user-mode networking provides. Fixed by that
# networking's contract, not by this machine's configuration.
nameserver 10.0.2.3
options timeout:2 attempts:2
RESOLV
chmod 0644 "$WORK/root/etc/resolv.conf"

say "Pruning kernel modules"
# A micro-VM has virtio devices and nothing else. Shipping the full Debian
# module tree means ~400MB of drivers for hardware that does not exist here,
# copied into every instance. Keep what the guest actually loads — resolved by
# asking modprobe for each module's dependencies rather than by guessing — and
# delete the rest.
KVER=$(basename "$(ls -d "$WORK/root/usr/lib/modules"/* | head -1)")
# sev-guest is not an optional driver for hardware that might be present — it is
# the reason this image exists. Without it /dev/sev-guest never appears, the
# guest cannot produce an attestation report, and a box that is genuinely sealed
# has no way to say so. Measured on 2026-07-29: a guest booted with SEV-SNP
# active, its kernel log confirming "SNP guest platform device initialized", and
# modprobe answered "Module sev-guest not found" — because this prune had
# deleted it. The image slimming removed the product's core security property
# and everything still appeared to work.
NEEDED="virtio_pci virtio_blk virtio_net virtio_console 9p 9pnet_virtio ext4 crc32c_generic sev-guest dm_mod dm_verity dm_crypt"

# The whole crypto directory is kept, and enumerating it was tried first and
# abandoned. This is worth the paragraph, because the failure it prevents is
# invisible and the reasoning is not obvious.
#
# sev-guest talks to the PSP over an AES-GCM channel keyed by the VMPCK, set up
# with crypto_alloc_aead("gcm(aes)"). The crypto API resolves that BY NAME at
# runtime and builds it from templates: gcm(aes) is gcm_base(ctr(aes), ghash).
# None of those are module link dependencies, so `modprobe --show-depends
# sev-guest` mentions none of them and no dependency-driven list can find the
# closure.
#
# Measured, in two rounds. With crypto pruned entirely the driver loaded and its
# probe failed at exactly one line — `ret = -EIO; init_crypto(...)` — surfacing
# as "sev-guest: probe of sev-guest failed with error -5" and no device node.
# Adding gcm and ghash was not enough: they loaded, and it still failed, because
# ctr was missing and gcm(aes) cannot be instantiated without it.
#
# That is the argument for keeping the directory rather than a longer list. The
# next algorithm we reach for would have its own hidden closure, and the failure
# mode is a guest that boots, serves traffic, and quietly cannot attest. The
# whole tree is a couple of megabytes against a 2GB image — far less than the
# cost of being wrong a third time.
KEEP_DIRS="kernel/crypto"
KEEP="$WORK/keep.list"
: > "$KEEP"
for m in $NEEDED; do
  chroot "$WORK/root" modprobe --set-version "$KVER" --show-depends "$m" 2>/dev/null |
    awk '/^insmod /{print $2}' >> "$KEEP" || true
done
if [[ -s "$KEEP" ]]; then
  # Compare basenames: modprobe reports /lib/modules/... while the tree lives at
  # /usr/lib/modules/... on a merged-usr system, and comparing those two paths
  # matches nothing — which silently deletes every module and leaves a guest
  # that cannot mount its own root.
  sed -E 's|.*/||' "$KEEP" | sort -u > "$KEEP.names"
  mv "$KEEP.names" "$KEEP"
  find "$WORK/root/usr/lib/modules/$KVER" -name '*.ko*' | while read -r ko; do
    rel=${ko#"$WORK/root/usr/lib/modules/$KVER/"}
    keep_dir=false
    for d in $KEEP_DIRS; do
      case "$rel" in "$d"/*) keep_dir=true ;; esac
    done
    $keep_dir && continue
    grep -qxF "$(basename "$ko")" "$KEEP" || rm -f "$ko"
  done
  find "$WORK/root/usr/lib/modules/$KVER" -type d -empty -delete
  chroot "$WORK/root" depmod -a "$KVER" 2>/dev/null || true
  KEPT=$(find "$WORK/root/usr/lib/modules/$KVER" -name '*.ko*' | wc -l)
  [[ $KEPT -gt 0 ]] || fail "the module prune removed everything — the guest would not boot"

  # The existing check above catches a prune that breaks booting. These catch a
  # prune that leaves a guest booting perfectly and unable to prove what it is —
  # the failure that hides, because nothing about it looks broken. A guest that
  # cannot attest is not a sealed machine with a missing feature; it is an
  # ordinary virtual machine that cannot be told apart from one.
  #
  # Both are asserted because the first fix was incomplete in a way that looked
  # complete: sev-guest was restored, the image built, and the guest still could
  # not attest — because the crypto its channel needs had gone the same way.
  find "$WORK/root/usr/lib/modules/$KVER" -name 'sev*guest*.ko*' | grep -q . ||
    fail "the module prune removed sev-guest — the guest would boot sealed and be unable to attest, which is worse than not booting"

  # Named individually rather than trusting KEEP_DIRS to have worked, because
  # these three are what gcm(aes) is actually built from and their absence is
  # what produced the EIO twice. A guard that only restates the policy would
  # have passed both times.
  for m in gcm ctr ghash; do
    find "$WORK/root/usr/lib/modules/$KVER/kernel/crypto" -name "$m*.ko*" | grep -q . ||
      fail "$m is missing from kernel/crypto — sev-guest cannot build its AES-GCM channel to the PSP and its probe will fail with EIO"
  done

  echo "  kept $KEPT modules"
else
  echo "  WARNING: could not resolve module dependencies; keeping the full tree"
fi

# Load sev-guest at boot rather than hoping something autoloads it.
#
# Not in the initramfs — attestation is not needed to mount a root filesystem,
# and putting it there would grow the image for no reason. It is needed by the
# time the agent runs, which is what modules-load.d gives.
#
# Explicit because the alternative is a device that appears only if a platform
# match fires, and a black box whose attestation depends on that is a black box
# whose attestation is occasionally absent for reasons nobody can reproduce.
mkdir -p "$WORK/root/etc/modules-load.d"
echo "sev-guest" > "$WORK/root/etc/modules-load.d/sev-guest.conf"

# Documentation, locales and firmware for hardware that is not here.
rm -rf "$WORK/root/usr/share/doc" "$WORK/root/usr/share/man" \
       "$WORK/root/usr/share/locale" "$WORK/root/usr/share/info" \
       "$WORK/root/usr/lib/firmware" 2>/dev/null || true

# Opening the verified root before anything mounts it.
#
# The measurement covers the kernel, the initramfs and the command line — and
# nothing else. So the root filesystem, where the agent actually lives, was not
# covered at all: two images differing only in their root filesystem produced
# the same measurement, which was demonstrated rather than assumed.
#
# dm-verity closes that by putting a hash of the entire filesystem on the
# command line, which IS measured. Every block is checked against that hash as
# it is read, so an altered root filesystem cannot be mounted under a
# measurement that says it is unaltered.
#
# This runs in the initramfs because the kernel here has device-mapper as a
# module, so the kernel's own dm-mod.create= shortcut is unavailable.
install -d -m 0755 "$WORK/root/etc/initramfs-tools/scripts/local-top"
cat > "$WORK/root/etc/initramfs-tools/scripts/local-top/verity" <<'VERITY'
#!/bin/sh
# Open the verity-protected root, using the hash the measured command line
# carries. No hash means an image built without verity, which still boots — and
# says so, because silently booting unverified is the failure this exists to
# prevent.
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac

. /scripts/functions

for arg in $(cat /proc/cmdline); do
  case "$arg" in
    verity.roothash=*)   ROOTHASH="${arg#verity.roothash=}" ;;
    verity.hashoffset=*) HASHOFFSET="${arg#verity.hashoffset=}" ;;
    verity.datadev=*)    DATADEV="${arg#verity.datadev=}" ;;
  esac
done

[ -n "$ROOTHASH" ] || { log_warning_msg "no verity root hash on the command line: booting an unverified root filesystem"; exit 0; }
: "${DATADEV:=/dev/vda}"

modprobe dm_mod    2>/dev/null || true
modprobe dm_verity 2>/dev/null || true

# Wait for the device: virtio probing races the initramfs on a cold boot, and
# failing here means an unbootable instance rather than a slow one.
i=0
while [ ! -b "$DATADEV" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
[ -b "$DATADEV" ] || panic "verity: $DATADEV never appeared"

if ! veritysetup open "$DATADEV" vroot "$DATADEV" "$ROOTHASH" --hash-offset="$HASHOFFSET"; then
  # Refusing to boot is the point. A root filesystem that does not match the
  # hash on the measured command line is not the image that was attested, and
  # continuing would mean serving one thing while proving another.
  panic "verity: the root filesystem does not match the measured hash — refusing to boot"
fi
VERITY
chmod 0755 "$WORK/root/etc/initramfs-tools/scripts/local-top/verity"

# veritysetup must be IN the initramfs, not merely installed in the image: the
# image it would come from is the one being opened.
install -d -m 0755 "$WORK/root/etc/initramfs-tools/hooks"
cat > "$WORK/root/etc/initramfs-tools/hooks/verity" <<'VHOOK'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
copy_exec /sbin/veritysetup /sbin
copy_exec /sbin/dmsetup /sbin
manual_add_modules dm_mod
manual_add_modules dm_verity
VHOOK
chmod 0755 "$WORK/root/etc/initramfs-tools/hooks/verity"

say "Rebuilding the initramfs for this guest"
# Debian's default initramfs carries every module for every machine — 35MB
# compressed, which unpacks into RAM before userspace exists and set the
# guest's memory floor higher than anything it actually runs. An instance
# deadlocked on memory 1.7 seconds into boot at 256MB because of it.
#
# MODULES=list with an explicit set, not MODULES=dep: dep reads sysfs, and the
# sysfs available here describes the build host, not the guest. Naming the
# modules is both correct and reproducible.
cat > "$WORK/root/etc/initramfs-tools/initramfs.conf" <<'IRCONF'
MODULES=list
BUSYBOX=auto
COMPRESS=zstd
DEVICE=
NFSROOT=auto
RUNSIZE=8M
IRCONF
cat > "$WORK/root/etc/initramfs-tools/modules" <<'IRMODS'
virtio_pci
virtio_blk
virtio_net
9p
9pnet_virtio
ext4
dm_mod
dm_verity
IRMODS
mount --bind /dev "$WORK/root/dev"
mount -t proc proc "$WORK/root/proc"
mount -t sysfs sys "$WORK/root/sys"
chroot "$WORK/root" update-initramfs -u -k "$KVER" >/dev/null 2>&1 \
  || echo "  WARNING: could not rebuild the initramfs; keeping the generic one"
umount -l "$WORK/root/sys" 2>/dev/null || true
umount -l "$WORK/root/proc" 2>/dev/null || true
umount -l "$WORK/root/dev" 2>/dev/null || true

say "Extracting the kernel"
# The guest is booted directly rather than through a bootloader: that is the
# normal shape for an SNP micro-VM and the better one, because with
# kernel-hashes=on the kernel, the initrd and the command line are all covered
# by the launch measurement. So they come out of the image and sit beside it.
kernel=$(ls "$WORK/root/boot"/vmlinuz-* 2>/dev/null | head -1) || true
initrd=$(ls "$WORK/root/boot"/initrd.img-* 2>/dev/null | head -1) || true
[[ -n "$kernel" ]] || fail "no kernel in the image — a root filesystem alone will not boot"
# Named after the image they belong to, not written to a shared path.
#
# With kernel-hashes=on the measurement covers the kernel, the initrd AND the
# image, so those three are one unit. Writing the kernel and initrd to a fixed
# name meant building a SECOND image silently replaced the first image's initrd
# and invalidated its pinned measurement — every instance of the first kind
# would then be destroyed as measuring the wrong thing, with nothing in the
# output to connect that to a build of something else.
#
IMAGE_STEM="$(basename "${OUT%.qcow2}")"
install -m 0444 "$kernel" "$(dirname "$OUT")/${IMAGE_STEM}-vmlinuz"

# Make the initramfs byte-reproducible before it goes beside the image.
#
# WHY THIS IS NOT A TIDINESS EXERCISE. The launch measurement covers the kernel,
# the initrd and the command line. A customer can only conclude anything from a
# measurement if they can rebuild the image themselves and get the same number —
# otherwise the measurement identifies an image they cannot inspect, and every
# claim resting on it reduces to trusting whoever built it. A non-reproducible
# build is fatal to the whole attestation story — it is the hinge the rest
# hangs on.
#
# WHAT WAS ACTUALLY WRONG. Measured on two real builds of the same image, whose
# kernels were byte-identical and whose initrds were not:
#
#   - the gzip header carries mkinitramfs's temp filename, which contains a
#     random suffix, and the build time
#   - inside the cpio, dev/inode numbers vary run to run
#   - and file mtimes are the build's own clock
#
# 1150 bytes differed out of 17,336,320 — 0.007%. Every one of them metadata.
# The extracted trees were identical in content, mode, ownership, type, size and
# symlink target: no file differed, anywhere.
#
# THE FIX, and each part was needed — this was established by applying them one
# at a time to two real initrds and comparing:
#
#   --reproducible      zeroes dev and inode. Gets 1150 down to 185 and no
#                       further; it does NOT normalise mtime, despite the name.
#   touch -h -d @EPOCH  pins every mtime, including symlinks (-h), which is what
#                       closes the remaining 185.
#   gzip -n             drops the filename and timestamp from the gzip header.
#
# With all three, two initrds built a day apart became byte-identical.
#
# SOURCE_DATE_EPOCH is the reproducible-builds convention and is honoured if the
# caller sets it; the default is fixed rather than "now" so that forgetting to
# set it cannot silently reintroduce the problem.
if [[ -n "$initrd" ]]; then
  say "Normalising the initramfs so the measurement can be reproduced"
  REPRO_EPOCH="$SOURCE_DATE_EPOCH"
  REPRO_DIR="$WORK/initrd-repro"
  rm -rf "$REPRO_DIR" && mkdir -p "$REPRO_DIR"

  # An early-microcode cpio is prepended UNCOMPRESSED to the initrd on some
  # distributions, and unpacking only the compressed part would silently drop
  # it. Refuse rather than produce an image that boots without microcode.
  head -c2 "$initrd" | od -An -tx1 | grep -q "1f 8b" ||
    fail "the initramfs does not begin with a gzip header, so it may carry an early-microcode cpio this does not handle: $initrd"

  gunzip -c "$initrd" > "$REPRO_DIR/raw.cpio"
  mkdir -p "$REPRO_DIR/tree"
  ( cd "$REPRO_DIR/tree" && cpio -idm --quiet < "$REPRO_DIR/raw.cpio" )
  find "$REPRO_DIR/tree" -exec touch -h -d "@$REPRO_EPOCH" {} +
  ( cd "$REPRO_DIR/tree" && find . | LC_ALL=C sort |
      cpio -o -H newc --reproducible --quiet ) > "$REPRO_DIR/norm.cpio"
  gzip -n -9 -c "$REPRO_DIR/norm.cpio" > "$REPRO_DIR/initrd.img"

  # The round trip must not lose anything. cpio extraction and repacking can
  # drop device nodes or hardlinks when it goes wrong, and an initramfs missing
  # a device node fails at boot in a way that looks like something else
  # entirely.
  before=$(gunzip -c "$initrd" | cpio -t --quiet 2>/dev/null | LC_ALL=C sort | wc -l)
  after=$(gunzip -c "$REPRO_DIR/initrd.img" | cpio -t --quiet 2>/dev/null | LC_ALL=C sort | wc -l)
  [[ "$before" == "$after" ]] ||
    fail "normalising the initramfs changed its contents: $before entries before, $after after"

  install -m 0444 "$REPRO_DIR/initrd.img" "$(dirname "$OUT")/${IMAGE_STEM}-initrd.img"
  echo "  initramfs normalised: $after entries, sha256 $(sha256sum "$REPRO_DIR/initrd.img" | cut -c1-16)…"
fi

say "Packing the image"
install -d -m 0700 "$(dirname "$OUT")"

# Refuse an image something is still holding open.
#
# Instances overlay this file, so a running guest keeps a lock on it. qemu-img
# does notice, but reports it as
#
#   Failed to get "write" lock Is another process using the image
#
# buried in twenty lines of libguestfs advice about enabling trace debugging —
# after the build has already spent ten minutes bootstrapping. Say it up front
# and say what to do, because the fix is to stop whatever holds the file, not to
# debug libguestfs.
if [[ -e "$OUT" ]] && command -v fuser >/dev/null && fuser "$OUT" >/dev/null 2>&1; then
  fail "$OUT is open by another process (most likely a guest still running from it).
     Stop it first, or build to a different OUT= and swap the result in."
fi
if [[ "$VERITY" == "1" ]]; then
  # A raw filesystem with its hash tree appended, rather than a partitioned
  # qcow2.
  #
  # No partition table, because verity covers a device and a partition table
  # would sit outside what it covers — an operator could rewrite it while the
  # hash still matched. No qcow2, because the hash must describe the bytes the
  # kernel reads, and a compressed container does not present those bytes.
  #
  # The hash tree lives in the same file, past the data, so an instance is one
  # artifact rather than two that can drift apart.
  # The same reasoning as the initramfs above, applied to the thing the root
  # hash actually describes. mke2fs writes a random filesystem UUID and a random
  # directory hash seed on every run, and every file keeps whatever mtime it
  # happened to get during bootstrap. All three change the bytes, so all three
  # change the root hash, so two builds of identical inputs disagree and the
  # reader concludes the published measurement does not describe the source.
  #
  # mke2fs -d rather than virt-make-fs, because it is the only one of the two
  # that exposes the knobs: -U and -E hash_seed take the UUIDs below, both
  # derived from nothing and fixed forever.
  # Two builds of this image were compared file by file. Of 4,499 files, five
  # differed, and every one was a record of the build rather than part of the
  # system: three logs, one cache, and one identifier. They are removed here
  # rather than tolerated, because a difference that is only noise is still a
  # different root hash, and a reader comparing hashes cannot tell the two
  # apart.
  say "Removing what the build wrote about itself"
  rm -f "$WORK/root"/var/log/bootstrap.log \
        "$WORK/root"/var/log/alternatives.log \
        "$WORK/root"/var/log/dpkg.log \
        "$WORK/root"/var/cache/ldconfig/aux-cache \
        "$WORK/root"/var/lib/systemd/random-seed

  # /var/lib/dbus/machine-id is not noise. debootstrap writes a random one into
  # the image, so it is fixed at build time and therefore SHARED by every
  # instance launched from that image — a stable identifier common to machines
  # that are supposed to be indistinguishable. Pointing it at /etc/machine-id,
  # which is deliberately empty so systemd generates one on first boot, gives
  # each instance its own and removes the difference between builds at the same
  # time. Both matter; only one of them shows up as a hash mismatch.
  rm -f "$WORK/root"/var/lib/dbus/machine-id
  ln -sf /etc/machine-id "$WORK/root"/var/lib/dbus/machine-id

  say "Normalising timestamps so the system image can be reproduced"
  find "$WORK/root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

  say "Building the verified system image"
  RAW="${OUT%.qcow2}.img"
  rm -f "$RAW"
  truncate -s "$SIZE" "$RAW"
  # -O ^has_journal: a journal records the history of writes to a filesystem
  # that is mounted read-only and verified block by block. It cannot be written
  # to, and its presence alone perturbs the bytes.
  # Turn OFF the features that newer versions of mke2fs turn on and older ones
  # do not, so the filesystem depends on what we asked for rather than on which
  # distribution the builder was running.
  #
  # Found by building the same image on two distributions and comparing: the
  # newer e2fsprogs adds orphan_file and metadata_csum_seed, which change the
  # metadata size and therefore the free-block count — so two filesystems with
  # byte-identical contents described themselves differently.
  #
  # Disabled rather than listed. Naming the features we want ADDS to the
  # defaults rather than replacing them, so an explicit list still inherits
  # whatever a future version decides to switch on; only ^feature removes
  # anything. That also means this list will need extending when a new default
  # appears, which is the honest cost of a tool whose output depends on its
  # version.
  #
  # has_journal is off for a different reason: a journal records the history of
  # writes to a filesystem that is mounted read-only and verified block by
  # block. It cannot be written to, and its presence alone perturbs the bytes.
  mke2fs -q -t ext4 -d "$WORK/root" \
    -U "$FIXED_FS_UUID" -E hash_seed="$FIXED_HASH_SEED" \
    -O ^has_journal,^orphan_file,^metadata_csum_seed \
    -I 256 -m 0 "$RAW" ||
    fail "could not build the system filesystem"

  # And the timestamps the filesystem records about itself. Newer versions
  # honour SOURCE_DATE_EPOCH here and older ones stamp the real clock, so the
  # image otherwise records when it was built — which is the same class of
  # problem as recording where.
  for field in mkfs_time lastcheck mtime; do
    debugfs -w -R "ssv $field @$SOURCE_DATE_EPOCH" "$RAW" >/dev/null 2>&1 || true
  done

  # Where the data ends and the hash tree begins. Written down and passed on the
  # command line, because a reader that guesses this reads hash blocks as data
  # and fails in a way that looks like corruption.
  DATA_BYTES=$(stat -c%s "$RAW")
  # --salt, because veritysetup generates a random one per run and mixes it into
  # every hash, so two identical filesystems still get different root hashes.
  # Found by building twice: the 2GiB filesystem compared byte-identical and the
  # images first differed 17 bytes past the end of it, inside the verity
  # superblock. A verity salt defends against precomputed hash tables for an
  # attacker who can choose file contents; here the contents are fixed at build
  # time and published, so there is nothing to precompute against, and a value
  # the reader cannot reproduce costs more than it protects.
  say "Hashing every block of the system image"
  VERITY_OUT=$(veritysetup format "$RAW" "$RAW" --hash-offset="$DATA_BYTES" \
                 --salt="$FIXED_VERITY_SALT" --uuid="$FIXED_VERITY_UUID" 2>&1) || {
    echo "$VERITY_OUT" >&2
    fail "could not build the verity hash tree"
  }
  ROOTHASH=$(echo "$VERITY_OUT" | awk '/Root hash:/ {print $3}')
  [[ -n "$ROOTHASH" ]] || fail "veritysetup produced no root hash"
  chmod 0444 "$RAW"

  printf '%s' "$ROOTHASH"     > "${OUT%.qcow2}.roothash"
  printf '%s' "$DATA_BYTES"   > "${OUT%.qcow2}.hashoffset"

  say "Image built (verified)"
  echo "  $RAW"
  echo "  root hash   $ROOTHASH"
  echo "  hash offset $DATA_BYTES"
  echo
  echo "The root hash goes on the kernel command line, which IS measured. So the"
  echo "measurement now covers the whole root filesystem — the agent binary"
  echo "included — and not merely the kernel and initramfs."
else
  virt-make-fs --format=qcow2 --size="$SIZE" --type=ext4 --partition=gpt "$WORK/root" "$OUT"
  chmod 0400 "$OUT"
fi

# A verified build already reported itself, and reports different artifacts:
# there is no qcow2, and the number that matters is the root hash rather than a
# digest of a file. Falling through to here printed a missing-file error at the
# end of a successful build, which is exactly how a good build gets read as a
# failed one.
if [[ "$VERITY" != "1" ]]; then
say "Image built"
echo "  $OUT"
sha256sum "$OUT" | awk '{print "  sha256 " $1}'
echo "  $(dirname "$OUT")/${IMAGE_STEM}-vmlinuz"
[[ -f "$(dirname "$OUT")/${IMAGE_STEM}-initrd.img" ]] && echo "  $(dirname "$OUT")/${IMAGE_STEM}-initrd.img"
fi

cat <<NEXT

The image content hash above identifies the file. It is NOT the launch
measurement — that covers the firmware, the guest's initial memory and the
launch configuration, and only the hardware can compute it.

To get the measurement, boot one instance from this image on SEV-SNP hardware
and read it out of the report the guest publishes:

  curl -s <instance>/api/attestation | jq -r .report \\
    | base64 -d | xxd -s 0x90 -l 48 -p

That endpoint stays available for the life of the instance, so it answers
whether the instance is new or has been in use for a year.

Reproducing that number yourself additionally requires the kernel command line
the instance was booted with, because the measurement covers it. Publish it
alongside the measurement; with VERITY=1 it must carry the root hash written
beside this image.

Pin the value as the expected measurement. From then on an instance that
launches anything else fails the comparison, and what to do about that is a
decision for whoever operates the hardware.
NEXT
