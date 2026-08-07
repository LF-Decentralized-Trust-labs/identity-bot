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
# The digest of the shared runtime this image will accept. "unpinned" builds an
# image that runs whatever it is given — for bring-up only, and it says so on
# every boot.
KERI_RUNTIME_DIGEST=${KERI_RUNTIME_DIGEST:-unpinned}
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
# This script runs on a shared machine, so it does not get to leave it worse
# than it found it.
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
[[ -n "$AGENT_BINARY" ]] || fail "set AGENT_BINARY to a linux/amd64 agent build: identity-agent-core for an individual image, org-backend for an organisation one. Both serve the same contract on :5050, so the image is identical apart from which one is inside it — which is the whole reason they must be separate images with separate measurements"
[[ -x "$AGENT_BINARY" ]] || fail "AGENT_BINARY is not executable: $AGENT_BINARY"

file "$AGENT_BINARY" | grep -q 'ELF 64-bit' || fail "AGENT_BINARY is not a Linux binary — build with GOOS=linux GOARCH=amd64"

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
  for t in mke2fs veritysetup; do
    command -v "$t" >/dev/null || fail "missing $t (apt-get install e2fsprogs cryptsetup-bin)"
  done
else
  command -v virt-make-fs >/dev/null || fail "missing virt-make-fs (apt-get install libguestfs-tools)"
fi

mknod "$WORK/probe-dev" c 1 3 2>/dev/null ||
  fail "$WORKROOT cannot hold device nodes (probably mounted nodev: $(findmnt -no FSTYPE,OPTIONS --target "$WORKROOT" 2>/dev/null)) — debootstrap needs them. Set WORKROOT= to a directory on an ordinary filesystem."
rm -f "$WORK/probe-dev"

say "Bootstrapping a minimal $SUITE root"
debootstrap --variant=minbase \
  --include=systemd,systemd-sysv,ca-certificates,dbus,linux-image-amd64,initramfs-tools,cryptsetup-bin,dmsetup,e2fsprogs \
  "$SUITE" "$WORK/root" >/dev/null

# The KERI runtime is NOT in this image. It is one read-only, digest-pinned
# mount shared by every instance on the host — identical in all of them, never
# written to, and verified against a digest baked into this image before use, so
# copying it into each one bought nothing but gigabytes.

say "Installing the agent"
install -D -m 0755 "$AGENT_BINARY" "$WORK/root/usr/local/bin/identity-agent-core"

# The front end goes inside the image, which means inside the measurement.
#
# That is the correct consequence and worth being deliberate about: the bundle
# is code the agent serves to a browser, so it belongs to what this instance is,
# and a change to it must change what the instance measures. The alternative --
# mounting it from the host like the KERI runtime -- would let the operator
# swap the interface a person types their details into without the measurement
# moving. The KERI runtime can be shared because it is identical everywhere and
# never touched; a front end is neither.
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

# Mount points must exist in the image, because a verified root is read-only and
# systemd cannot create one at boot. Missing, they fail as "Read-only file
# system" — which reads like a permissions problem rather than a missing
# directory, and takes the agent down with them through the dependency chain.
install -d -m 0755 "$WORK/root/opt/keri"

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
cat > "$WORK/root/etc/systemd/system/opt-keri.mount" <<'UNIT'
[Unit]
Description=Shared KERI runtime (read-only)
Before=keri-driver.service

[Mount]
What=keri
Where=/opt/keri
Type=9p
Options=trans=virtio,version=9p2000.L,ro

[Install]
WantedBy=multi-user.target
UNIT
ln -sf /etc/systemd/system/opt-keri.mount \
  "$WORK/root/etc/systemd/system/multi-user.target.wants/opt-keri.mount"

# pysodium finds libsodium through ctypes.util.find_library, which consults the
# ldconfig cache rather than LD_LIBRARY_PATH — so the runtime's lib directory
# has to be a search path the cache knows about, refreshed once the mount is
# there.
echo "/opt/keri/lib" > "$WORK/root/etc/ld.so.conf.d/keri-runtime.conf"

# The writable file the driver's loader cache is bound over.
#
# Created here rather than by the unit, because the bind is set up when the
# unit's namespace is built — which is before anything the unit runs. A source
# that does not exist yet makes the unit fail to start with a message about the
# mount rather than about the file.
install -d -m 0755 "$WORK/root/etc/tmpfiles.d"
cat > "$WORK/root/etc/tmpfiles.d/keri-runtime.conf" <<'TMPF'
d /run/keri 0755 root root -
f /run/keri/ld.so.cache 0644 root root -
TMPF

cat > "$WORK/root/usr/local/bin/verify-keri-runtime" <<'VERIFY'
#!/bin/sh
# The digest this image expects. Baked in at build time: an instance that is
# handed a different runtime refuses to start rather than running provider-
# supplied code it cannot vouch for.
set -eu
EXPECTED="__KERI_RUNTIME_DIGEST__"
[ "$EXPECTED" = "unpinned" ] && {
  echo "keri-runtime: WARNING unpinned image — the runtime is not being verified" >&2
  exit 0
}
# LC_ALL=C to match how the digest was computed: sort order is locale-
# dependent, and disagreeing about it looks exactly like tampering.
ACTUAL=$(cd /opt/keri && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d" " -f1)
[ "$ACTUAL" = "$EXPECTED" ] || {
  echo "keri-runtime: FATAL expected sha256:$EXPECTED but mounted sha256:$ACTUAL" >&2
  exit 1
}
VERIFY
chmod 0755 "$WORK/root/usr/local/bin/verify-keri-runtime"

# The driver is supervised in its own right rather than spawned as a child of
# the agent — the agent's own code calls that the robust model, because a
# backend restart then cannot orphan a driver or contend for the keystore.
cat > "$WORK/root/etc/systemd/system/keri-driver.service" <<'UNIT'
[Unit]
Description=KERI driver (keripy, from the shared runtime)
After=network.target opt-keri.mount
Requires=opt-keri.mount

[Service]
Environment=KERI_DRIVER_PORT=9999
# The runtime carries its own interpreter and shared objects: this image has
# no Python at all.
Environment=LD_LIBRARY_PATH=/opt/keri/lib
BindPaths=/run/keri/ld.so.cache:/etc/ld.so.cache
Environment=PYTHONHOME=/opt/keri
Environment=PYTHONPATH=/opt/keri/driver/venv/lib/python3.11/site-packages
ExecStartPre=/usr/local/bin/verify-keri-runtime
# The loader cache has to be rebuilt once the runtime is mounted, and on a
# verified root /etc cannot be written. So this unit gets a writable copy of
# that one file and nothing else, bound over the real one: the processes that
# read it are inside the same namespace and see it.
#
# -C matters as much as the bind. ldconfig writes a temporary file NEXT TO its
# output and renames it, so pointing it at /etc/ld.so.cache still needs a
# writable /etc no matter what is bound over the file itself. Writing to the
# run directory keeps both the temporary file and the rename where they are
# allowed.
#
# One file rather than a writable /etc, because the reason /etc is read-only is
# the reason the image can be verified at all.
ExecStartPre=/sbin/ldconfig -C /run/keri/ld.so.cache
ExecStart=/opt/keri/bin/python3 /opt/keri/driver/server.py
Restart=always
RestartSec=2
WorkingDirectory=/opt/keri/driver

[Install]
WantedBy=multi-user.target
UNIT
ln -sf /etc/systemd/system/keri-driver.service \
  "$WORK/root/etc/systemd/system/multi-user.target.wants/keri-driver.service"

cat > "$WORK/root/etc/systemd/system/identity-agent.service" <<'UNIT'
[Unit]
Description=Identity Agent (sealed instance)
After=network-online.target keri-driver.service
Wants=network-online.target keri-driver.service

[Service]
Environment=AGENT_DATA_DIR=/var/lib/identity-agent
Environment=PORT=5050
# Measured on the host: the Go agent idles at 60MB without these and 29MB with
# them, and stayed healthy through inception, profile writes and a full
# adoption. Most of the difference was heap the collector had no reason to
# return — which is the right default for a laptop and the wrong one where many
# of these run side by side.
Environment=GOMEMLIMIT=40MiB
Environment=GOGC=50
Environment=KERI_DRIVER_EXTERNAL=1
Environment=KERI_DRIVER_PORT=9999
Environment=FLUTTER_WEB_DIR=/usr/share/identity-agent/web
# This instance is only ever reached through the proxy in front of it, so the
# proxy is the only party that knows the name, the scheme and the path prefix a
# person actually used. Without this the agent guesses from a local interface
# and publishes an address in its OOBI that resolves nowhere.
#
# Safe to state HERE and nowhere else: an instance is not directly reachable, so
# nothing can reach it with forwarding headers of its own choosing. An agent
# somebody can reach directly must not set this.
Environment=TRUST_FORWARDED_HEADERS=1
ExecStart=/usr/local/bin/identity-agent-core
Restart=always
RestartSec=2
# The agent is the only thing this VM is for.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/identity-agent
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
ln -sf /etc/systemd/system/identity-agent.service \
  "$WORK/root/etc/systemd/system/multi-user.target.wants/identity-agent.service"

# The guest gets its address by DHCP from QEMU's user-mode network. Without
# this a minimal Debian brings up no interface at all, so the agent starts,
# listens on localhost inside the VM, and nothing outside can ever reach it —
# which looks exactly like a slow boot from the provisioning side.
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

sed -i "s/__KERI_RUNTIME_DIGEST__/$KERI_RUNTIME_DIGEST/" "$WORK/root/usr/local/bin/verify-keri-runtime"

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
# sev-guest is not a driver for hardware that might be here — it is the reason
# this instance is worth renting. Without it /dev/sev-guest never appears, the
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
  # the failure that hides, because nothing about it looks broken. An instance
  # that cannot attest is not a degraded black box; it is an ordinary VM
  # somebody is being charged for as a sealed one.
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
  mke2fs -q -t ext4 -d "$WORK/root" \
    -U "$FIXED_FS_UUID" -E hash_seed="$FIXED_HASH_SEED" \
    -O ^has_journal -I 256 -m 0 "$RAW" ||
    fail "could not build the system filesystem"

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
                 --salt="$FIXED_VERITY_SALT" 2>&1) || {
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
