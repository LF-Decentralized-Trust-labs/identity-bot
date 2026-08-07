# Reproducing a sealed image, and checking a measurement yourself

An Identity Agent can run on hardware somebody else owns, inside a confidential
VM whose memory that owner cannot read. It proves what it is by publishing an
attestation report, and a client checks that report before trusting the machine.

Most of that chain you can verify on your own. The report's signature checks
against the certificate the processor's manufacturer issued for that exact part,
and that certificate against the manufacturer's root. Either it verifies or it
does not, and no part of that requires trusting whoever runs the hardware.

One step is different. The report contains a **launch measurement** — a digest
over the firmware, kernel, initial filesystem and launch arguments the machine
started with. A client compares it against a measurement it expects. That
comparison is only as good as knowing which measurement is the right one, and
until you can build the image yourself, that is a fact you are being told rather
than one you have checked.

**This directory exists so you can check it.**

## What is here

`build-sealed-image.sh` produces the image a sealed instance runs. Given the same
inputs it produces the same bytes, so it produces the same measurement.

## Reproducing a measurement

You need a Linux host and root, plus `debootstrap`, `e2fsprogs`,
`cryptsetup-bin`, `file`, `cpio` and `gzip`. (`libguestfs-tools` is needed only
for the unverified path below.) The script checks all of these before it starts
rather than failing ten minutes in.

```sh
VERITY=1 \
AGENT_BINARY=./identity-agent-core \
WEB_BUNDLE=./web \
KERI_RUNTIME_DIGEST=<the digest published for that image> \
OUT=./image.img \
  ./build-sealed-image.sh
```

**`VERITY=1` is what makes the measurement worth checking, and it is not the
default.** Without it the measurement covers only the kernel, the initramfs and
the command line — so two images differing entirely in their root filesystem,
agent binary included, produce the same measurement. That was demonstrated
rather than assumed. A build without it succeeds, boots and attests, and proves
nothing about the software inside. Always pass it.

`WEB_BUNDLE` must be a `flutter build web --pwa-strategy=none` output: the
script rejects a bundle carrying a service worker, because one would cache
itself and keep serving an old app after the image is replaced.

To reproduce a specific published image you need the same values for all of the
above — the agent binary built from the stated commit, the same web bundle, the
same pinned runtime digest — and the same values for the parameters that have
defaults: `SIZE` (default `2G`), `SUITE` (default `bookworm`) and
`SOURCE_DATE_EPOCH` (default `1700000000`). All three change the output bytes.
The per-image values are published alongside the measurement rather than here,
because they change per image and this script does not.

**One input is not a parameter: the Debian archive.** `debootstrap` fetches
packages from your host's configured mirror at build time, unpinned, so a build
today and a build in three months produce different bytes from identical
arguments. To reproduce an older image, point the host at the matching
`snapshot.debian.org` date first. This is the most likely cause of a first
mismatch.

### Outputs

With `VERITY=1` and `OUT=./image.img` the build writes:

| File | What it is |
|---|---|
| `image.img` | the raw system image, with its hash tree appended past the data |
| `image.roothash` | the root hash covering every block of it |
| `image.hashoffset` | where the data ends and the hash tree begins |
| `image-vmlinuz` | the kernel it boots |
| `image-initrd.img` | the initial filesystem, normalised to be reproducible |

The **root hash** goes on the kernel command line, and the command line is
inside the measurement — so the measurement covers the entire system image, the
agent binary included, and not merely the kernel.

### The command line is part of the measurement

Because the measurement covers the kernel command line, reproducing the image
is necessary but not sufficient: you also need the exact command line the
instance was booted with, including the `verity.roothash=` and
`verity.hashoffset=` values above. Whoever publishes a measurement publishes
that command line with it. This script does not construct one — it produces the
image and the values that go into it, and what boots them is outside it.

## Getting the launch measurement itself

The root hash is not the launch measurement. The measurement covers the guest's
initial memory and launch configuration, and **only the processor can compute
it**. Reproducing the image gives you identical bytes; obtaining the measurement
means booting the image on SEV-SNP hardware and reading it out of a report:

```sh
curl -s http://<instance>/api/attestation \
  | python3 -c 'import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)["report"])[0x90:0xC0].hex())'
```

That endpoint also returns the same value in a `measurement` field. The slice
above reads it out of the signed report instead, because the `measurement` field
is the instance's own account of itself while the report is the part the
processor signed — and it is the signed part a verifier should be comparing.

If that value matches the one published for the image you just built, then the
published measurement describes the source you can read, and a client accepting
it is accepting something you have verified rather than something you were told.

## What is deliberately not here

**How any particular operator runs this.** Their hardware, hosting, network and
provisioning are not needed to reproduce an image, and would not help you check
one. What you need to verify the claim is here; what describes somebody's
operation is not, and its absence takes nothing away from the check.

**Reproducibility across build environments has not been demonstrated.** The
build fixes the inputs that are known to vary within one environment: every
timestamp comes from `SOURCE_DATE_EPOCH`, the initramfs is repacked with sorted
entries and no embedded name or time, and the filesystem is built with a fixed
UUID and a fixed directory hash seed rather than the random ones the tools
generate per run. Whether a different distribution or toolchain version produces
the same bytes is untested, and until somebody does it, a mismatch is as likely
to mean a toolchain difference as a problem with the image. If you try it, the
result is worth reporting either way.

## The honest summary

You can verify, with no trust in the operator: that a report came from a genuine
processor, that it describes a machine running an image with a particular
measurement, that the report belongs to the connection you are using, and that
the guest was not started in a debuggable state.

With this directory you can additionally verify that the published measurement
corresponds to source you can read.

What remains is knowing which measurement *should* be accepted for a given
service — a statement about whom you trust to publish it. That is a smaller
thing to trust than the whole chain, and naming it is better than leaving it to
be discovered.
