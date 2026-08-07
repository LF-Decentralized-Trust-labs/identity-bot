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

You need a Linux host with `debootstrap`, `libguestfs-tools`, `qemu-utils` and
`cryptsetup-bin`, and root.

```sh
VERITY=1 \
AGENT_BINARY=./identity-agent-core \
WEB_BUNDLE=./web \
KERI_RUNTIME_DIGEST=<the digest published for that image> \
OUT=./image.qcow2 \
  ./build-sealed-image.sh
```

Every input is a parameter and there are no hidden ones. To reproduce a specific
published image you need the same values for all of them: the agent binary built
from the stated commit, the same web bundle, and the same pinned runtime digest.
Those are published alongside the measurement rather than here, because they
change per image and this script does not.

The build prints a **root hash** covering the whole root filesystem. That hash
goes on the kernel command line, and the command line is inside the measurement —
so the measurement covers the entire system image, the agent binary included, and
not merely the kernel.

## Getting the launch measurement itself

The root hash is not the launch measurement. The measurement covers the guest's
initial memory and launch configuration, and **only the processor can compute
it**. Reproducing the image gives you identical bytes; obtaining the measurement
means booting the image on SEV-SNP hardware and reading it out of a report:

```sh
curl -s http://<instance>/api/attestation \
  | python3 -c 'import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)["report"])[0x90:0xC0].hex())'
```

If that value matches the one published for the image you just built, then the
published measurement describes the source you can read, and a client accepting
it is accepting something you have verified rather than something you were told.

## What is deliberately not here

**How any particular operator runs this.** Their hardware, hosting, network and
provisioning are not needed to reproduce an image, and would not help you check
one. What you need to verify the claim is here; what describes somebody's
operation is not, and its absence takes nothing away from the check.

**Reproducibility across build environments has not been demonstrated.** Repeated
builds in one environment produce byte-identical output. Whether a different
distribution or toolchain version produces the same bytes is untested, and until
somebody does it, a mismatch is as likely to mean a toolchain difference as a
problem with the image. If you try it, the result is worth reporting either way.

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
