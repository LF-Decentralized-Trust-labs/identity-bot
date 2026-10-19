# ADR-043 — A developer mode rooted in a separate trust anchor, not a mode flag

**Status:** Accepted — records the decision; not yet implemented (each part lands with its own code).
**Date:** 2026-10-18
**Relates to:** ADR-011 (build versioning: development vs release builds), ADR-027 (hardware-gated signing key custody), ADR-028 (reporting what a machine can protect a key with), ADR-042 (how an agent is reached; the confidential-VM substrate)

## Context

Identity Agents prove their software to one another by attestation: a counterparty, a management surface, or
a peer wants evidence that the code on the other side is what it claims to be before it trusts it. That is the
right posture for production, and it is tested the right way — on real hardware. But it makes *functional*
development painful. To exercise an end-to-end flow — founding an identity, creating a delegated AI agent,
pairing, a login — every participant wants the others to attest, and attestation is exactly what a developer's machine
often cannot produce. Only some platforms can attest software legitimacy at all (a mobile platform with app
attestation, a confidential VM on a CPU with a hardware root of trust); a plain desktop cannot (ADR-028). So
an end-to-end functional test stalls on a chicken-and-egg: nobody will talk to anybody because nobody can
prove their software.

The obvious shortcut — a "developer mode" that turns attestation off — is correct in spirit and dangerous in
the naïve form. If the dev/prod distinction is a self-reported field ("I am a dev build, trust me without
attestation"), nothing stops a build from asserting it. That is bad anywhere, and it is worse here for a
specific reason: **this core is open source.** Anyone can clone it and recompile it with the production flag
set. A compiled mode constant is therefore not a security boundary against a determined party — it is at best
a convenience marker. A developer mode has to be built so that a dev build *cannot* be accepted by production
even though its source is public and recompilable.

Surveying how the confidential-computing field handles this (enclave SDKs and their simulation modes,
confidential-VM debug families, remote-attestation services) shows one consistent pattern: the dev/prod
boundary is never a self-assertion. It is always a credential the dev build *cannot forge* — either the
hardware stamps an unclearable debug marker into the signed attestation, or, where there is no hardware root,
the two sides are rooted in *different trust anchors* and each accepts only its own.

## Decision

### 1. Build-time mode, selecting a trust anchor — not a runtime flag

A build has a mode, `prod` or `dev`, fixed at build time (consistent with ADR-011's development-vs-release
distinction). The mode is a *build input* that selects the artifact's **trust anchor**: which signing
identity it carries, which roots it trusts, and — for a sealed instance — which measurement allowlist it
accepts. It also bakes in a visible `MODE` marker (UI, logs, provenance). The marker is defense-in-depth and
legibility; it is **not** the boundary. The boundary is the trust anchor.

### 2. Dev and prod are rooted in separate trust anchors; each trusts only its own

A production verifier carries production roots only; a development verifier carries development roots only. A
dev-rooted peer, credential, or measurement is therefore simply not in a prod verifier's trust set, and vice
versa — independent of any field anyone reports. Because the anchors are disjoint, a recompiled public-source
build claiming `MODE=prod` still presents a dev-rooted (or no) credential, and production rejects it on the
credential, not on the claim. Verification fails closed.

### 3. Two developer modes, by whether a hardware root is present

- **Mock / off** — on a machine with no hardware root (a desktop, CI). No attestation can be produced;
  separation rests entirely on the dev trust anchor the prod verifier does not carry. This is the mode that
  lets functional flows run on a developer's own machine.
- **Debug-attested** — on a confidential VM with a hardware root (ADR-042's substrate). Real attestation
  flows, but with the hardware's debug marker set, which a production verifier rejects; the build additionally
  uses a dev measurement allowlist and a dev signing identity. This keeps the attestation-*verification* code
  path exercised in development instead of only in production.

### 4. Non-interoperability holds at every layer — peer, service, and data at rest

A development-mode Identity Agent and a production one refuse each other as peers (§2). The same holds for shared services (a
production witness, relay, or tunnel accepts only prod-rooted callers; development uses its own
development-scoped instances) and for data at rest. Where a sealed instance derives its storage key from the
hardware, it must derive it so that a debug/dev instance *cannot* derive the production key — binding the
guest policy (including the debug marker) into the key-derivation request, so the hardware itself refuses to
produce the production key for a debug guest, and binding a mode tag into each record's authenticated
associated data, so a cross-mode record fails to decrypt cryptographically rather than by a check the code
could skip.

### 5. Protocol-level domain separation for unattested clients

An unattested client (a desktop or mobile app in mock/off) has no hardware credential, and in a
decentralized-identifier system there is no central authority issuing it a client certificate. Its separation
from production is therefore not a certificate but three things together: a dev build defaults to disjoint
development roots, witnesses/watchers, and endpoints, so it never *accidentally* reaches production; every
signed event and handshake carries an environment domain separator, so a signature made in development is not
valid in production even if a key is reused; and any high-trust action (storage unlock, founding, anything
consequential) requires a genuine hardware attestation that an unattested build cannot forge. An unattested
client is thus untrusted-by-definition for anything consequential, and kept out of production by
default-isolation plus domain separation — not by a pretence that an open-source client binary can be pinned
to production.

### 6. Provisioning is authenticated

Creating an Identity Agent instance, or a delegated AI agent, is an authenticated operation, so that "which
mode, under whose authority" is established at creation rather than asserted afterward by an unauthenticated
caller.

## Consequences

- Functional development runs on any machine, with no attestation in the loop, and cannot touch production —
  the property that makes it safe is cryptographic, not a flag.
- Production attestation and the sealed-instance security model are unchanged; they continue to be tested on
  real hardware.
- Signing genuinely diverges by mode (a dev build carries a dev signing identity); this is an additional,
  free separation layer at the install/update channel.
- Development needs its own scoped infrastructure (development-rooted witnesses, relays, tunnels). A shared
  production service cannot be protected by a mode field.
- Deployments must hold production trust-root custody to a high bar (hardware-backed roots; multi-party
  control over minting, rotation, and release signing) and keep reproducible builds so a measurement maps back
  to source. These are deployment concerns; this ADR fixes only the protocol/core mechanism the modes rest on.

## What is shipped, and what is still to build

This ADR records the decision; the mechanism is not yet implemented in the core. Shipped today: the
confidential-VM substrate and its ingress (ADR-042), hardware-gated key custody (ADR-027), and capability
reporting for what a machine can attest (ADR-028). Still to build: the mode-selected trust anchor, the two
developer modes, cross-mode refusal at the service and data-at-rest layers, the domain separator in signed
events, and authenticated provisioning. Each lands with its own code and tests, and is not implied by this
record.
