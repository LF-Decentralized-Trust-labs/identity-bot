# ADR-028: Reporting What a Machine Can Protect a Key With

**Status:** Accepted
**Date:** 2026-07-29
**Extends:** ADR-027 (Hardware-Gated Signing Key Custody)

## Context

ADR-027 established that a hardware key gates access to the software Ed25519 signing key, since no consumer secure element can hold Ed25519 itself. It assumed the platform layer could report whether such hardware was available.

It cannot, and the way it fails is worse than not reporting at all.

`PlatformSigner.Available() bool` returns one bit. Three of the five platform implementations — Linux, Windows, Android — return a hardcoded `false`. That is not detection finding nothing; it is detection nobody wrote. Downstream, a `false` is indistinguishable from "this machine has no security hardware", which is untrue for the large majority of those machines: Windows 11 cannot ship without a TPM 2.0, and Android has had a TEE-backed keystore since 6.0.

The same conflation appears in widely-used reference code. Google's `go-attestation` states it plainly: *"If we fail to initialize the Platform Crypto Provider, we assume a TPM is not present."* Anyone reaching for the obvious implementation inherits the defect.

It matters because a downstream consumer now depends on the answer. A device's ability to protect a key sets a ceiling on the confidence its owner's identity can be assigned, so a wrong "no hardware" is not a missing optimisation — it is a permanent, invisible penalty applied to somebody for a fact nobody checked.

Measurements that motivated this, all taken on real hardware on 2026-07-29:

- On an AMD SEV-SNP host, `/dev/sev` is `0600 root:root`. An unprivileged `stat` **succeeds** while `open` is **denied**. Asking one question — "can I open it?" — collapses "there is hardware here I cannot reach" into "there is no hardware". On Linux this is the common case, not an edge case: the standard tpm2-tss udev rule ships `/dev/tpmrm0` as `0660 root:tss`.
- On an Apple M4 Pro with cgo enabled, enclave key creation fails with `OSStatus -34018` (`errSecMissingEntitlement`) — *after* the enclave has successfully produced a key. The hardware works; persisting the key to the keychain is what fails, because the binary carries no entitlement. Reported as a bare `false`, this reads as a Mac with no Secure Enclave.

## Decision

Introduce a capability vocabulary alongside the signer, with one rule above all others:

**Absent must be proven. Unknown is the default.**

Four states, and the distinctions are the point:

| Status | Meaning |
|---|---|
| `Usable` | proven — a key was actually created in hardware and discarded, or a report actually obtained |
| `Present` | hardware answered but cannot be used now: unprovisioned, locked out, malfunctioning |
| `Absent` | positively established. **The only status a detector may not infer** |
| `Unknown` | could not be determined — no permission, no API, an unrecognised error, or no detector on this platform |

`RootKeyPermitted()` returns true only for `Usable`. Not for `Unknown`: guessing permissively puts an identity in a plain file, and unlike most errors nobody discovers it until the file has been copied.

A platform with no detector returns `Unknown` with the detail *"this says nothing about whether the machine has security hardware"* — not `Absent`.

The Linux detector asks "is it there" and "can I use it" as separate questions, checks confidential computing before the TPM (sealed infrastructure has no TPM at all, so a TPM-first check would reject the strongest environment), and treats a host-side `/dev/sev` as a **provider** capability rather than a key-protection one. A host that can launch sealed guests cannot protect its own keys with any of that, and conflating the two would let a host claim the protection it provides to others rather than the protection it has itself.

## Consequences

**Good.** A machine is no longer told it lacks hardware it has. Failures carry their platform error, so `errSecMissingEntitlement` is distinguishable from absent hardware. An unclassifiable device is a signal to learn from rather than a verdict.

**Costly.** `Unknown` is a real state that callers must handle. Anything gated on hardware is unavailable while it is the answer — which is correct, because the alternative is gating on a guess.

*Updated 2026-08-31: when this was written, `Unknown` was the answer on three of the five supported platforms and the cost above was mostly theoretical. Detectors have since been written for all of them, so `Unknown` now means a specific machine could not be read rather than a platform nobody had taught this software to inspect. The distinction matters to the wording of any refusal built on this: it is no longer safe to explain an unknown answer as a missing detector.*

**Accepted risk.** Detection runs on the machine being detected, so a compromised host can lie about itself. That is unavoidable for local detection and is why remote attestation exists as a separate mechanism; this ADR is about not lying to ourselves in the ordinary case.

## Alternatives Considered

**Keep `Available() bool` and infer from it.** Rejected: it is the defect. One bit cannot carry the difference between three states that need different responses.

**Return `Absent` when detection fails, and treat `Unknown` as a later refinement.** Rejected: this is the current behaviour and the reason for the ADR. A permissive-sounding default here produces confident false statements about people's hardware.

**Infer the platform's capability from a model table.** Rejected. A table is wrong about hardware that did not exist when it was written, and the failure is silent. Detection is by trying; a table is for explaining an answer to a person, not producing it.
