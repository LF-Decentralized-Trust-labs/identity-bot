# ADR-022: Hybrid Post-Quantum KERI Cipher Suite

**Status:** Accepted, with the implementation notes below corrected 2026-08-18.
The suite and its reasoning stand. Two things this ADR describes are no longer
how the code works, and one never became true — see "What changed since this was
written" at the end before relying on any implementation detail here.
**Date:** 2026-06-19
**Deciders:** Rob Andersen

---

## Context

KERI identities are anchored by signing keys, and KERI's whole value proposition is that a key event log (KEL) remains verifiable indefinitely. "Indefinitely" is exactly the threat model that breaks under quantum computing: a cryptographically relevant quantum computer would forge Ed25519 signatures and recover X25519 key-agreement secrets, retroactively invalidating identities and decrypting "harvest now, decrypt later" captures.

The Identity Agent issues durable, long-lived identities. We cannot wait for a flag day to migrate. At the same time, the post-quantum algorithms standardized as FIPS 203/204 (ML-KEM and ML-DSA) are young; a careless "rip out classical, drop in PQC" migration would replace a battle-tested algorithm with one that has had far less cryptanalysis. The prudent path is **hybrid**: require *both* a classical and a post-quantum guarantee, so the identity is safe as long as *either* family holds.

We also run on three engines — Go (desktop backend), Python keripy (desktop KERI driver), and Rust (mobile bridge) — and they must agree byte-for-byte, or a hybrid identity created on one platform won't verify on another.

---

## Decision

### Four-key hybrid inception

A hybrid AID is born with **two classical and two post-quantum keys**, identified by the cipher-suite tag `"IA-HYBRID-1"`:

| Slot | Purpose | Algorithm | CESR code |
|---|---|---|---|
| `k[0]` | Signing (classical) | Ed25519 | `D` |
| `k[1]` | Signing (post-quantum) | ML-DSA-65 | `1PDA` |
| `a[0].ka[0]` | Key agreement (classical) | X25519 | `1PXB` |
| `a[0].ka[1]` | Key agreement (post-quantum) | ML-KEM-768 | `1PKM` |

The two signing keys live in the standard KERI `k` field (length 2). The pre-rotation `n` field carries two Blake3-256 digests — one per next signing key — so rotation stays hybrid across the whole KEL. The two key-agreement (encryption) keys ride in an anchor seal `a[0]` alongside the cipher-suite id `ia: "IA-HYBRID-1"`, keeping the event a valid KERI 1.1.x event that a non-hybrid verifier can still parse. ML-DSA-65 and ML-KEM-768 are the FIPS Level-3 parameter sets (verify key 1952 / 1184 bytes; signature 3309 bytes).

The builder is `BuildHybridInception` (`identity-agent-core/iacrypto/hybrid_inception.go`), mirrored by `build_hybrid_inception` in the Python driver (`drivers/keri-core/pqc/hybrid_inception.py`, which round-trips through keripy's `SerderKERI(makify=True)` for protocol conformance) and `build_hybrid_inception` in Rust (`identity_agent_ui/rust/src/pqc/hybrid_inception.rs`).

### Both signatures must verify

A hybrid signature is a single composite wire object carrying an indexed Ed25519 signature (CESR `B`, index 0) and an indexed ML-DSA-65 signature (CESR `1PDS`, index 1) under a count-2 controller-signature counter. **Verification returns true only if both halves verify.** A valid classical signature with a broken PQC signature is rejected, and vice versa — neither family alone is sufficient. This "both-must-verify" gate is enforced identically in all three engines:

- Go: `VerifyHybridSignature` (`identity-agent-core/iacrypto/hybrid_signature.go`) gates on a hybrid identity with exactly two signing keys, then requires `ed25519.Verify` **and** `mldsa65.Verify` to both succeed.
- Python: `verify_hybrid_signature` (`drivers/keri-core/pqc/hybrid_signature.py`) does the same via keripy's `Verfer` plus the ML-DSA verifier.
- Rust: `verify_hybrid_signature` (`identity_agent_ui/rust/src/pqc/hybrid_signature.rs`) requires `verify_strict` (Ed25519) and `mldsa65::verify` to both pass.

The security consequence: the identity is forgeable only by an attacker who can break **both** Ed25519 and ML-DSA-65.

### Golden-vector pinning across three engines

The composite wire format, key sizes, CESR codes, and the inception event bytes are pinned in `identity-agent-core/iacrypto/golden_vectors.json`. From a fixed seed it fixes the AID, the SAID, the exact base64 length of the inception event, the `k`/`n`/`ka` lengths (each must be 2), and the composite signature wire string. It also pins **negative vectors** — one with a corrupted classical signature and one with a corrupted PQC signature — that must both be rejected, which is the executable proof of the both-must-verify rule.

All three engines assert against the same JSON: Go (`iacrypto/hybrid_signature_test.go`), Python (`drivers/keri-core/tests/pqc_hybrid_signature_keripy_test.py`), and Rust (`identity_agent_ui/rust/tests/pqc_golden_constants.rs` + the in-module tests). Cross-engine agreement is therefore enforced by construction, not by hope.

### Two PQC backends: liboqs-go on desktop, RustCrypto on mobile
*(Superseded — there is one backend now. See the end of this document.)*

PQC primitives are not yet first-class in our base crypto stack, so the suite uses two interchangeable backends pinned to the same vectors:

- **Desktop (Go/liboqs).** The proof-of-concept and desktop path call **liboqs** (Open Quantum Safe) through the `liboqs-go` CGO wrapper for `ML-DSA-65` and `ML-KEM-768` (`pqc-poc/roundtrip/roundtrip.go`). This depends on the liboqs C library being installed (`brew install liboqs` on macOS); the wrapper handles CGO linking internally. A gomobile wrapper (`pqc-poc/mobilepqc`) exists but mobile liboqs availability is the constraint that motivates the fallback.
- **Mobile (Rust/RustCrypto).** The mobile bridge uses pure-Rust RustCrypto crates — `ml-dsa` and `ml-kem` — via `pqc-poc-rust` (`pqc-poc-rust/src/mldsa65.rs`, `lib.rs`), exposed to Flutter through `flutter_rust_bridge` (`identity_agent_ui/rust/src/pqc`). No C dependency, so it links cleanly on iOS and Android. The Python driver reaches the same Rust implementation by shelling out to a small CLI (`drivers/keri-core/pqc/mldsa_crypto.py`), keeping the Python reference path deterministic against the Rust crate.

Because both backends are pinned to the same golden vectors, an identity created with liboqs on desktop verifies under RustCrypto on mobile and vice versa.

---

## Consequences

### Positive

- **Quantum-safe with a classical safety net.** An identity is forgeable only if *both* Ed25519 and ML-DSA-65 fall — strictly stronger than either alone, and immune to a single-algorithm break (including a future flaw found in the young PQC standards).
- **No flag day.** Hybrid AIDs are valid KERI 1.1.x events; the PQC material rides in standard fields and anchor seals, so the migration is additive.
- **Cross-engine determinism.** One golden-vector file governs Go, Python, and Rust; key sizes, CESR codes, and the both-must-verify rule are all executable assertions.
- **Backend flexibility.** liboqs and RustCrypto are interchangeable behind the same vectors, so each platform uses the backend that links cleanly there.

### Negative / Trade-offs

- **Size.** ML-DSA-65 keys (1952 B) and signatures (3309 B) dwarf Ed25519's 32/64 bytes, inflating KELs and signed payloads; ML-KEM-768 encapsulation keys are 1184 B. This is the unavoidable cost of PQC.
- **liboqs build dependency.** The desktop liboqs path needs the C library present, and the `pqc-poc` packages do not build in environments without it — this is a packaging constraint to resolve before desktop ships hybrid by default.
- **Two PQC implementations to keep in lockstep.** liboqs-go and the RustCrypto crates must stay pinned to the same vectors as their respective versions advance.
- The suite is `IA-HYBRID-1`; future parameter or algorithm changes will require a new suite tag and a new golden-vector set.

---

## Implementation notes

- Go engine: `identity-agent-core/iacrypto/` (`hybrid_inception.go`, `hybrid_signature.go`, `cesr.go`, `golden_vectors.json`).
- Python engine: `drivers/keri-core/pqc/` (`hybrid_inception.py`, `hybrid_signature.py`, `mldsa_crypto.py`, `cesr.py`).
- Rust engine + mobile bridge: `identity_agent_ui/rust/src/pqc/` and the underlying crate `pqc-poc-rust/` (`mldsa65.rs`, `lib.rs`).
- liboqs desktop proof-of-concept: `pqc-poc/` (`roundtrip/`, `mobilepqc/`, `cmd/c4roundtrip/`).
- Key sizes are FIPS Level-3: ML-DSA-65 verify key 1952 B / signature 3309 B; ML-KEM-768 encapsulation key 1184 B; X25519 / Ed25519 32 B.


---

## What changed since this was written

Corrected 2026-08-18 after an audit of what the code does. The cipher suite, the
key layout and the reasoning for hybrid-from-inception are unchanged. These
three implementation claims are not accurate and should not be relied on:

**1. There is one post-quantum backend, and it is neither of the two named
here.** Both `ML-DSA-65` and `ML-KEM-768` come from `github.com/cloudflare/circl`
— pure Go, no CGO, no C library to install. It compiles on every platform,
including mobile, where the core is embedded via `gomobile`. liboqs is not a
dependency of the core; the RustCrypto path is gone with the Rust bridge
(ADR-037). The "two interchangeable backends pinned to the same vectors"
reasoning no longer applies, because there is one implementation and the golden
vectors now pin it against itself.

**2. The messaging channel is hybrid. The identity is not.** This ADR describes
every identity as founded with `k[0]` Ed25519 and `k[1]` ML-DSA-65. That is not
what the production path does: the inception route founds with a single Ed25519
key, and `BuildHybridInception` has no production caller. `SignHybrid` and
`VerifyHybridSignature` have no callers outside tests.

What *is* live and mandatory is DIDComm: `didcomm/crypto.go` requires both
signatures to verify with no classical-only branch, and derives the content key
from an X25519 exchange and an ML-KEM-768 encapsulation combined in one HKDF, so
removing the post-quantum half means nothing decrypts.

So quantum resistance today protects messages between Identity Agents, not the
identity's own signing key — which is the longer-lived secret of the two. Closing
that is tracked separately.

**3. A hybrid identity would still declare a signing threshold of one.**
`hybrid_inception.go` sets `Isith: "1"` with two keys, so a conformant validator
accepts the Ed25519 signature alone. Any work to make identities hybrid has to
address the threshold as well, or the protection is enforced by our verifier
rather than by the identity.
