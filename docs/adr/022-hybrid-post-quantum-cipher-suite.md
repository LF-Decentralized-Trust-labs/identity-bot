# ADR-022: Hybrid Post-Quantum KERI Cipher Suite

**Status:** Accepted
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

The builder is `BuildHybridInception` (`identity-agent-core/m63/hybrid_inception.go`), mirrored by `build_hybrid_inception` in the Python driver (`drivers/keri-core/m63/hybrid_inception.py`, which round-trips through keripy's `SerderKERI(makify=True)` for protocol conformance) and `build_hybrid_inception` in Rust (`identity_agent_ui/rust/src/m63/hybrid_inception.rs`).

### Both signatures must verify

A hybrid signature is a single composite wire object carrying an indexed Ed25519 signature (CESR `B`, index 0) and an indexed ML-DSA-65 signature (CESR `1PDS`, index 1) under a count-2 controller-signature counter. **Verification returns true only if both halves verify.** A valid classical signature with a broken PQC signature is rejected, and vice versa — neither family alone is sufficient. This "both-must-verify" gate is enforced identically in all three engines:

- Go: `VerifyHybridSignature` (`identity-agent-core/m63/hybrid_signature.go`) gates on a hybrid identity with exactly two signing keys, then requires `ed25519.Verify` **and** `mldsa65.Verify` to both succeed.
- Python: `verify_hybrid_signature` (`drivers/keri-core/m63/hybrid_signature.py`) does the same via keripy's `Verfer` plus the ML-DSA verifier.
- Rust: `verify_hybrid_signature` (`identity_agent_ui/rust/src/m63/hybrid_signature.rs`) requires `verify_strict` (Ed25519) and `mldsa65::verify` to both pass.

The security consequence: the identity is forgeable only by an attacker who can break **both** Ed25519 and ML-DSA-65.

### Golden-vector pinning across three engines

The composite wire format, key sizes, CESR codes, and the inception event bytes are pinned in `identity-agent-core/m63/golden_vectors.json`. From a fixed seed it fixes the AID, the SAID, the exact base64 length of the inception event, the `k`/`n`/`ka` lengths (each must be 2), and the composite signature wire string. It also pins **negative vectors** — one with a corrupted classical signature and one with a corrupted PQC signature — that must both be rejected, which is the executable proof of the both-must-verify rule.

All three engines assert against the same JSON: Go (`m63/hybrid_signature_test.go`), Python (`drivers/keri-core/tests/m63_hybrid_signature_keripy_test.py`), and Rust (`identity_agent_ui/rust/tests/m63_golden_constants.rs` + the in-module tests). Cross-engine agreement is therefore enforced by construction, not by hope.

### Two PQC backends: liboqs-go on desktop, RustCrypto on mobile

PQC primitives are not yet first-class in our base crypto stack, so the suite uses two interchangeable backends pinned to the same vectors:

- **Desktop (Go/liboqs).** The proof-of-concept and desktop path call **liboqs** (Open Quantum Safe) through the `liboqs-go` CGO wrapper for `ML-DSA-65` and `ML-KEM-768` (`pqc-poc/roundtrip/roundtrip.go`). This depends on the liboqs C library being installed (`brew install liboqs` on macOS); the wrapper handles CGO linking internally. A gomobile wrapper (`pqc-poc/mobilepqc`) exists but mobile liboqs availability is the constraint that motivates the fallback.
- **Mobile (Rust/RustCrypto).** The mobile bridge uses pure-Rust RustCrypto crates — `ml-dsa` and `ml-kem` — via `pqc-poc-rust` (`pqc-poc-rust/src/mldsa65.rs`, `lib.rs`), exposed to Flutter through `flutter_rust_bridge` (`identity_agent_ui/rust/src/m63`). No C dependency, so it links cleanly on iOS and Android. The Python driver reaches the same Rust implementation by shelling out to a small CLI (`drivers/keri-core/m63/mldsa_crypto.py`), keeping the Python reference path deterministic against the Rust crate.

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

- Go engine: `identity-agent-core/m63/` (`hybrid_inception.go`, `hybrid_signature.go`, `cesr.go`, `golden_vectors.json`).
- Python engine: `drivers/keri-core/m63/` (`hybrid_inception.py`, `hybrid_signature.py`, `mldsa_crypto.py`, `cesr.py`).
- Rust engine + mobile bridge: `identity_agent_ui/rust/src/m63/` and the underlying crate `pqc-poc-rust/` (`mldsa65.rs`, `lib.rs`).
- liboqs desktop proof-of-concept: `pqc-poc/` (`roundtrip/`, `mobilepqc/`, `cmd/c4roundtrip/`).
- Key sizes are FIPS Level-3: ML-DSA-65 verify key 1952 B / signature 3309 B; ML-KEM-768 encapsulation key 1184 B; X25519 / Ed25519 32 B.
