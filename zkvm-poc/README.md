# zkVM Proof of Concept — Verifiable Identity Confidence Score

This PoC demonstrates **verifiable local execution** of the Identity Agent's
confidence scoring algorithm using [RISC Zero's zkVM](https://risczero.com/).

It directly addresses all action items and open questions from
[Issue #6](https://github.com/LF-Decentralized-Trust-labs/identity-bot/issues/6).

## The Problem

The Identity Agent runs locally on Bob's device. Without verification,
Bob could modify the scoring code to output a fake "100% confidence" score.
Alice cannot trust the score unless she can mathematically verify the execution.

## The Solution — Hybrid zkVM + Selective Disclosure

A single ZK proof that simultaneously guarantees three things:

| Layer | What it proves | How |
|-------|---------------|-----|
| **1 — Credential Authenticity** | VCs were signed by real issuers | Ed25519 verified by host; SHA-256 commitments re-verified inside zkVM |
| **2 — Selective Disclosure** | Score based on real data; details stay private | Only `credential_type` + issuer fingerprint committed to public journal |
| **3 — Algorithm Integrity** | Scoring code was NOT modified | RISC Zero Image ID (hash of guest binary) |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1 — HOST (native speed, ~272µs)                               │
│                                                                     │
│  Issuer Gov  ──signs──▶ GovernmentID VC ──verify Ed25519──▶ ✓       │
│  Issuer Bank ──signs──▶ BankAccount  VC ──verify Ed25519──▶ ✓       │
│  Attacker    ──signs──▶ FakeCredential  ──verify Ed25519──▶ ✓ sig   │
│                                           but issuer untrusted       │
│                                                                     │
│  For each VC:                                                       │
│    commitment = SHA-256(issuer_pubkey || payload_hash || trusted)    │
│                                                                     │
└───────────────────────────────────┬─────────────────────────────────┘
                                    │ commitments (not raw VCs)
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 2 — zkVM (full proof mode, ~20 seconds)                       │
│                                                                     │
│  Guest re-derives each commitment using SHA-256 accelerator         │
│  Rejects any mismatch → host cannot lie about VC contents           │
│  Scores only commitment-verified credentials                        │
│  Selectively discloses: type + issuer fingerprint only              │
│                                                                     │
│  Receipt proves: algorithm v4 + these exact commitments → 100%      │
└───────────────────────────────────┬─────────────────────────────────┘
                                    │ score + ZK proof
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 3 — ALICE (verifier, ~20ms)                                   │
│                                                                     │
│  receipt.verify(IMAGE_ID) ──▶ ✓                                     │
│                                                                     │
│  Alice knows:                                                       │
│    • Score 100% from algorithm v4 (Image ID: ae7072b4...)           │
│    • GovernmentID verified (issuer 79b5562e...)                     │
│    • BankAccount verified (issuer 6bf2d4c5...)                      │
│    • FakeCredential excluded (untrusted issuer)                     │
│    • Raw VC data (names, doc numbers, balances) NOT revealed        │
└─────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
zkvm-poc/
├── Cargo.toml                # Workspace root
├── README.md                 # This file
├── ALGORITHM_REGISTRY.md     # Proposal for Image ID standardization
├── host/
│   └── src/main.rs           # Issuer sim, Ed25519 verify, commitment builder, prover
└── methods/
    ├── build.rs              # Compiles guest to RISC-V ELF
    ├── src/lib.rs            # Exports ELF + Image ID constants
    └── guest/
        └── src/main.rs       # Algorithm v4: commitment verify + selective disclosure
```

## Prerequisites

**Rust** (1.77+):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**RISC Zero toolchain**:
```bash
curl -L https://risczero.com/install | bash
rzup install
cargo risczero --version  # should show 3.0.6+
```

## Build & Run

```bash
cd zkvm-poc

# Build
cargo build

# Run with full ZK proof (no dev mode needed — ~20s on Apple Silicon M-series)
cargo run
```

## Verified Output (Apple Silicon M-series, full proof mode)

```
╔══════════════════════════════════════════════════════════════╗
║  Identity Agent - Hybrid zkVM v4 (SHA-256 Commitment PoC)   ║
║  Full proof mode — no RISC0_DEV_MODE needed                 ║
╚══════════════════════════════════════════════════════════════╝

━━━ STEP 1: HOST — Ed25519 Verification (native speed) ━━━

  VC #1 (GovernmentID)   — Ed25519 sig valid: true
  VC #2 (BankAccount)    — Ed25519 sig valid: true
  VC #3 (FakeCredential) — Ed25519 sig valid: true (but issuer UNTRUSTED)
  Native Ed25519 verification time: 272.17µs
  Commitments built: 3

━━━ STEP 2: zkVM — SHA-256 Commitment Verification + Scoring ━━━

  Generating full ZK proof (no dev mode)...
  Proof generated in 20.55s

  PUBLIC OUTPUT (what Alice receives):
    Confidence Score:     100%
    Algorithm Version:    v4
    Commitments Verified: 3
    Commitments Rejected: 0
    Disclosed:
      • GovernmentID  issuer 79b5562e... trusted=true
      • BankAccount   issuer 6bf2d4c5... trusted=true
      • FakeCredential issuer 197f6b23... trusted=false

━━━ STEP 3: ALICE — Verify Proof ━━━

  ✓ VERIFICATION PASSED in 20.56ms

━━━ SECURITY TEST: Can host lie about commitment? ━━━

  Injected commitment with mismatched hash:
    Commitments verified: 0 (rejected by guest)
    Commitments rejected: 1
    Score: 25% (no valid VCs counted)
    ✓ PASS — host cannot fabricate fake commitments
```

## Performance (Apple Silicon M-series, full proof mode)

| Step | Time | Notes |
|------|------|-------|
| Ed25519 verification (host, native) | ~272µs | All 3 VCs |
| ZK proof generation | **~20s** | Full cryptographic proof, no GPU needed |
| ZK proof verification | **~20ms** | Alice's side, near-instant |

### Why ~20s instead of 10-30 minutes?

The previous v3 approach ran Ed25519 signature verification *inside* the zkVM,
which requires ~500 million RISC-V cycles per signature (elliptic curve math
is expensive in a virtual circuit). v4 uses the **SHA-256 commitment pattern**:

- Ed25519 verification runs on the **host natively** (~272µs total)
- The zkVM only processes SHA-256 hashes using the **hardware accelerator precompile**
- SHA-256 runs ~10,000x fewer cycles than Ed25519 inside the zkVM
- Result: proof generation drops from hours to **~20 seconds**

This is the standard production pattern used by zkEVMs for signature precompiles.

## Security Model

Alice's proof guarantees:

1. **Algorithm integrity** — Image ID is a deterministic hash of the guest binary.
   Any code change produces a different ID, which Alice would reject.

2. **Commitment integrity** — The guest re-derives each commitment using SHA-256.
   If the host fabricated a commitment (e.g., lied about `issuer_trusted=true`),
   the re-derived hash won't match → the commitment is rejected.

3. **Selective disclosure** — The journal exposes only `credential_type` and
   8-byte issuer fingerprints. Raw claims (names, document numbers, balances)
   never appear in the proof or journal.

4. **Independent verification** — Alice can re-verify the Ed25519 signatures
   herself using the issuer fingerprints committed in the journal, if she
   chooses not to rely solely on the host's pre-verification.

## Scoring Algorithm v4

Three pillars + synergy bonus (max 100 points):

| Pillar | Max | Factors |
|--------|-----|---------|
| KERI Cryptographic Identity | 25 | AID age, witness count, key rotation |
| Verified Credentials | 45 | Commitment-verified count, trusted issuers, type diversity |
| Local Authentication | 20 | Biometric, peer endorsements |
| Cross-Pillar Synergy | 10 | Bonus when all 3 pillars have strong signals |

## Answers to Issue #6 Open Questions

| Question | Answer |
|----------|--------|
| Do we need this? | **YES** — without it Alice must parse, verify issuer sigs, and run scoring logic herself for every interaction |
| Performance? | **~20s proof, ~20ms verify** on Apple Silicon. No GPU required. |
| Algorithm ID standardization? | **Image ID** (`ae7072b4...`) is the hash of the compiled guest binary — deterministic and unforgeable. See `ALGORITHM_REGISTRY.md` for the full 3-level registry proposal. |

## Algorithm Registry

See [ALGORITHM_REGISTRY.md](./ALGORITHM_REGISTRY.md) for the proposal on how
Image IDs map to named algorithm versions — including a KERI-anchored trust
registry design.

## Next Steps (Integration with Identity Agent)

- [ ] Parse real ACDC Verifiable Credentials (KERI-native format)
- [ ] Expose proof generation via Go Core REST API (`POST /identity/prove-score`)
- [ ] Implement algorithm registry as a KERI-anchored TEL
- [ ] Serialize receipt for network transport (CBOR / protobuf)
- [ ] Benchmark on mobile ARM64 for feasibility

## References

- [RISC Zero Documentation](https://dev.risczero.com/)
- [Issue #6](https://github.com/LF-Decentralized-Trust-labs/identity-bot/issues/6)
- [Identity Agent Specification v1.5](../Identity%20Agent%20Specification%2C%20v1.5.txt) — Section 7
