# Algorithm Registry — Standardizing Identity Confidence Score Algorithms

## Purpose

When Bob sends Alice a confidence score with a ZK proof, Alice needs to
instantly recognize *which* algorithm produced that score. The zkVM gives us
a deterministic **Image ID** (a SHA-256 hash of the compiled guest binary),
but Alice needs a way to map that opaque hash to a known, audited algorithm.

This document proposes a standardization framework for the algorithm registry.

## The Problem

The Image ID is a 256-bit hash like:
```
[0x0ba46383, 0x5430b25a, 0x3fee05eb, 0x1ed9b17c, ...]
```

This is deterministic (same source code always produces the same ID), but:
- It's not human-readable
- It changes with every code edit, dependency update, or compiler version
- Alice's system needs a lookup table to decide which IDs she trusts

## Proposed Architecture

### Level 1: Algorithm Specification (Human-Readable)

Each scoring algorithm has a versioned specification:

```json
{
  "algorithm_name": "identity-confidence-basic",
  "version": "2.0.0",
  "description": "Weighted scoring across KERI identity, Verified Credentials, and local attestation",
  "author": "LF Decentralized Trust Labs",
  "license": "Apache-2.0",
  "source_repository": "https://github.com/LF-Decentralized-Trust-labs/identity-bot",
  "source_path": "zkvm-poc/methods/guest/src/main.rs",
  "max_score": 100,
  "pillars": [
    { "name": "Cryptographic Identity (KERI)", "max_points": 25 },
    { "name": "Verified Credentials", "max_points": 45 },
    { "name": "Local Authentication", "max_points": 20 },
    { "name": "Cross-Pillar Synergy", "max_points": 10 }
  ],
  "input_schema": "ScoringInput",
  "output_schema": "ScoringOutput"
}
```

### Level 2: Build Manifest (Reproducible)

To produce the same Image ID, the exact build environment must be pinned:

```json
{
  "algorithm_name": "identity-confidence-basic",
  "version": "2.0.0",
  "build": {
    "zkvm": "risc0",
    "risc0_version": "3.0.6",
    "rust_toolchain": "1.97.0",
    "target": "riscv32im-risc0-zkvm-elf",
    "source_commit": "abc123def456...",
    "reproducible_build_command": "cargo build --release -p scoring"
  },
  "image_id": "0ba463835430b25a3fee05eb1ed9b17cd1c04d4de8585e101509c11038099f24"
}
```

### Level 3: Trust Registry (Decentralized)

The registry itself should be:
- **Published as a KERI-anchored document** — signed by the algorithm author's AID
- **Versioned in Git** — full audit trail of algorithm changes
- **Distributable** — peers can maintain their own accepted algorithm lists

```json
{
  "registry_version": "1.0.0",
  "maintainer_aid": "ELf3Decentralized...",
  "accepted_algorithms": [
    {
      "name": "identity-confidence-basic",
      "version": "2.0.0",
      "image_id": "0ba463835430b25a3fee05eb1ed9b17cd1c04d4de8585e101509c11038099f24",
      "trust_level": "audited",
      "audit_date": "2026-07-01",
      "auditor_aid": "EAudit0r..."
    },
    {
      "name": "identity-confidence-basic",
      "version": "1.0.0",
      "image_id": "deadbeef12345678...",
      "trust_level": "deprecated",
      "deprecation_reason": "Superseded by v2.0.0"
    }
  ]
}
```

## Verification Flow

When Alice receives a proof from Bob:

```
1. Extract Image ID from the ZK receipt
2. Look up Image ID in her trusted algorithm registry
3. If found:
   → Check trust_level (audited / community / deprecated)
   → Verify the ZK proof against the Image ID
   → Accept the score with the corresponding trust level
4. If NOT found:
   → Reject the score (unknown algorithm)
   → Optionally: ask Bob which registry lists this algorithm
```

## Algorithm Lifecycle

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   DRAFT      │────▶│   AUDITED    │────▶│  DEPRECATED  │
│              │     │              │     │              │
│ New version  │     │ Community    │     │ Superseded   │
│ under review │     │ has reviewed │     │ by newer ver │
└──────────────┘     └──────────────┘     └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │   REVOKED    │
                     │              │
                     │ Vulnerability│
                     │ discovered   │
                     └──────────────┘
```

## Open Design Questions

1. **Who maintains the canonical registry?**
   - Option A: LF Decentralized Trust maintains a "blessed" registry
   - Option B: Each community/industry maintains their own (federated model)
   - Option C: Both — a root registry with domain-specific extensions

2. **How do we handle compiler/toolchain updates?**
   - Even with identical source code, a Rust compiler update changes the binary
   - Proposal: Pin exact toolchain in `rust-toolchain.toml` and use reproducible builds
   - The registry lists ALL known-good Image IDs for a given algorithm version

3. **Minimum accepted score for a transaction?**
   - This is NOT standardized by the registry — it's Alice's policy
   - Example: Alice's bank requires score >= 80% from an "audited" algorithm
   - Example: A forum might accept score >= 30% from any recognized algorithm

4. **Cross-zkVM compatibility?**
   - RISC Zero and SP1 produce different Image IDs for the same source
   - Proposal: The registry maps algorithm versions to multiple zkVM implementations
   - Each entry specifies `zkvm: "risc0"` or `zkvm: "sp1"`

## Example: Alice's Verification Code (Pseudocode)

```python
def verify_identity_score(receipt, claimed_score, registry):
    # Extract the Image ID from the proof
    image_id = receipt.get_image_id()
    
    # Look up in registry
    algorithm = registry.find_by_image_id(image_id)
    
    if algorithm is None:
        return Reject("Unknown algorithm — not in my trusted registry")
    
    if algorithm.trust_level == "revoked":
        return Reject("Algorithm has been revoked — security issue")
    
    if algorithm.trust_level == "deprecated":
        return Warn("Algorithm is deprecated — ask Bob to upgrade")
    
    # Verify the ZK proof cryptographically
    if not receipt.verify(image_id):
        return Reject("Invalid proof — possible tampering")
    
    # Extract the score from the verified journal
    verified_score = receipt.journal.decode()
    
    # Apply Alice's policy
    if verified_score.confidence_score >= ALICE_MINIMUM_THRESHOLD:
        return Accept(verified_score)
    else:
        return Reject(f"Score {verified_score}% below my threshold")
```

## Integration with Identity Agent Spec

This registry maps to the Identity Agent Specification v1.5:

- **Section 7 (Identity Assurance & Scoring Logic)**: The "Algorithm Levels"
  (Basic, Manual/NIST, Grape Score) each become separate entries in the registry
  with their own Image IDs.

- **Section 3.1 (Hierarchy of Authority)**: The registry itself can be signed
  by the Identity Agent's Root Authority or a delegated governance key.

- **Section 2 (System Integrity)**: The Shadow Auditor can automatically check
  that the local agent is using a non-deprecated algorithm from the registry.
