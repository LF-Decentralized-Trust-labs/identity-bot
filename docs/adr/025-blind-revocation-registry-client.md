# ADR-025: Blind Revocation Registry Client

**Status:** Accepted
**Date:** 2026-06-19
**Deciders:** Rob Andersen

---

## Context

Credentials get revoked — a badge is withdrawn, a license lapses, a key is compromised. A verifier must be able to ask "is this credential still valid?" and get a trustworthy answer. The naive designs all leak: a per-credential status URL tells the issuer (or whoever hosts the registry) exactly which credential a verifier is checking and when, which reconstructs the holder's presentation graph. A purely local revocation list, on the other hand, can't be checked by a third-party verifier at all.

We want a revocation check that (1) doesn't reveal to the registry *which* credential is being checked or *whose*, (2) doesn't require trusting the registry operator to tell the truth, and (3) doesn't create a new central point of control. KERI gives us the trust primitive — receipts and a local transaction event log (TEL) — and blinding plus herd-privacy queries give us the privacy. The registry itself is an **external, open, multi-provider** service; this ADR is about the **Identity-Agent-side client** for it.

---

## Decision

### A client, not a registry — issuer and verifier sides

`identity-agent-core/brr/` is the IA-side client for both roles against an external blind revocation registry. It speaks an open protocol over HTTP and holds the issuer's Ed25519 keypair so it can sign enrollments and events. The client never sends a plaintext credential SAID to a registry.

The core type is `brr.Client` (`identity-agent-core/brr/client.go`).

### Blinding — the registry never sees the credential

A revocation is pushed under a **blinded id**, computed locally as:

```
BlindedID = Blake3-256( credential_SAID || registry_salt )   // hex
```

(`BlindedID`, `identity-agent-core/brr/blind.go` — consistent with the project-wide Blake3-256 hashing standard.) The salt is per-registry-instance, so the same credential maps to a different blinded id at each provider, and the provider sees only opaque 32-byte hashes — never the SAID, never which credential or holder it belongs to, and never a value it can correlate across registries.

### Issuer side — enroll, then push blinded events

- **Enroll** (`Client.Enroll`): the issuer registers a `registry_prefix`, its AID, and its public key with a provider via `POST /registry/enroll`, signing the request body with Ed25519.
- **Push** (`Client.PushBlindedEvent`): for each issuance or revocation the issuer pushes `(blinded_id, event_type ∈ {iss, rev}, sequence_number)` — and only that — to `POST /registry/{prefix}/event`, again signed. The plaintext credential never leaves the issuer.

### Verifier side — herd-private bulk query, checked locally

A verifier does not ask "is *this* credential revoked?" — that would leak the credential. Instead it fetches a **bulk proof** for a coarse bucket (`Client.FetchBulkProof`, `GET /registry/{prefix}/bulk-proof?bucket_hint=…`): a sparse-merkle subtree covering many blinded ids, providing herd obfuscation so the registry can't tell which credential the verifier cares about. The verifier then finalizes **locally** (`VerifyLocally` / `CheckRevocation`, `identity-agent-core/brr/verify.go`): it recomputes the blinded id from the credential SAID and the registry salt and checks whether it appears in the proof's revoked set, yielding one of `valid` / `revoked` / `unknown` / `check_failed`.

### Trust model — the provider can't lie, only be unreachable

Correctness rests on KERI, not on trusting the operator. The bulk proof is a signed merkle structure (`BulkProof`, `identity-agent-core/brr/merkle.go`): the registry signs the merkle root with its own AID key, and the verifier — having resolved the provider's KEL via OOBI — checks that signature and recomposes the bucket subtree to the signed root. A provider therefore cannot fabricate a false "valid" or hide a revocation without producing a signature/root that fails verification. The only thing a provider can do is **fail to answer** — denial of availability, not forgery.

Two mitigations cover the availability gap and the centralization concern:

- **Multi-provider redundancy.** An issuer enrolls with several providers, and a verifier can fall back across them. Providers are discovered from the **issuer's published service endpoints** (in the issuer's KEL / OOBI), so no global directory is needed — the issuer advertises which registries carry its revocations.
- **Local TEL as truth.** The issuer's own transaction event log is the authoritative record of issuance and revocation. The registries are convenience caches with privacy properties; if every provider is unreachable, the issuer's KERI-anchored TEL remains the ground truth a verifier can ultimately demand.

---

## Consequences

### Positive

- **Privacy on both sides.** Blinding hides *which/whose* credential from the registry; herd-private bulk queries hide *what the verifier is checking*.
- **No trusted operator.** KERI receipts + a signed merkle root mean a provider can only be unreachable, never deceptive — the failure modes are availability, not integrity.
- **No new central point.** Multi-provider redundancy plus issuer-published service-endpoint discovery means revocation isn't owned by any single registry, and the issuer's local TEL is the final source of truth.
- **Open protocol.** The client targets a protocol, not a vendor; any conformant provider works.

### Negative / Trade-offs

- Herd-private bulk proofs trade bandwidth for privacy — the verifier downloads a subtree covering many credentials to check one.
- Discovery depends on issuers actually publishing registry service endpoints in their KEL; an issuer that publishes none forces the verifier back to the TEL/OOBI path.
- The full sparse-merkle multiproof composition and registry-signature verification are the load-bearing integrity checks and must be completed and pinned before production use; until then the client's proof path is not yet authoritative.
- Multi-provider failover and TEL fallback are part of the design surface but not yet fully wired in the client.

---

## Implementation notes

- Client (issuer + verifier): `identity-agent-core/brr/client.go` (`Client`, `Enroll`, `PushBlindedEvent`, `FetchBulkProof`).
- Blinding: `identity-agent-core/brr/blind.go` (`BlindedID` = Blake3-256 of SAID‖salt).
- Verification: `identity-agent-core/brr/verify.go` (`CheckRevocation`, `VerifyLocally`, status constants) and `merkle.go` (`BulkProof`, subtree-to-root composition).
- End-to-end issue→blind-revoke→verify path: `identity-agent-core/brr/steel_thread_test.go`.
- Provider discovery uses the issuer's published service endpoints (issuer KEL / OOBI); the local TEL is treated as the authoritative revocation record.
