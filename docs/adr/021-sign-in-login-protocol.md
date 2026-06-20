# ADR-021: Sign In with Identity Agent — Login Protocol

**Status:** Accepted
**Date:** 2026-06-19
**Deciders:** Rob Andersen

---

## Context

A self-sovereign Identity Agent is only useful if a user can actually *use* it to log in to the websites and apps they already touch every day. The dominant pattern on the web — "Sign in with Google/Apple/Facebook" — hands an identity provider a tracking position over every login and makes the user a tenant of someone else's platform. We need the opposite: a login the user fully owns, where no central party sees the login graph, and where each relying party (RP) gets a *different* identifier for the same person so RPs cannot correlate users across the web.

The login flow also has to be a special case of a more general capability. A relying party does not only want "prove you are a returning user" — it may also want a credential presented, a payment authorized, or contact details shared. Designing a bespoke protocol for each of these would fragment the agent's interaction surface. We want one envelope that carries any of these requests.

Finally, the world already has OpenID Connect, SIOPv2, and OpenID4VP deployed at scale. A login protocol that cannot speak those standards is dead on arrival for enterprise adoption. We need native sovereignty *and* a compatibility surface for existing OIDC relying parties.

---

## Decision

### The "Ask" — a universal signed interaction envelope

Every RP-initiated interaction is an **Ask**: a signed, typed request that the user reviews and grants, producing a signed assertion in return. The Ask is versioned `"ASK1"` and carries an integer intent discriminator `t`:

| `t` | Intent | Meaning |
|---|---|---|
| 1 | `login` | Prove a (pairwise) identity to an RP, optionally disclosing fields / credentials / a score band |
| 2 | `present` | Present a credential |
| 3 | `pay` | Authorize a payment |
| 4 | `contact` | Share contact information |
| 5 | `issue` | Receive an offered credential |

Only `login` (t=1) is implemented in this change; the rest are reserved registry slots so future interaction types extend the same envelope rather than inventing new ones. The intent registry lives in `packages/login-verify/src/types.ts` (`AskIntent`).

### The login challenge / assertion flow

A login is a two-message exchange between the RP and the user's Identity Agent (IA):

1. **Challenge (RP → IA).** The RP builds a `ChallengeBundle` (the login Ask) and signs it with its site key (Ed25519). The bundle carries the site AID, the site's OOBI, the RP origin as `audience`, a fresh `nonce`, timestamps, the `requested_disclosures` / `requested_credentials` / optional `requested_score`, a `callback_url`, and a `session_token`. The canonical Go struct is `login.ChallengeBundle` in `identity-agent-core/login/types.go`; the TypeScript verifier that produces it is `IdentityAgentVerifier.createChallenge` in `packages/login-verify/src/verifier.ts`.

2. **Assertion (IA → RP).** The IA fetches and verifies the challenge, asks the user to grant or decline the requested disclosures, then builds a signed `login.Assertion`. The assertion is issued from a **pairwise AID** — a per-RP identity, never the user's root AID — and carries only the granted disclosures, any presented credentials, and an optional signed score attestation. Its `D` field is a Blake3-256 SAID over the canonical body; the body is then Ed25519-signed with the pairwise key. `login.Handler.BuildAssertion` (`identity-agent-core/login/handlers.go`) is the canonical builder.

Verification (`IdentityAgentVerifier.verifyAssertion`) checks the nonce and audience bind to the original challenge, the timestamp is fresh (default ±300s), resolves the pairwise public key from the assertion's `did:webs` OOBI, and verifies the Ed25519 signature over the canonical body.

#### Pairwise identity is the privacy boundary

The IA derives a fresh Ed25519 keypair per RP and mints a pairwise AID from it (`login.Handler.GetOrCreateRelationship`). Because each RP sees a different AID for the same user, RPs cannot join their user tables on identifier. This is the core anti-correlation property — the login graph exists nowhere, not even on the user's relay.

### Canonical serialization

Both the challenge and assertion are signed over a **canonical body**: a fixed field order, compact JSON (no incidental whitespace), NFC-normalized strings, integer-second RFC3339 UTC timestamps, and base64url no-pad nonces. The signature covers the UTF-8 body excluding the `sig` field; the SAID covers the body excluding both `d` and `sig`. Go and TypeScript implement byte-identical canonicalizers (`canonicalChallengeBody` / `canonicalAssertionBody` in both `identity-agent-core/login` and `packages/login-verify/src`). This determinism is what makes cross-language golden vectors possible.

### The QR / pointer model

The login QR encodes the **smallest possible pointer**, not the whole challenge:

```
https://rp.example/i/Joy6X61xwxdQhhQ
```

The `/i/` namespace is the Ask pointer route; the trailing token is the `session_token`. The IA scans the QR, GETs the pointer, and receives the full signed `ChallengeBundle` — so the heavy fields (site AID, OOBI, requested disclosures) travel in the *signed* fetched bundle, not in the QR. This keeps QR density low (error-correction level "L") and ensures the RP origin is implicit in the URL host, so it never needs a separate `rp` parameter. The QR builder is `buildLoginQrUrl` (`packages/login-verify/src/qr-url.ts`); the React renderer is `LoginQrCode.tsx` (`packages/login-web`). A copy/paste full-OOBI fallback link is provided for environments without a camera.

### The login-verify package and golden vectors

`packages/login-verify` is the embeddable RP-side library. It exports the `IdentityAgentVerifier` class, a standalone `verifyLoginAssertion()` core (no network), the canonicalizers, the `did:webs` key resolver, and the OIDC adapter. `packages/login-web` provides the browser/React glue; `services/login-verify-ms` packages the verifier as a microservice.

The protocol is pinned by **golden vectors** (`packages/login-verify/golden_vectors.json`, seed in `golden-seed.ts`): a frozen signing seed, fixed timestamp, and known-good assertion produce a pinned canonical body, a pinned Blake3-256 SAID, and a pinned signature. The microservice runs `runGoldenSelfTest` (`services/login-verify-ms/src/golden.ts`) on startup, which recomputes the SAID, compares the canonical body byte-for-byte, verifies the signature, and confirms a corrupted signature is rejected. Any drift in serialization or crypto breaks the self-test immediately.

### OIDC / SIOPv2 / OpenID4VP compatibility adapter

The adapter (`identity-agent-core/oidc/`, mirrored in `packages/login-verify/src/oidc/`) lets a standard OIDC relying party use the login substrate without knowing anything about Asks:

- An incoming OIDC authorization request is parsed (`AuthRequest`), its `scope`/`claims` are expanded into Ask `requested_disclosures`, and it is mapped to a `ChallengeBundle` via `AuthRequest.ToChallengeBundle()`. Client ID → site AID, redirect URI → callback, nonce → nonce.
- The granted assertion is wrapped back into an OIDC **ID token** (a signed EdDSA JWT) and, for OpenID4VP, a **VP token** in either SD-JWT VC (default) or KERI-native ACDC form. The full signed Ask assertion is embedded in the ID token under a namespaced claim so a relying party that *does* understand the substrate can recover it.
- A per-pairwise-issuer discovery document advertises the supported response types, formats, and pinned profile versions. The pinned EUDI ARF / SIOPv2 / OpenID4VP / SD-JWT-VC profile constants are duplicated in `oidc/profile.go` and `oidc/profile.ts` and held in lockstep; `ValidateDiscovery` / `validateDiscoveryConformance` reject a discovery document that drifts from the pinned profiles.

### Identity-Levels AuthProvider

`authproviders/identity-levels` is a small HTTP service implementing the AuthProvider contract (`ap-1`). It answers `/health`, `/score`, and `/check`, returning a trust **band** (`green` / `amber` / `red`) and a numeric score with a freshness timestamp. When a challenge carries a `requested_score`, the login handler calls this provider, signs the resulting band into a `ScoreAttestation`, and embeds it in the assertion's `custom_data`; the OIDC layer surfaces it as a namespaced ID-token claim. The AuthProvider is a pluggable seam — any conformant scoring service can sit behind the `ap-1` contract without touching the login flow.

---

## Consequences

### Positive

- **No login graph anywhere.** Pairwise AIDs mean RPs cannot correlate the same user across sites, and there is no identity provider in the middle to observe logins.
- **One envelope, many interactions.** The Ask registry lets present/pay/contact/issue reuse the exact challenge→grant→assertion machinery already proven for login.
- **Drop-in for OIDC RPs.** Existing OpenID Connect / SIOPv2 / OpenID4VP relying parties integrate through the adapter without learning the native protocol.
- **Tamper-evident by construction.** Canonical serialization + Blake3-256 SAID + Ed25519, pinned by cross-language golden vectors, means any serialization or crypto regression is caught at startup.
- **Pluggable trust scoring.** The Identity-Levels AuthProvider is a contract, not a hardcoded dependency.

### Negative / Trade-offs

- The IA must manage one keypair and pairwise relationship per RP, which grows the agent's key inventory over time (mitigated: relationships are cached and reused).
- The OIDC adapter pins specific profile versions; bumping a profile requires a coordinated Go+TypeScript change plus a discovery-conformance update.
- Only the `login` intent is implemented; present/pay/contact/issue are reserved and not yet wired to user flows.

---

## Implementation notes

- Core login types and handler: `identity-agent-core/login/types.go`, `identity-agent-core/login/handlers.go`.
- RP-side verifier library: `packages/login-verify` (`verifier.ts`, `standalone-verify.ts`, `qr-url.ts`, `oidc/`); browser glue in `packages/login-web`; microservice in `services/login-verify-ms`.
- OIDC adapter: `identity-agent-core/oidc/` (adapter, auth, idtoken, vp, discovery, conformance, profile), mirrored in `packages/login-verify/src/oidc/`.
- Golden vectors: `packages/login-verify/golden_vectors.json` + `golden-seed.ts`, self-tested by `services/login-verify-ms/src/golden.ts`.
- Score AuthProvider: `authproviders/identity-levels/main.go` (contract `ap-1`).
- Pairwise public keys resolve via `did:webs` documents served at `{relayBase}/{aid}/did.json` — see ADR-024 for the publishing side.
