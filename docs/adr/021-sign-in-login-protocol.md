# ADR-021: Sign In with Identity Agent — Login Protocol

**Status:** Accepted
**Date:** 2026-06-19
**Deciders:** Rob Andersen

---

## Context

A user-controlled Identity Agent is only useful if a user can actually *use* it to log in to the websites and apps they already touch every day. The dominant pattern on the web — "Sign in with Google/Apple/Facebook" — hands an identity provider a tracking position over every login and makes the user a tenant of someone else's platform. We need the opposite: a login the user fully owns, where no central party sees the login graph, and where each relying party (RP) gets a *different* identifier for the same person so RPs cannot correlate users across the web.

The login flow also has to be a special case of a more general capability. A relying party does not only want "prove you are a returning user" — it may also want a credential presented, a payment authorized, or contact details shared. Designing a bespoke protocol for each of these would fragment the agent's interaction surface. We want one envelope that carries any of these requests.

Finally, the world already has OpenID Connect, SIOPv2, and OpenID4VP deployed at scale. A login protocol that cannot speak those standards is dead on arrival for enterprise adoption. We need native sovereignty *and* a compatibility surface for existing OIDC relying parties.

---

## Decision

### The "Ask" — a universal signed interaction envelope

Every RP-initiated interaction is an **Ask**: a signed, typed request that the user reviews and grants, producing a signed assertion in return. The Ask (challenge side) is versioned `"ASK1"` and carries an integer action discriminator `t` (Ask registry). The signed assertion uses a string `t` ("login-assertion") as its type discriminator. Clarification: integer `t` belongs to the challenge / Ask envelope registry (generalizes to present=2 etc.); string `t` is the assertion type. See also `login/types.go` (ChallengeBundle.T int, Assertion.T string).

| `t` | Action | Meaning |
|---|---|---|
| 1 | `login` | Prove a (pairwise) identity to an RP, optionally disclosing fields / credentials / a score band |
| 2 | `present` | Present a credential |
| 3 | `pay` | Authorize a payment |
| 4 | `contact` | Share contact information |
| 5 | `issue` | Receive an offered credential |

Only `login` (t=1) is implemented in this change; the rest are reserved registry slots so future interaction types extend the same envelope rather than inventing new ones. The action registry lives in `packages/login-verify/src/types.ts` (`AskAction`).

### The login challenge / assertion flow

A login is a two-message exchange between the RP and the user's Identity Agent (IA):

1. **Challenge (RP → IA).** The RP's organisation Identity Agent builds a `ChallengeBundle` (the login Ask) and signs it with the site asset's key (Ed25519), which it holds and never exports (`createSignedAssetChallenge`, behind `/api/login/challenge` and the widget route `/api/login/session/{asset_id}`). *(Amended 2026-10-24: a relying party does not hold a site key of its own.)* The bundle carries the site AID, the site's OOBI, the RP origin as `audience`, a fresh `nonce`, timestamps, the `requested_disclosures` / `requested_credentials` / optional `requested_score`, a `callback_url`, and a `session_token`. The canonical Go struct is `login.ChallengeBundle` in `identity-agent-core/login/types.go`. The TypeScript `IdentityAgentVerifier.createChallenge` in `packages/login-verify/src/verifier.ts` signs with a key the caller holds, which no real site has, so it cannot serve a real site until it can have its organisation Identity Agent sign instead (tracked); until then a website signs people in through its organisation Identity Agent's own challenge and callback routes (`/api/login/challenge`, `/api/login/callback`), with `confirmLoginSession` from `packages/login-web` on its server.

2. **Assertion (IA → RP).** The IA fetches and verifies the challenge, asks the user to grant or decline the requested disclosures, then builds a signed `login.Assertion`. The assertion is issued from a **pairwise AID** — a per-RP identity, never the user's root AID — and carries only the granted disclosures, any presented credentials, and an optional signed score attestation. Its `D` field is a Blake3-256 SAID over the canonical body; the body is then Ed25519-signed with the pairwise key. `login.Handler.BuildAssertion` (`identity-agent-core/login/handlers.go`) is the canonical builder.

Verification (`IdentityAgentVerifier.verifyAssertion`, `login.VerifyAssertion`) checks the nonce and audience bind to the original challenge, the assertion names this site (`site_aid`), the timestamp is fresh (default ±300s), takes the pairwise public key from the key log the assertion carries (`p_kel`), and verifies the Ed25519 signature over the canonical body.

#### A relying party has an organisation Identity Agent

A website or app that signs people in does so through its organisation's own Identity Agent. Its sign-in identity is an asset of that Identity Agent, which serves the site's key log so each person's Identity Agent can check the site is the one it claims to be, and which checks each person's key log when the assertion reaches its callback (`handleLoginCallback`, through `login.VerifyAssertion`). `POST /public/login/key` is the same check offered to verifiers written in other languages, so they need no KERI code of their own. The earlier path, in which a relying party with no KERI library made one Ed25519 check against a key read from a `did.json`, is withdrawn: a did.json cannot bind a key to its identifier, so it let anybody sign in as anybody. *(Amended 2026-10-24.)*

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

`packages/login-verify` is the embeddable RP-side library. It exports the `IdentityAgentVerifier` class, a standalone `verifyLoginAssertion()` core, the canonicalizers, `keyFromIdentityAgent` (which asks the relying party's organisation Identity Agent what key a person's key log establishes, over TLS), and the OIDC adapter. `generateDevSiteIdentity` makes a development identity with no key log behind it, which updated Identity Agents refuse. `packages/login-web` provides the browser/React glue; `services/login-verify-ms` packages the verifier as a microservice.

The protocol is pinned by **golden vectors** (`packages/login-verify/golden_vectors.json`, seed in `golden-seed.ts`): a frozen signing seed, fixed timestamp, and known-good assertion produce a pinned canonical body, a pinned Blake3-256 SAID, and a pinned signature. The microservice runs `runGoldenSelfTest` (`services/login-verify-ms/src/golden.ts`) on startup, which recomputes the SAID, compares the canonical body byte-for-byte, verifies the signature, and confirms a corrupted signature is rejected. Any drift in serialization or crypto breaks the self-test immediately. The golden assertion carries `p_kel` (the signed key log of the golden identity) and `site_aid`, and is checked for the site it names. The Go side reads the same file (`TestTheGoldenAssertionIsTheSameInGoAndTypeScript` in `identity-agent-core/login`) and checks the canonical body, the SAID, the signature, and that the key log derives the golden identity and puts the golden key in force, so a field added on one side only fails there. *(Amended 2026-10-24; adding the field showed that Go had computed the SAID over `"d":""` rather than over the body without `d`. Nothing verified the SAID, so the fix changed no outcome.)*

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
- Only the `login` action is implemented; present/pay/contact/issue are reserved and not yet wired to user flows.

---

## Implementation notes

- Core login types and handler: `identity-agent-core/login/types.go`, `identity-agent-core/login/handlers.go`.
- RP-side verifier library: `packages/login-verify` (`verifier.ts`, `standalone-verify.ts`, `qr-url.ts`, `oidc/`); browser glue in `packages/login-web`; microservice in `services/login-verify-ms`.
- OIDC adapter: `identity-agent-core/oidc/` (adapter, auth, idtoken, vp, discovery, conformance, profile), mirrored in `packages/login-verify/src/oidc/`.
- Golden vectors: `packages/login-verify/golden_vectors.json` + `golden-seed.ts`, self-tested by `services/login-verify-ms/src/golden.ts`.
- Score AuthProvider: `authproviders/identity-levels/main.go` (contract `ap-1`).
- A pairwise public key is taken from the identity's own key log, which every assertion carries signed in `p_kel`: the key counts only when the log validates and its inception derives the identifier named (`login.KeyFromKeyLog`). Site and signer keys come from the key log at their OOBI under the same check (`login.KeyFromOOBI`). A key read from a `did.json` at an address the assertion names is not used, because the assertion's author chose that address. Verifiers in other languages ask an Identity Agent to check a log (`POST /public/login/key`, `keyFromIdentityAgent` in `packages/login-verify`) rather than keeping a second implementation. The `did:webs` documents of ADR-024 are still served: for identities published to the registry, from keys proved this way; for the Identity Agent's own assets, from its own records. *(Amended 2026-10-24; until then keys were read from `{relayBase}/{aid}/did.json`.)*
- What a key log proves, and what it does not *(amended 2026-10-24)*:
  - It proves who signed it, never that it is the newest. A sign-in pairwise identity names no witnesses, so nothing could show a rotation of it is current; it is therefore never rotated, a log showing a rotation of an identity with no witnesses is refused, and a pairwise key is retired by ending the relationship. (Pairwise identities minted for an Ask signer, `mintPairwiseIn`, name witnesses when the witness service offers them.) An identity with witnesses is taken as its log stands; asking its witnesses for their newest event, so a shortened log is caught, is not done yet, and until it is a key such an identity has retired can still sign as it, for a person, a site or a signer alike. The relay protection above therefore holds for a site whose key was never compromised.
  - A delegator's approval of a site is the exception already closed: a delegator that names witnesses must show their receipts on every event of the log it serves, the approving seal included. Its witnesses saw any rotation and will not receipt a second event in its place, so a key it has retired cannot sign a new approval on a branch made from the shorter log.
  - Only single-key identities are checked: one signature travels per event, and thresholds are not read yet, so every multi-key identity is refused, including a `kt "1"` set such as a hybrid Ed25519 + ML-DSA key pair, whose single signature would in fact suffice.
  - A carried key log comes without a delegator's, so a delegated inception in it is refused. A site that claims a delegator for a membership sign-in is honoured only when the delegator's own verified log carries the seal approving the site (`verifyDelegationAnchor`, using `keri.ValidateDelegation`).
  - A carried key log is at most 8 events and 64 KiB.
- The assertion names the site whose challenge it answers (`site_aid`, signed). A site's audience, nonce and callback are text another site can copy into a challenge it signs itself; the key that signed the challenge is not, so a relying party refuses an assertion naming any site but its own. *(Amended 2026-10-24.)*
- The key registry (`/_register`) is a courtesy to whoever resolves a pairwise identifier later: registration failing does not stop a sign-in. Each identity is its own file under `registered_keys/`, bounded at 100,000 identities and 256 MiB; a full registry answers 507. A held log is replaced only by itself carried further, or by a rotation recovering it from interaction events made after its last establishment event. The open key-log routes (`/_register`, `/public/_register`, `/public/login/key`) allow each caller 60 checks a minute and at most 4 at once in all, and give a caller 10 seconds to send its request, which is read before a checking slot is taken. Requests through the URL relay all arrive from the relay's own address, so they share one budget of 600 a minute rather than counting as one caller; telling relayed callers apart needs the relay to pass on an authenticated address, which it does not yet do. An entry loaded from disk is proved again against the identity its file names. Publishing runs beside the sign-in, so a registry that hangs does not delay the person's consent screen. *(Amended 2026-10-24.)*

---

## Running & testing locally

The protocol is exercised end-to-end by existing tests — prefer these over ad-hoc scripts.

**Steel thread (challenge → assertion → verify):**

```
# identity-agent-core:
go test ./server/ -run 'AMemberSignsIn|NotInvitedIsRefused'
```

This runs the whole sign-in with nothing standing in for either side: a founded
organisation delegates a website asset and anchors the approval, its Identity
Agent serves the introductions, the signed challenge and the callback over HTTP,
and a person's Identity Agent holding only a root seed checks the site, checks
the organisation's approval of it, signs and is admitted (or, for an invite-only
site that invited nobody, refused on policy alone). The core runs `keri-go`
in-process, so this needs no Python and no external engine. Other proofs:
`packages/login-verify/src/steel-thread.test.mjs` and `go test ./login/...`
(`login_flow_test.go`, `canonical_test.go`, `verify_assertion_test.go`).
*(Amended 2026-10-24: the earlier `local-login-e2e.mjs` script relied on a
development site identity with no key log, which Identity Agents now refuse, so
it is removed.)*

The same run exercises the full KERI path (real inception + ACDC): `keri-go`
performs inception, signing and credential formatting directly.

**Local-run gotchas:**

- Set `PUBLIC_URL=http://127.0.0.1:PORT` and set the tunnel provider to `none`
  (`PUT /api/settings/tunnel {"provider":"none"}`) so the OOBI / callback URLs are
  localhost and don't depend on a tunnel warming up.
- When running two agents on one host, give each a distinct `PORT` so their
  listeners don't collide.
