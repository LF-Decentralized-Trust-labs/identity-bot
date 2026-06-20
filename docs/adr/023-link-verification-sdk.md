# ADR-023: Link Verification SDK

**Status:** Accepted
**Date:** 2026-06-19
**Deciders:** Rob Andersen

---

## Context

The web is full of links that claim to come from someone: a document, a profile, a payment request, a share link. Today a recipient has no cheap, local way to answer "does this link actually belong to the identity it claims, and has that identity been tampered with?" The usual answers are a TLS padlock (which only proves the host, not the controller) or trust in a centralized issuer (which reintroduces a platform).

We want any website or app to embed a small SDK that, given a URL or identifier, returns a trust verdict derived from cryptography the verifier checks **itself** — not a claim it is asked to believe. KERI already gives us the machinery: a `did:webs` identifier resolves to a published key event log (KEL), and replaying that KEL locally proves the current controlling key without trusting the host that served it.

---

## Decision

### Verification = did:webs resolution + local KEL replay → verdict

Given an input (a plain URL, a `did:webs:` DID, an OOBI URL, or a QR payload), the SDK:

1. **Normalizes** the input to a kind and a canonical string (`normalizeInput`).
2. **Derives the artifact URLs** for the identifier — `did.json`, `keri.cesr`, and `oobi` — from the `did:webs` host/AID structure (`didwebs.DeriveFromDID` / `DeriveFromURL`, `identity-agent-core/didwebs/urls.go`).
3. **Fetches** `did.json` and `keri.cesr` and reads the keystate headers (`X-Keri-Keystate-Seq`, `X-Keri-Cesr-Complete`). If the CESR stream is unparseable it falls back to the OOBI endpoint (`Resolver.Resolve`, `identity-agent-core/didwebs/fetch.go`).
4. **Replays the KEL locally.** The fetched events are handed to the KERI engine via `ValidateKEL` (`identity-agent-core/didwebs/keri_backend.go` → the Python driver's `/validate-kel`), which replays the chain and returns whether it is valid, the current public key, and any replay errors. The host's claim is never trusted — only the locally-replayed result counts. A mismatch between the `did.json` `id` and the expected DID forces the verdict to unverified.
5. **Classifies** the outcome and returns a verdict.

The orchestrator is `SDK.Verify` (`identity-agent-core/linkverifier/sdk.go`).

### The verdict

The result is a `VerificationResult` (`identity-agent-core/linkverifier/types.go`) with one of four outcomes:

| Outcome | Meaning | Band |
|---|---|---|
| `verified` | KEL replayed cleanly and the identifier binds | green |
| `tampered` | KEL replay failed / events mismatch | red |
| `incomplete` | partial fetch or CESR not complete (e.g., witness receipts below threshold) | amber |
| `unverified` | not found / no valid verification path | gray |

The verdict also carries the AID, the verification path (`did_webs` / `oobi` / `none`), the KEL-replay status, a last-verified timestamp, and — only when explicitly requested — contact correlation (`known` / `stranger`) and, in the gated tier, a score band and badge. The default (free) tier silently omits the score fields, so an embedder without a paid relationship still gets a usable verdict rather than an error.

### Caching and graceful degradation

Results are cached by a key combining input kind, input, flow, and tier, with a short positive TTL and an even shorter negative TTL, so repeated badge renders on a page don't re-replay the KEL. A `forceRefresh` flag bypasses the cache.

The verification flow is split into a **badge** flow (privacy-preserving — conceals who the identity is, just shows the trust band) and a **link** flow (may expose the verified `registered_to` ownership). Contact correlation is only available through an explicit IA-internal loopback path, never to anonymous web embedders.

### The embeddable web SDK

`packages/link-verify-web` is the browser package (`@identity-agent/link-verify-web`). Its public API is deliberately tiny:

- `verify(input, options?)` — GETs the IA loopback (`/api/verification/badge`) on `http://127.0.0.1:5050` by default and returns a `VerificationResult`. It **never throws**: on any failure it returns a neutral `unverified` / gray result, so a site embedding the badge degrades cleanly when no Identity Agent is running locally. It uses `credentials: "omit"` (no cookies).
- `renderBadge(container, result, options?)` — renders a colored dot + outcome label into a DOM element, with optional ownership display in the link flow.
- `verifyRequest` / `outcomeLabel` — helpers for non-browser callers and label mapping.

Because verification runs against the user's own Identity Agent over loopback, the heavy lifting (fetch, KEL replay, KERI engine) stays on the user's machine; the web SDK is a thin, safe client.

---

## Consequences

### Positive

- **Verifier-checked, not issuer-asserted.** The trust verdict comes from a locally replayed KEL, so a malicious host cannot fake a "verified" result — at worst it serves a KEL that fails replay (→ tampered) or is unreachable (→ unverified).
- **Embed in three lines.** A website drops in `verify` + `renderBadge`; the SDK never throws and degrades to a neutral badge when no IA is present.
- **Privacy-tiered.** The badge flow reveals only a trust band; ownership disclosure and contact correlation are opt-in and gated.
- **Cheap to repeat.** Caching with separate positive/negative TTLs keeps page-level badge rendering fast.

### Negative / Trade-offs

- Verification requires a local Identity Agent reachable on loopback; embedders without one get only the neutral fallback.
- Full KEL replay depends on the KERI driver being available; the SDK surfaces `incomplete`/`unverified` rather than a hard error when it is not.
- The gated (score-bearing) tier requires a provider relationship; the free tier intentionally returns less information.

---

## Implementation notes

- Go SDK and verdict types: `identity-agent-core/linkverifier/` (`sdk.go`, `types.go`, `cache.go`).
- did:webs resolution / KEL replay: `identity-agent-core/didwebs/` (`urls.go`, `fetch.go`, `replay.go`, `keri_backend.go`) → KERI driver `ValidateKEL` (`identity-agent-core/drivers/keri_driver.go`).
- Web SDK: `packages/link-verify-web/` (`verify.ts`, `badge.ts`, `types.ts`, `index.ts`); loopback route `GET /api/verification/badge`.
- The publishing side of `did:webs` (serving `did.json` / `keri.cesr` / `oobi`) is covered in ADR-024.
