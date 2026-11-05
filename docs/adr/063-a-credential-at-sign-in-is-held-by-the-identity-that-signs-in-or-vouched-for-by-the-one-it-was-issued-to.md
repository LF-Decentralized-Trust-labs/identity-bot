# ADR-063 — A credential at sign-in is held by the identity that signs in, or vouched for by the one it was issued to

**Status:** Proposed
**Date:** 2026-11-05
**Amends:** ADR-021 (Sign in with Identity Agent — login protocol)
**Relates to:** ADR-036 (A computer you pair with does not publish who you are), ADR-025 (Blind revocation registry client), ADR-056 (Revoking an AI agent is final), ADR-060 (A key or signature has one accepted string per spelling), ADR-035 (What a verifier can check for itself)

## Context

A site can require a credential before it admits someone (`RequiredCredSchema`,
`RequiredCredIssuer`, checked by `credentialGateSatisfied` in
`identity-agent-core/server/login_handlers.go`). A credential says it was issued
to one identity, its **issuee**. For the gate to mean anything the person
presenting it has to be that issuee: otherwise anyone holding a copy of someone
else's credential passes.

Per ADR-021 the identity that signs a sign-in is a **per-site pairwise identity**
(`getOrCreateRelationship`), never the person's root. So the gate now asks that
the issuee be the identity signing in (change on `origin/credential-gate-genuine`).
That is correct, and it fails closed for every credential that arrives from
outside:

- An outside issuer issues to whatever identity the person gave it. The receiving
  code assumes a pairwise identity per issuer ("A1: credentials issued to P-AID
  not Root", `handleReceiveCredential` in `identity-agent-core/server/server.go`)
  but then reads the issuee as a string field `a`, which in a real ACDC is the
  attribute block, so it falls back to the root; inbound delivery
  (`identity-agent-core/server/inbound_credential.go`) stores the holder as the
  root outright. Either way the credential's issuee is **not** the site's pairwise
  identity, and no credential from outside can ever pass a gate.
- The protocol already has fields for this (`PresentedCredential.PresSaidB64`,
  `CesrSig`, `HolderPublicKey`; `checkPresentation` in
  `identity-agent-core/keriengine/credentials.go`). They do not do the job:
  1. the gate only checks them if all three are present, so leaving them out
     skips the check rather than failing it;
  2. what is signed is the presentation's own identifier, a digest of
     {credential, holder, issuer, schema}. Nothing in it names a sign-in, a site
     or a challenge, so one valid signature is valid for every site and every
     later sign-in, forever. A site that receives it can replay it elsewhere;
  3. the key log of the issuee is optional, and when absent the key is only
     *claimed*; `checkPresentation` records an error for that, but the call is
     unreachable when the three fields are left out.

## Decision

**A site's credential gate accepts a credential in exactly two ways, and refuses
in every other case.**

1. **The issuee is the signer.** The credential's issuee equals the identity
   (`i`) that signed this assertion. Nothing else is needed. This is today's rule.
2. **The issuee vouches for the signer, for this sign-in only.** The assertion
   carries a **holder binding** (`HB1`): a statement signed by the issuee's
   **current** key, naming this challenge, this site and the identity signing in,
   together with the issuee's key log so the site can check the key is the
   issuee's.

The issuee is read from the credential's own attribute block (`a.i`, what the
engine parses as `Recipient`), never from the record's `holder_aid` field or
anything the presenter declares.

### What the holder signs (exact bytes)

The binding follows the assertion's canonical form (ADR-021, "Canonical
serialization"): compact JSON, fixed field order, NFC-normalized strings,
integer-second RFC3339 UTC times. The signed bytes are the UTF-8 of this body,
excluding `d` and `sig`:

```
{"v":"HB1","t":"holder-binding","i":"<issuee AID>","cred":"<credential SAID>",
 "signer":"<AID signing the assertion>","site_aid":"<site AID>",
 "audience":"<RP origin>","nonce":"<challenge nonce>","dt":"<RFC3339 UTC>"}
```

(Shown wrapped; the real body has no whitespace.) Every field is required; a body
with a missing, extra or reordered field is refused. `d` is the Blake3-256 SAID of
the body without `d` and `sig`; `sig` is the issuee key's Ed25519 signature over
the same UTF-8 bytes, written as the one accepted CESR `0B…` string (ADR-060: one
spelling per signature, so the same signature cannot be counted or recorded twice
under two strings). The key is a qb64 `D…` Ed25519 key, again with the one
accepted spelling.

Why each field is there:

| Field | What it prevents |
|---|---|
| `cred` | The statement is about this credential, not any other the issuee holds. |
| `signer` | It vouches for one identity. Without it, a site could attach it to a different assertion of its own making. |
| `site_aid`, `audience` | It cannot be replayed at another site (ADR-021 already makes `site_aid` the thing another site cannot copy). |
| `nonce` | It is for this challenge: a captured binding does nothing on a later sign-in. |
| `dt` | Freshness, same ±300 s window as the assertion. |

The binding travels inside the assertion's `presented_acdcs` entry, so the
pairwise signature on the assertion (which covers `presented_acdcs`) also covers
it: it cannot be stripped or swapped without breaking the assertion.
`PresentedCredential` gains `holder_binding` (the body, `d` and `sig`) and
`holder_kel` (the issuee's key log, same limits as `p_kel`: at most 8 events and
64 KiB). The old `pres_said_b64`, `cesr_sig` and `holder_public_key` are **not
accepted by the gate** any more: they are a replayable proof and stay only for
the verify route that exists for other callers.

### What the site checks, in order, each refused by name

1. The credential verifies (SAID, issuer's key log, schema, issuer; as today).
2. Its issuee is read from `a.i`.
3. If the issuee equals `signer`/`i` of the assertion: accept (path 1). Else a
   `holder_binding` is required; absent means refuse, never skip.
4. `holder_binding` has the exact shape above; `i` equals the issuee, `cred` the
   credential's SAID, `signer` the assertion's `i`, `site_aid`/`audience` this
   site, `nonce` this challenge, `dt` fresh; `d` re-derives.
5. `holder_kel` validates and its inception derives the issuee's identifier
   (`login.KeyFromKeyLog`, as for `p_kel`). The key in force is taken from the log,
   not from anything the presenter names; there is no `holder_public_key` on the wire.
6. `sig` verifies under that key.
7. The credential is not revoked, using its transaction log or a blind registry
   check (ADR-025). "Unknown" and "could not read" are refusals (see below).

### Replay

A binding is valid for one `(nonce, site_aid, audience, signer, cred)`. The site
callback settles a challenge once (`challengeStatus` in `login_handlers.go`); the
binding adds nothing to store, but the implementation must confirm a settled
challenge refuses a second assertion, because replay protection rests on it. A binding captured by anyone, including a malicious site that received it,
is dead anywhere else and on any later sign-in, because the nonce and site differ.
The one thing a binding does not stop is the site that received it **showing it to
a third party as proof that the two identities are one person** (see Privacy).

### An issuee that rotated

The credential names an identifier, not a key, so rotation of the issuee does not
invalidate the credential. The key in force is the last one in `holder_kel`.

- **A pairwise issuee that names no witnesses is never rotated** (ADR-021
  amendment 2026-10-24); a log showing a rotation of one is refused. Its key is
  its inception key.
- **An issuee with witnesses is taken as its log stands**, with the limit ADR-021
  already states: nothing yet shows the log is the newest, so a key the issuee has
  *retired* can still sign a binding. Stated here rather than hidden: for a
  rotated issuee, path 2 is only as strong as the presenter's log being current.
  Until witnesses' latest events are asked for (ADR-031), a site for which this
  matters should require path 1 (the credential issued to the signer) or an issuee
  without rotation. This does not widen anything: a stolen retired key already
  signs sign-ins as the identity today.
- A log whose end shows no key in force (abandoned, empty next-digest) gives no
  binding: refuse.
- Multi-key issuees are refused, as ADR-021 already refuses them for `p_kel`.

### A revoked or pairwise identity

- **Credential revoked.** Revocation is an event in the credential's transaction
  log, not a flag. The gate must be handed that log (or ask a blind registry,
  ADR-025) and refuse on `revoked`, `unknown` or a log that does not read. Today
  the gate passes neither, so a revoked credential passes; closing that is part of
  this change, not a follow-up.
- **The issuee is itself a pairwise identity** (e.g. the one made for the issuer).
  That is the intended case for path 2. It works only while the person's agent
  still holds that identity's key. **Ending the relationship with the issuer
  destroys the key** (ADR-021: a pairwise key is retired by ending the
  relationship), after which no binding can ever be made for credentials issued
  to it. The agent must say so before the relationship is ended.
- **The issuee is revoked or ended** (an AI agent's identity, ADR-056, or a
  relationship ended): no key signs, so no binding. Refusal is correct.
- **The signer's relationship with the site ended:** the agent signs nothing for
  that site; nothing to bind.

### What the site learns, and whether that is acceptable

Path 2 tells the site, in a signed statement it can keep and show others, that
the identity signing in and the issuee are **the same person**, and gives it the
issuee's identifier and key log. That is the cost of using a credential issued
elsewhere, and it is the same cost ADR-036 describes: an identifier visible in a
log is what lets someone recognise a person elsewhere.

What this means depends on **which identity the issuee is**:

- **A pairwise identity made for the issuer (the intended case):** the site learns
  an identifier that meant something only between that person and that issuer. It
  can join the person's two identities, and could do so with another site that
  received a binding for the same issuee; **two sites receiving the same issuee
  can compare notes and link the person across them.** The issuer already knows
  the issuee, so the issuer-site link is new information only for the site.
  Acceptable if the person agrees to it for this site.
- **The person's root identifier:** the site learns the one identifier that
  identifies the person in every relationship, permanently (ADR-036). **This is
  not acceptable by default.** The agent refuses to build a binding for a root
  issuee unless the person explicitly agrees, to this site, in words that say what
  it gives away. Where possible the person should ask the issuer to re-issue to
  the site's pairwise identity, which needs no binding and reveals nothing.
- **Deniability:** the signed binding is transferable proof of the link, not a
  claim only the site can verify. The site, or anyone it shows it to, can prove
  the link later. That loss is real and is the reason the consent below is not
  optional.

**How the person is told.** The consent screen for a sign-in that would use path 2
lists, for each such credential, in plain words: *"To use <credential> from
<issuer>, <site> will learn that your sign-in here and your <issuer> account are
the same person, and can prove it to others."* The person approves or declines
per credential; declining sends the sign-in without it. A root issuee gets a
separate, stronger line and starts declined. The consent preview
(`CredentialRequestPreview`) gains `needs_link` so the screen knows before the
person agrees. This is the Experience-OS "tell the truth about what is happening"
gate, and it means the person is never linked silently.

### Alternatives considered

**Always require issuance to the site's pairwise identity.** Reveals nothing and
needs no new protocol, but it only works for issuers who issue after the sign-in
is known, so it excludes every credential already held and every issuer that
issues once. Kept as the preferred route where possible, not the only one.

**Sign the existing presentation identifier plus a nonce.** A smaller change but
leaves the site and signer unbound and keeps the key optional; rejected for the
replay and skip-the-check weaknesses above.

**A zero-knowledge proof that the two identities are one person.** Avoids the link
and the transferable proof, but needs primitives this protocol does not have;
recorded as the way to remove the privacy cost, not part of this decision.

## Consequences

- Credentials from outside issuers can pass a gate, with the person's consent
  each time and with no replayable artefact.
- The gate never skips the holder check: no binding means refusal.
- The issuee is read from the credential, which also fixes the stored holder
  being the root (`handleReceiveCredential`, `inbound_credential.go`): both
  should record the issuee from `a.i`. Records already stored with the root as
  holder need a one-time re-read.
- The login wire format gains `holder_binding` and `holder_kel` in
  `presented_acdcs`, in Go (`login/types.go`) and TypeScript
  (`packages/login-verify`) together; the pinned golden assertion is unchanged
  because the fields are omitted when empty.
- Ending a relationship can strand credentials issued to it; the agent warns.

## Test vectors a site would check

Frozen seeds and a fixed `dt`, in `packages/login-verify/golden_vectors.json`
beside the assertion vector, read by Go and TypeScript. The byte-exact values
(canonical body, `d`, `sig`) are generated when this is implemented and pinned;
this draft fixes the **cases** and expected outcomes, and writes no values it has
not computed.

| # | Case | Expected |
|---|---|---|
| V1 | Issuee equals signer | accept, no binding needed |
| V2 | Issuee ≠ signer, valid `HB1` over the exact body, key log valid | accept |
| V3 | Same, but `holder_binding` absent | refuse: "issued to X, not to the identity signing in, and no binding" |
| V4 | `nonce` of an earlier challenge | refuse |
| V5 | `site_aid` or `audience` of another site | refuse |
| V6 | `signer` differs from the assertion's `i` | refuse |
| V7 | `cred` differs from the credential presented | refuse |
| V8 | `dt` outside ±300 s | refuse |
| V9 | Field missing, extra, or reordered; `d` does not re-derive | refuse |
| V10 | Signed by a key not in force in `holder_kel`; or log whose inception does not derive the issuee | refuse |
| V11 | Issuee rotated, signed by the new key, log shows the rotation, issuee has witnesses | accept |
| V12 | Same rotation for an issuee with no witnesses | refuse (ADR-021) |
| V13 | Signed by the retired key after a rotation | refuse where the log shows the rotation; **accept** where the log shown is shortened (the stated limit) |
| V14 | Credential revoked; transaction log unreadable; registry says unknown | refuse |
| V15 | Signature or key in a non-canonical spelling (ADR-060 cases) | refuse |
| V16 | Binding replayed on a later sign-in of the same site | refuse (nonce) |
| V17 | A binding from sign-in A attached to an assertion by a different pairwise identity | refuse (`signer`) |

## What this asks Rob to decide

1. Accept path 2 (the link is shown to the site, with the person's consent each
   time) rather than only "issue to the site's identity".
2. A root issuee: refuse by default, allow only on explicit per-site consent.
3. Accept the stated limit on rotated issuees with witnesses until witnesses are
   queried for their newest event.
