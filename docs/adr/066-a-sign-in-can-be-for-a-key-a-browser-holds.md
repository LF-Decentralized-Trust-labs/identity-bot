# ADR-066: A Sign-In Can Be for a Key a Browser Holds

**Status:** Proposed
**Date:** 2026-11-05
**Deciders:** Rob Andersen
**Amends:** ADR-021 (Sign In with Identity Agent — Login Protocol)

---

## Context

A person who signs in to a website through their Identity Agent is let in by
the site's back end learning that the sign-in finished. What it then gives the
browser is a session token. A token is a bearer secret: whoever copies it —
from a log, an address bar, a shared screen, a browser extension — is let in
as that person, with no need for the person or their phone.

A browser can hold a key it cannot export (WebCrypto, `extractable: false`).
If the sign-in is bound to that key, and every later request proves possession
of it, a copied token alone is worthless: the thief lacks the key.

For that to mean anything, **the person's approval must be for that key**. If
the site only remembered the key beside the session, the person's phone would
have approved "let this site's visitor in", and a second browser could race
the first to the callback. So the key the browser holds is named in the
challenge, the person's Identity Agent repeats it in its signed assertion, and
the relying party accepts only an assertion that repeats the one it asked for.

Today the assertion repeats nonce, audience and `site_aid` only
(`login.Assertion`), so ADR-021 cannot carry this. This ADR adds one field to
each of the challenge and the assertion.

---

## Decision

### The browser key's name is its RFC 7638 thumbprint

A browser key is a P-256 key (ECDSA, the curve every browser's WebCrypto
supports for a non-extractable key). Its name in the protocol is its **JWK
thumbprint** (RFC 7638): the unpadded base64url of the SHA-256 of
`{"crv":"P-256","kty":"EC","x":"…","y":"…"}`, members in that order, no
whitespace. It is exactly 43 characters. One spelling only: base64url, no
padding, the unused bits zero (ADR-060). `login.ThumbprintP256` and
`thumbprintP256` in `packages/login-verify` compute it; both refuse
coordinates that are not 32 bytes in one spelling.

### One new field, `browser_key`, in the challenge and in the assertion

- **Challenge (ADR-021 Ask, `t`=1).** `browser_key` is optional. When present it
  is part of the signed canonical body, written after the relationship anchor
  fields and before `callback_url`. A challenge with none keeps its former
  canonical form, so every existing signature stays valid.
- **Assertion.** `browser_key` is optional. When present it is part of the
  signed canonical body and the SAID, written last, after `site_aid`. A
  person's Identity Agent copies it from the challenge it approved; it takes
  no other source. Nothing about the person's pairwise identity changes.

Both are omitted from the canonical body when empty. Go
(`canonicalChallengeBody`, `canonicalAssertionBody`) and TypeScript
(`packages/login-verify/src/canonical.ts`) write them byte for byte alike.

### The verifier refuses any mismatch, in both directions

`login.VerifyAssertionForBrowserKey` (and `verifyLoginAssertion` with
`expectedBrowserKey`) takes the thumbprint the challenge named — empty when it
named none — and requires the assertion's `browser_key` to equal it exactly.
Refused, with reason "browser key mismatch":

- the assertion names a different thumbprint than the challenge did;
- the assertion names none, though the challenge did;
- the assertion names one, though the challenge named none (so an assertion
  made for a browser key cannot be used where no key is bound);
- the expected value is not a well-formed thumbprint.

The check runs after the site check and before the signature check, in both
languages. `login.VerifyAssertion` is `VerifyAssertionForBrowserKey` with none
expected, so every existing caller (the OIDC adapter included) refuses an
assertion made for a browser key rather than silently dropping the binding.

A person's Identity Agent refuses a challenge whose `browser_key` is not a
well-formed thumbprint, before showing it.

### What the protocol does not do

The core only carries and checks the thumbprint. Proving, on each later
request, that the caller holds the key is the relying party's session layer:
it learns the public key from the browser (hashing it must give the
thumbprint it put in the challenge), and signs the session to it. That is
specified by whoever builds the session, not here.

### Golden vectors

`packages/login-verify/test-vectors/browser-key-thumbprint.json` pins, from
the golden signing seed and RFC 7515 appendix A.3's P-256 key: the thumbprint,
a signed challenge and a signed assertion carrying it (canonical bodies, SAID,
signatures), and a thumbprint that must be refused. Go
(`TestTheBrowserKeyVectorsAreTheSameInGoAndTypeScript`) and TypeScript
(`a-sign-in-for-a-browser-key-is-for-that-key.test.mjs`) both check them.

---

## Consequences

### Positive

- A copied session token, with no browser key behind it, lets nobody in.
- The person approves a sign-in *for a key*, so a second browser cannot be
  admitted on an approval made for the first.
- No change for any sign-in that names no browser key: bodies, SAIDs and
  signatures are unchanged.

### Negative / trade-offs

- A browser that clears its site data loses the key and must sign in again.
- A thumbprint is only a name. A relying party that never makes the browser
  prove possession gets none of the benefit.
- `login.VerifyAssertion` callers that have a challenge naming a browser key
  must move to `VerifyAssertionForBrowserKey`; until they do, they refuse such
  assertions (the safe direction).
- **Older person agents refuse a challenge that names a browser key.**
  `ReadChallengeBundle` reads a challenge strictly and rejects a field it does
  not know, so an Identity Agent that predates this ADR will not show or sign
  such a challenge. That fails safe: nothing is signed for the wrong key. But
  the challenge's version stays "ASK1", so nothing tells a relying party in
  advance, and a relying party that asks for a browser key locks out every
  person whose agent has not updated. A relying party should ask for a browser
  key only when the person's agent is known to support it (for example because
  the agent advertises support), and otherwise fall back to a challenge that
  names none, accepting the weaker, bearer-token session for that person.

## Implementation notes

- Go: `identity-agent-core/login/browser_key.go`, `canonical.go`, `types.go`,
  `verify_assertion.go`; the callback in `identity-agent-core/server/login_handlers.go`
  verifies against the stored challenge's `browser_key`; a challenge is made for
  a key with `browser_key` on `POST /api/login/challenge` and `browserKey` on
  `POST /api/login/session/{asset_id}`.
- TypeScript: `packages/login-verify` (`LoginChallenge.browser_key`,
  `CreateChallengeOptions.browserKey`, `VerifyAssertionOptions.expectedBrowserKey`),
  `services/login-verify-ms` (`expected_browser_key`), `packages/login-web`
  (`SignInButton`'s `browserKey`).
- Add-ons (`addon.Host`, `identity-agent-core/addon/addon.go`). An add-on that
  fronts an asset (an app that serves pages) starts and reads a sign-in for a
  browser's key through three Host methods; it is the same challenge and
  result `POST /api/login/challenge` and `GET /api/login/challenge/{token}/status`
  serve to a caller of the core's API, for a caller that is code in the core's
  process. The person's Identity Agent fetches the challenge at `/i/{session}`
  and answers at `/api/login/callback`; none of that is the add-on's.
  - `StartBrowserKeySignIn(assetID, audience, browserKey, publicURL)` returns a
    `server.BrowserKeySignIn`: `CanonicalBody` and `Sig` (the exact text the
    asset signed, and the signature, so a party outside the process can check
    them), `Pointer` (what the Identity Agent opens), `Session` and `Collector`.
    Keep `Session` and `Collector` on the server; show the browser neither.
    `browserKey` is the 43-character thumbprint. It fails with a
    `*server.SignInRefused` carrying the status the route would have answered
    (400 for no key or a malformed one, 404 for an unknown asset).
  - `BrowserKeySignInResult(session, collector)` returns a
    `server.BrowserKeySignInResult`: `State` is `pending`, `declined` or
    `verified`; when verified, `Pairwise` is the person's identifier at the
    asset, `BrowserKey` the thumbprint the assertion repeated (compare it to the
    one asked for) and `Disclosures` what the person chose to show. A wrong
    `collector`, an unknown session and a sign-in that was not for a browser's
    key all return the same error.
  - `AssetStillAdmits(assetID, pairwiseAID)` asks again whether the asset's
    enrolment policy admits that person, by **membership only**: it does not
    re-check a required credential, which needs what the person presented. An
    error means the asset could not be read, which is not an answer either way.
    Use it to sign out someone removed from the roster since they signed in.

### A signed-in person speaks to an AI agent from the app's page

The app's back end opens a session here with the Host's `OpenAppSession(appID,
tokenHash, x, y, person, expires)`: the SHA-256 of the session token
(`login.BrowserSessionBinding`; never the token), the P-256 key the sign-in
approved, the person the organisation can prove, and when it ends. The talk
routes (`POST` and `GET /api/mcp/agents/{id}/conversations`, `GET
/api/mcp/conversations/{cid}`) then accept, besides a paired controller, a
request that carries the token as a bearer **and** is signed by that key
(`login.BrowserProofString`: fresh within two minutes, used once, covering the
method, host, target and body, so a proof made for one Identity Agent is
no proof at another). `OpenAppSession` refuses a person who stands as the
owner, an app id that is not an `app` asset this core hosts, and a token hash
already in use; it also drops sessions that have ended. Such a request is never a controller and has no
grant; `TheAppSessionThatAsked` tells a handler it came this way so it can show
that person only what is theirs. A request whose `Origin` is not the session's
app, a session for something that is not an `app` asset, an ended or expired
session, and a person who no longer stands are refused. The router answers CORS
for an origin an `app` asset lists, on those routes only.

*Added 2026-11-06:* an app session also reads which AI agents its person may
talk to, at `GET /api/app-session/agents`, so an app can show them before
anyone speaks. It is admitted exactly as the talk routes are (the token as a
bearer, every request signed by the session's key, from the app's listed
origin only), and it is the only route besides them that an app session
reaches. It answers `{"agents": [...]}` for the person the session names, by
the rule the talk routes ask (`agentmessage.PersonRef.MayTalkToAnAIAgent`: a
signer or the owner may talk to every AI agent of the organisation, an
employee to none, who is answered an empty list). Of each AI agent it says only
`id`, `name`, `agent_aid`, `person_aid` (the signer of the machine that made it,
else the owner) and `organisation_aid` (the organisation that delegated it):
nothing of its brain, machine, capabilities or grant. A caller that is not an
app session is refused, and a controller's `GET /api/mcp/agents` is unchanged.
It cannot see an AI agent the AI-agent add-on has revoked, which that add-on
alone records; a talk to one is refused there as before.
