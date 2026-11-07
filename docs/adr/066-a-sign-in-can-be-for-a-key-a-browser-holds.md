# ADR-066: A Sign-In Can Be for a Key a Browser Holds

**Status:** Proposed
**Date:** 2026-11-05
**Deciders:** Rob Andersen
**Amends:** ADR-021 (Sign In with Identity Agent — Login Protocol)
**Amended by:** ADR-072, 2026-11-09 (the talk-route note)

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

### A signed-in person speaks to an AI agent from the app's page — SUPERSEDED

**Superseded 2026-11-07 by the owner's ruling, citing ADR-006, and by ADR-072.** An Identity
Agent core is never reached from a browser, by anyone, for anything, on any
route: a browser cannot check the code it is served, cannot verify the machine,
and has no enclave. This section described the opposite: an app's back end
opened a session in the core (`OpenAppSession`, `EndAppSession`,
`EndAppSessionsOf`), and the core admitted a request carrying the session token
and a browser-key proof from the app's origin on the talk routes, answering
CORS for that origin. All of it is removed: the core keeps no app-session
registry, admits no browser credential, and answers no browser origin on any
route.

What stays is the sign-in above, which is browser -> app: the browser key named
in the challenge and repeated in the person's assertion, and the app's own
session layer that makes the browser prove it holds the key.

**What the core keeps from the sign-in.** When the callback verifies an
assertion that repeats the challenge's `browser_key`, the core records, itself,
"key K speaks for person P at asset A until T" (P is the pairwise identifier
the assertion proved, T is 12 hours on). The app does not write it and cannot.
It is the only way the core learns whose a browser key is.

**How a person talks to an AI agent from the app's page.** The browser talks to
the app, and the app's back end, an enrolled machine bound to the app's asset,
talks to the core with its own signed request, naming the person and carrying
the statement the person's browser key signed over a salted fingerprint of
their words (ADR-067) and that fingerprint's salt. The machine's grant is the
app's, not one person's: it may speak for whoever the asset admits now
(`assetStillAdmits`), so an organisation's chat app can serve all its
employees. The core admits the request only when all of these hold, and an app
machine that sends no statement is refused:

- the statement is checked by `trail.CheckAuthor`, the same function
  `trail.Write` runs first: well formed, the signature holds, it is for this
  Identity Agent, and the recorded sign-in says that key speaks for that person
  at that asset, has not lapsed, and the asset still admits them;
- it is fresh to within `authorisation.Skew` (`trail.CheckFresh`), the rule the
  trail and the conversation bundle hold every statement to;
- it is for this request: its fingerprint is of the words in the body under the
  salt, and its conversation, kind (a message or an ask), recipient, reply and
  message id (the body's `nonce`) are the route's and the body's;
- it has not been used before.

**The browser key is P-256 and stays P-256.** The statement's signer is the
browser key itself, in the machine-key form every other key in the core has
(`agentbody.Verify` verifies P-256 as well as Ed25519, low-s), and the key is
matched to the sign-in by its RFC 7638 thumbprint
(`login.BrowserKeyThumbprintOfMachineKey`). The alternative, a sign-in naming an
Ed25519 key, would change this ADR's wire format, its vectors and its
TypeScript packages, and a non-extractable Ed25519 key is not available in
every browser's WebCrypto. An Ed25519 key has no thumbprint here and speaks for
no one.

Nothing in this path reaches the core from a browser. The core's other browser
routes, and the login widget's `/api/login/session/*` CORS, are not changed by
it.

### How long a key speaks, and what ends it early

A sign-in lets its key speak for at most twelve hours (`browserKeyLife`), and
three things can end that sooner. Each is checked when the key is used, not
only when the person signed in.

- **The app signs the person out.** The app's back end calls
  `Host.EndBrowserKeys` with the request it signs as any controller does, naming
  a key by its thumbprint or a person by their identifier at the asset (every key
  of theirs ends). The asset is the one the calling machine is bound to
  (`ControllerGrant.AppAsset`), never one the caller names, so an app can end
  only its own asset's records. Ending only takes power away, so the app that
  signed the person in may do it. A key whose record is gone speaks for no one;
  speaking again takes a new sign-in.
- **The asset stops standing behind the person.** `keysSpeakingAt` asks the
  asset's whole gate again (`assetStillStands`): the enrolment policy's
  membership gate and, where the policy requires a credential, that credential
  as the person presented it at sign-in, verified again. The record keeps what
  was presented for that (`browserKeyRecord.Presented`, only the entries of the
  required schema). A person whose required credential has lapsed or been
  revoked stops speaking on the next use, not at the end of the twelve hours.
  The employee list is not the asset's answer and is not consulted.
- **A statement works once, across a restart.** What has been used is kept in
  `person_statements_used.json` in the data directory for as long as a statement
  could still be fresh, so restarting the core does not make a used statement
  usable again. A statement that cannot be marked used is refused.

A statement names the conversation it is for, and the request names the same
one: a request that names none (it would open a new conversation) matches no
statement. A statement is for the AI agent it names, and is accepted only on
that agent's route. A person an app spoke for is `Signer{Standing: "member",
Asset: <asset>}`, and whether they still stand for a conversation they opened is
the asset's answer (`personStandsAtAsset`).

**What the conversation bundle shows of it.** A controller entry carries the
person's statement (`agentmessage.ControllerProof.PersonStatement`), and the
record is held to it: signed by the key it names, from the person the entry is
from, naming this entry's conversation, kind, recipient, reply and message id.
The bundle also checks it names this organisation and was signed within
`authorisation.Skew` of when the Identity Agent took it. It cannot show that
the machine is the back end of an app, or that the key is the person's: the
asset is not in the machine's Controller Grant credential, so the bundle says
that is the Identity Agent's word. Carrying it in the credential is a new
version of the Controller Grant schema and is not part of this change.
