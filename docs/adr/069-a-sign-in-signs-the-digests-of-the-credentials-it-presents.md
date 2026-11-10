# ADR-069: A Sign-In Signs the Digests of the Credentials It Presents

**Status:** Proposed
**Date:** 2026-11-08
**Deciders:** Rob Andersen
**Amends:** ADR-021 (Sign In with Identity Agent — Login Protocol)

---

## Context

A sign-in assertion carries `presented_acdcs`: the credentials the person showed
the site, each with its full body. ADR-021 (amendment of 2026-11-08) lets a page
with only the login SDK and no server of its own sign a person in, and hands the
assertion to that page's collector so the page can check it. The collector is any
script in the page. So a credential the person showed to the website's owner is
also handed to every script the page loads, which the person never agreed to and
the website's owner never needed. A stopgap releases the assertion only to a
sign-in a page started; it does not stop that page's own scripts reading it.

The credentials are needed in one place: the website owner's Identity Agent, which
checks them against the asset's policy when the person's Identity Agent calls back.
The assertion's signature needs only to bind the person to *which* credentials
they showed, not to carry their contents.

## Decision

1. **The assertion signs digests.** `presented_acdcs` holds one string per
   credential shown: the credential's SAID, the digest the credential carries as
   its own `d` and which names its exact body. The field keeps its name and its
   place in the canonical body, so a signature covers the list as before; only its
   elements change from credential objects to strings.
2. **The full credentials travel beside the assertion, to the callback only.**
   When the person's Identity Agent posts to a callback it sends
   `{"assertion": <the assertion>, "credentials": [<the full credentials>]}`
   whenever it presented any. With none, it posts the bare assertion as before.
   The `credentials` are not signed; they are bound by the digests that are: the
   owner's Identity Agent uses a posted credential only if its SAID is one the
   assertion names and the body it carries has that SAID. A credential posted but
   not named is ignored; a digest named but not posted is a credential not
   presented.
3. **A page collector receives the assertion, which names digests, and never the
   credentials.** The owner's Identity Agent keeps the posted credentials for the
   policy check and does not store or release them.
4. **One window for the old form.** An assertion whose `presented_acdcs` holds
   credential objects is still read and still checked at the callback, because the
   owner's Identity Agent (`handleLoginCallback`) and the Express callback in
   `packages/login-verify` take assertions from Identity Agents that have not
   updated. Such an assertion is **never** handed to a page collector, since it
   would carry the credentials with it; the sign-in completes without it. The
   window ends in the first release after every Identity Agent we ship sends the
   new form; the old form is then refused, by a later ADR amendment.
5. **The OIDC adapter** puts the full credentials in the VP token it builds, as
   now, and the digests in the assertion it embeds in the ID token.

## Consequences

### Positive

- A script in a website's page learns that a credential was shown and which one,
  not what it says.
- The signed assertion binds the person to exact credentials, so a credential
  cannot be swapped in the post after the person approved.
- No change to the canonical field order or the SAID rules, so a verifier that
  checks only the signature reads the new form unchanged.

### Negative / Trade-offs

- A digest is a stable identifier of the credential. A page can tell that the
  same credential was shown on two sign-ins to it. Pairwise identities already
  make the person unlinkable across sites; they do not hide a credential's own
  identifier from one site.
- A verifier in another language that checked credentials from the assertion
  alone must now read the callback's envelope.
- Two forms exist until the window closes.

## Implementation notes

- Person's side: `login.Handler.buildAssertion` and `postAssertion`
  (`identity-agent-core/login`); the post body is read by `login.ReadSignInPost`.
- Owner's side: `handleLoginCallback` and `boundCredentials` in
  `identity-agent-core/server/login_handlers.go`.
- TypeScript: `postedAssertion` in `packages/login-verify/src/express-handlers.ts`
  reads both bodies.
- Vectors: `packages/login-verify/test-vectors/core-canonical-and-spellings.json`
  gains an assertion presenting digests, read by Go and TypeScript alike.
