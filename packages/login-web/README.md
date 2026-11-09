# @identity-agent/login-web

React widget for "Sign In with Identity Agent" (login js-widget surface).

```tsx
import { SignInButton } from "@identity-agent/login-web";
```
## From a website's server

The site holds no key. Its organisation created a website asset; the server asks
that organisation's Identity Agent for a sign-in on it and, once the person has
answered, asks again who signed in:

```ts
import { startLoginSession, confirmLoginSession } from "@identity-agent/login-web/server";
// Any store with claim(key): boolean. @identity-agent/login-verify has an
// in-memory one (inMemoryConsumedNonces) and a durable, shareable one
// (fileConsumedNonces, from @identity-agent/login-verify/consumed-in-files). An in-memory
// store forgets on restart; use the durable one if you restart or run several processes.
// The claim carries a keep-until time (consumeForSeconds, default one hour).
const spent = { claim: (k) => !seen.has(k) && (seen.add(k), true) };
const seen = new Set();

// 1. The person asks to sign in. Show them `pointerUrl`; keep `collectorSecret` on the server.
const s = await startLoginSession({ agentUrl, assetId, audience: "https://your-site.example" });

// 2. When the page reports the sign-in finished (or on your own poll):
const r = await confirmLoginSession({ agentUrl, assetId, sessionToken: s.sessionToken,
                                      collectorSecret: s.collectorSecret, consume: spent });
if (r.state === "verified") issueYourSession(r.pairwiseAid);
```

`consume` makes a verified sign-in sign nobody in a second time (it is spent when `verified` comes back, so if your own session issue fails, start the sign-in again). The Identity
Agent has already checked the person's key log, the audience, the nonce and the
organisation's policy.

## From a page with no back end

A page with only the SDK can sign a person in. It talks to the website owner's
Identity Agent on its public login routes only, which is a sign-in to a website
asset and never access to an identity. The audience is the page's own origin,
which the Identity Agent reads from the `Origin` the browser sends; the page
cannot name another.

```ts
import { SignInButton } from "@identity-agent/login-web";           // or startPageSession/readPageSession from "@identity-agent/login-web/page"
import { checkSignInInPage } from "@identity-agent/login-verify/browser";

<SignInButton
  sessionEndpoint="https://ia.example.com/api/login/session/the-website"
  requestDisclosures={["display_name"]}
  onSuccess={async ({ signIn }) => {
    // The Identity Agent hands the page the assertion once, with the identity.
    const r = await checkSignInInPage(signIn!, {
      agentUrl: "https://ia.example.com",
      expectedSiteAid: "E…",   // optional: pin your website asset's identifier
      // consume: your own store, same shape as the back end's: claim(key, keepUntilMs)
    });
    if (r.valid) showSignedIn(r.pairwiseAID);
  }}
/>
```

`checkSignInInPage` asks the Identity Agent to check the person's key log
(`POST /public/login/key`, so the page carries no KERI code), then checks the
signature, that the audience is this page's origin, the challenge's nonce and
site, and freshness, and spends the assertion with the same rule a back end uses
(`consume.claim(key, keepUntilMs)`; the default is a store shared by the
page, forgotten with it). A second presentation to the same page load is refused
as already used. That is advisory, not a replay defence: the nonce and site come
in the same reply as the assertion, the store lasts one page load, and a user can
skip the check. The replay refusal is the website's own Identity Agent's, which
checked the assertion once when the person's Identity Agent called back.

What this does not give you: the audience binding to the website asset holds only if the asset names its website's origin (`origin`), otherwise any page's origin is accepted as the audience; the page trusts its Identity Agent for the
challenge's nonce and site (pin `expectedSiteAid`, and the audience is always
the page's own), and the key log is checked by the same Identity Agent that handed over the assertion, so the page's own checks are the audience, the pinned site and the replay store, not independence from that agent; a page's script is whatever the page serves, so a page
cannot keep a secret from a person who reads it. If the Identity Agent hands the
result over and the page's check then fails to complete (for example the key
check could not be reached), the result is gone: start the sign-in again.
