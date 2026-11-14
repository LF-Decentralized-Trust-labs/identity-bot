# @identity-agent/login-web

React widget for "Sign In with Identity Agent" (login js-widget surface).

```tsx
import { SignInButton } from "@identity-agent/login-web";
```
## Installing: what is published

Install and build this package **from a checkout of this repository**: `npm install` at the repository root links `@identity-agent/login-web` and `@identity-agent/login-verify` together as workspaces, and `npm run build` here builds login-verify first (`npm run build --workspace @identity-agent/login-verify`), which only works inside this repository.

Outside this repository the published package cannot be installed yet: it depends on `@identity-agent/login-verify` `^0.1.1` from the npm registry, and that version is not published there, so the install returns a 404. Publishing login-verify (then login-web) is the fix and is proposed as follow-up work; it has not been done.

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

## A utility app's page

A utility app opens no port: its page is loaded from a fixed address and reaches
the app's back end through a relay nobody trusts (ADR-072). `@identity-agent/login-web/app`
holds what such a page checks and keeps, once, so the page is the button and
this module:

```tsx
import { SignInButton } from "@identity-agent/login-web";
import { appFetch, loadPinnedApp, readPinnedAppLink } from "@identity-agent/login-web/app";

// The link the person opened carries #aid=…&kel=…&rid=…&api=…&seal=…&min=…&iat=… (a fragment, sent to no server).
// It is held to the app the page's own config.json pins:
// { "app": { "aid": …, "kel": …, "rid": …, "api": …, "min": …, "wit": "<address>,…" or "none" } }.
const app = await appFetch(readPinnedAppLink(location.hash, await loadPinnedApp()));
<SignInButton sessionEndpoint={app.sessionEndpoint} fetchFn={app.fetchFn}
  browserKey={app.browserKey} frontEnd="browser" requestDisclosures={[]}
  onSuccess={({ appSessionToken }) => keepSession(appSessionToken)} />
```

A hosted page is pinned to one app. Its own `config.json`, served beside it and
written when the page is published, names the app's identifier and key log, the
relay identifier, the back end's address (compared byte for byte, so it is
written in lower case up to the path), the relay identifier's latest key log
event and its witnesses. `readPinnedAppLink` refuses a link that names another
app, relay identifier or back end, so a crafted link opened on the real page
cannot run the sign-in against another back end. It also refuses a link that
leaves out a pinned witness or names an earlier event, and every sealing key
statement must reach the pinned event as well as the link's. A page with no pin,
or part of one, signs nobody in. The key log in a link is taken only if it
derives the pinned identifier. A page opened with no sign-in link (on one
conversation, say) uses `pinnedAppLink(pin)`, which fetches the statement in
force from the pinned back end and checks it the same way, so nothing it holds
lapses. A utility app's page never
looks for an Identity Agent on the visitor's own machine (`SignInButton`'s
`sameDeviceProbe` is off for `frontEnd="browser"`), so its policy need not allow
any loopback address.

`appFetch` refuses a key log that does not derive the app's identifier, makes
the key the browser cannot export, believes an answer only if the app signed it
for that call, and shows the code only if the challenge is the app's, for this
browser's key and the browser kind, and not lapsed. Every call after the start
carries a proof made with the key. The back end's half is `packages/login-go`.

Once signed in, `appSession(link)` makes every later call: it carries the
session and a proof, believes an answer only if the app signed it for that call,
throws `SessionEnded` (a sentence a person can act on) when the app says 401, and
`signOut()` ends the session at the app and here. `signInProblem` is the one
wording for a sign-in that was declined, ran out of time or could not reach the
app; `SignInButton` already hands it to `onError`. `refusalInWords` says a
refused answer that leaves the sign-in open (its `lastRefusal`) in words.

A page that wants none of React or a build step loads the ready-built
`bundle/identity-agent-app.js` (`@identity-agent/login-web/bundle`, global
`IdentityAgentApp`: `loadPinnedApp` and `readPinnedApp` (a configuration already read), `pinnedAppLink`, `readAppLink` (the pinned read: `readAppLink(location.hash, pin)`),
`appSession`, `mountSignIn`, `SessionEnded`).
`npm run build:app -- <folder>` makes it (`bundle/` by default, which git ignores): it is built from the sources, never committed, and a test fails if what it writes lacks what pages use.
