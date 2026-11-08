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
// in-memory one (inMemoryConsumedNonces); share one across processes if you have several.
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
