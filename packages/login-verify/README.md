# @identity-agent/login-verify

Login challenge creation and assertion verification for relying parties (Node/TypeScript).

A relying party signs people in through its organisation's own Identity Agent,
which holds the site's sign-in identity and its key, serves the site's key log
so people's Identity Agents can check the site, and checks each person's key
log. There is no path that verifies with one Ed25519 check against a key read
from a `did.json`: that cannot bind a key to its identifier.

**What works today.** A website signs people in through its organisation
Identity Agent's own routes: it asks for a challenge (`POST /api/login/challenge`,
or the widget route `POST /api/login/session/{asset_id}`), shows the person the
pointer, and on its server confirms the result with `confirmLoginSession` from
`@identity-agent/login-web`. The person's assertion reaches the Identity Agent's
`/api/login/callback`, which does every check.

**What does not work yet.** `IdentityAgentVerifier` signs challenges with a site
key the caller holds. A real site's key stays inside its organisation Identity
Agent and is never exported, so this class cannot serve a real site until it can
ask that Identity Agent to sign; up-to-date Identity Agents refuse every
challenge it signs today. `verifyLoginAssertion` with `keyFromIdentityAgent`
does work for checking an assertion:

```ts
import { verifyLoginAssertion, keyFromIdentityAgent } from "@identity-agent/login-verify";

const result = await verifyLoginAssertion(assertion, {
  expectedAudience: "https://your-site.example",
  expectedNonce: nonceYouIssued,
  expectedSiteAid: yourSitesIdentifier,
  // Checks the key log the assertion carries, by asking your organisation's
  // Identity Agent (over https).
  resolveKey: keyFromIdentityAgent("https://your-organisations-identity-agent.example"),
});
```

An assertion is read by the Identity Agent core's rules, so the two accept
exactly the same ones. A repeated key, and a whole number written as `1.0`,
can only be seen in the text, which `JSON.parse` discards: where you receive an
assertion as text, read it with `readAssertion(text)` before verifying it.
`mountIdentityAgentLoginRoutes` does this for its callback wherever you mount
it, before or after a JSON body parser of your own.

`maxSkewSeconds` is a whole number of seconds: zero or less means the default
of 300, more than 3600 is narrowed to 3600, and anything else is refused.

`generateDevSiteIdentity` is for development only. It makes an identifier with
no key log behind it, so an up-to-date Identity Agent refuses every challenge it
signs.
