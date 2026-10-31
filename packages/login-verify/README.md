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
`mountIdentityAgentLoginRoutes` does this for its callback, and mounts on an
app, a `Router` or a sub-app. What else to mount depends on your body parsers:

- **No body parser of your own**, or only ones mounted after these routes:
  nothing. The callback reads its own body.
- **A body parser mounted before these routes**, anywhere above them
  (including a parent app's): mount `identityAgentCallbackBody()` before it,

  ```ts
  app.use(identityAgentCallbackBody());
  app.use(express.json());
  mountIdentityAgentLoginRoutes(app, verifier);
  ```

  Where the routes sit under a prefix, name the callback's full path:
  `identityAgentCallbackBody({ path: "/login/auth/ia/callback" })`. It reads
  only a POST to exactly that path, matched as Express matches routes (case
  and a trailing slash ignored unless you pass `caseSensitive` or `strict`),
  and answers a body over 1 MiB with 413.

  Or give every parser that could read the callback `keepLoginRawBody` as its
  `verify` option: `app.use(express.json({ verify: keepLoginRawBody }))`.

Without one of these, a parser has already read the assertion by the time the
callback runs, and the callback refuses it with a message naming both. The
session route reads its options whatever parsers you have.

`maxSkewSeconds` is a whole number of seconds: left out (undefined), zero or
less means the default of 300, more than 3600 is narrowed to 3600, and
anything else, `null` included, is refused.

`generateDevSiteIdentity` is for development only. It makes an identifier with
no key log behind it, so an up-to-date Identity Agent refuses every challenge it
signs.
