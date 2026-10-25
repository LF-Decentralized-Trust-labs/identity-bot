# @identity-agent/login-verify

Login challenge creation and assertion verification for relying parties (Node/TypeScript).

```ts
import { IdentityAgentVerifier, mountIdentityAgentLoginRoutes, keyFromIdentityAgent } from "@identity-agent/login-verify";

const verifier = new IdentityAgentVerifier({
  // Your site's sign-in identity: an asset of your organisation's Identity
  // Agent, which serves its key log so people's Identity Agents can check it.
  siteIdentity,
  // Checks the key log each assertion carries, by asking your organisation's
  // Identity Agent (over https). Without a resolveKey every assertion is
  // refused: a key is tied to an identifier only by its own log.
  resolveKey: keyFromIdentityAgent("https://your-organisations-identity-agent.example"),
});
```

A relying party signs people in through its organisation's own Identity Agent.
There is no path that verifies with one Ed25519 check against a key read from a
`did.json`: that cannot bind a key to its identifier.

`generateDevSiteIdentity` is for development only. It makes an identifier with
no key log behind it, so an up-to-date Identity Agent refuses every challenge it
signs.

