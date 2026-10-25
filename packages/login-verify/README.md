# @identity-agent/login-verify

Login challenge creation and assertion verification for relying parties (Node/TypeScript).

```ts
import { IdentityAgentVerifier, mountIdentityAgentLoginRoutes, keyFromIdentityAgent } from "@identity-agent/login-verify";

const verifier = new IdentityAgentVerifier({
  siteIdentity,
  // Checks the key log each assertion carries. Without a resolveKey every
  // assertion is refused: a key is tied to an identifier only by its own log.
  resolveKey: keyFromIdentityAgent("https://your-identity-agent.example"),
});
```

