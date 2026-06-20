# @identity-agent/link-verify-web

Embeddable **SEAM-15** link verification SDK for browser surfaces (M58 / SM7).

## Usage

```ts
import { verify, renderBadge } from "@identity-agent/link-verify-web";

const result = await verify("https://alice.example.com/doc", {
  flow: "link",
  tier: "free",
  coreBaseUrl: "http://127.0.0.1:5050",
});

const el = document.getElementById("badge")!;
renderBadge(el, result, { showOwnership: true });
```

## Architecture

- Browser embedders call the IA loopback route `GET /api/verification/badge` (IF7, `127.0.0.1` only).
- `contact_correlation` is populated only on that loopback path inside the user's IA.
- Without a local IA core, `verify()` returns neutral `unverified` (never errors).

## BLOCKED

- **BLOCKED:** Standalone browser verification without IA — no in-browser KEL replay; loopback or Go SDK required.
- **BLOCKED:** Gated tier in third-party embedders — silently degrades to free per SEAM-15 §3.2.
- **BLOCKED:** Production M35 did:webs publisher — verified path needs live `did.json` + `keri.cesr`.