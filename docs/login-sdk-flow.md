# Website login via SDK — flow and runbook

Passwordless website login where a website (a *relying party*) is registered as an
**asset** of an identity agent, and a user signs in with their own identity agent.
No passwords: the site binds its account to a **per-site pairwise AID** the user's
agent mints and signs for. This document is the map of where the code lives, how the
flow works, and how to run it.

## The flow

```
  SITE'S AGENT  (relying party — owns the website asset)      USER'S AGENT
  ──────────────────────────────────────────────────         ────────────────────────
  1. register website asset  ─► per-asset AID + HD signing key
  2. mint SIGNED challenge    ─► {session_token, qr_url, /i/{token} bundle}
                                     │  (QR / deep-link)
                                     ▼
                               3. fetch bundle, VERIFY the site's signature (site did.json / OOBI)
                               4. mint a per-SITE pairwise AID (unlinkable across sites)
                               5. SIGN an assertion (Ed25519 / KERI) + optional disclosures / ACDCs
                                     │  POST assertion → callback_url
                                     ▼
  6. VERIFY the assertion signature (resolve the asserter's did.json)
  7. AUTHORIZE against the asset's enrollment policy
  8. status → verified + pairwise_aid  ─► site binds its account to that pairwise AID
```

## Where the code lives (`identity-agent-core/` unless noted)

**Relying-party side (the agent that owns the website asset):**
- `asset/` — website-as-asset: `POST /api/assets` mints a per-asset AID + HD signing
  key, stores the enrollment policy, and returns `sdk_config`
  (`ASSET_ID`, `SITE_OOBI`, `SITE_PAIRWISE_AID`). CRUD + invites + members + policy
  routes in `server/asset_handlers.go`.
- `server/login_handlers.go` — `POST /api/login/challenge` (mint signed challenge),
  `GET /i/{token}` (serve the signed bundle), `POST /api/login/callback`
  (verify the assertion + `authorizeAssetAccess`),
  `GET /api/login/challenge/{token}/status`.
- `server/login_widget_adapter.go` — `createSignedAssetChallenge(...)` and the
  widget-compatible `POST /api/login/session/{asset_id}` (+ status).
- `server/public_didwebs.go` — serves the site's `did.json` / OOBI at
  `/public/oobi/{aid}` so the user's agent can verify the site's signature.

**User side (the agent that approves and signs):**
- `login/handlers.go` — `HandleStart` / `HandlePreview` (`prepareLogin`: fetch the
  bundle, `verifyChallengeSig`, mint the pairwise AID, build the consent preview),
  `HandleApprove` (`completeLogin`: sign the assertion, POST it to the callback),
  `HandleDecline`, `HandlePendingList`. Routes:
  `POST /api/login/{start,preview,approve,decline}`, `GET /api/login/pending`.
- `login/types.go` — `StartLoginRequest {session_token, rp_session_url}`,
  `LoginPreviewResponse`, and the assertion (incl. the `PresentedACDCs` slot — see
  *Credential-gated login*).
- `login/verify_assertion.go`, `login/canonical.go`, `login/sign_challenge.go` — the crypto.

**Crypto driver:** `drivers/keri_driver.go` talks to a Python KERI service
(`drivers/keri-core/server.py`) for KERI inception and ACDC issuance. Run it from the
project virtualenv **`drivers/keri-core/.venv-keri1117/`** (see *Gotchas*). For the
login steel thread, `ENABLE_KERI_DRIVER=false` uses Go-native Ed25519 and skips
Python entirely.

**Credential issuance:** `POST /credential/issue` →
`KeriDriver.IssueCredential(name, claims, schemaSaid, holderAid, edges)` — a real
KERI ACDC.

**SDK / website glue:**
- `packages/login-web/` — a React `SignInButton` widget (create session, poll, render
  QR, desktop deep-link, local-agent detection). The script-tag `createLoginButton()`
  path is currently a stub — finish it for no-bundler embedding.
- `packages/login-verify/` — the relying-party verify library
  (`IdentityAgentVerifier`, `mountIdentityAgentLoginRoutes`, a `did:webs` resolver, and
  a dev relay).
- `demo-rp/` — a runnable example website (Node) that calls `POST /api/login/challenge`,
  renders the QR, and polls status.

## Running it (use the existing tests — don't hand-roll a harness)

**Steel thread (challenge → assertion → verify), no KERI venv required:**
```
# terminal 1 — identity-agent-core:
ENABLE_KERI_DRIVER=false PORT=5050 go run .
# terminal 2 — packages/login-verify:
npm install && npm run build
IA_BASE=http://127.0.0.1:5050 node src/local-login-e2e.mjs
```
Other existing proofs: `scripts/login_steel_thread_test.py`,
`packages/login-verify/src/steel-thread.test.mjs`, and the Go tests
`go test ./login/...` (`login_flow_test.go`, `canonical_test.go`, `verify_assertion_test.go`).

**Full KERI path (real inception + ACDC):** run the core *without*
`ENABLE_KERI_DRIVER=false`, with
`KERI_DRIVER_PYTHON=drivers/keri-core/.venv-keri1117/bin/python`. When running two
local agents, give each a distinct `KERI_DRIVER_PORT` (default 9999 collides).

## Enrollment policy (who may sign in) — `asset/types.go` `EnrollmentPolicy`

`authorizeAssetAccess` (`server/login_handlers.go`) enforces, per asset:
- `mode`: **open** (any verified agent) · **request** (approve-then-member) ·
  **invite** (invited member)
- `required_aal` (NIST 800-63B level) · `required_badge` (badge tier: green/yellow/red) ·
  `required_ofa_score`

## Credential-gated login (not yet enforced)

To gate sign-in on the user *holding a specific credential (ACDC)*: the assertion has
a `PresentedACDCs` slot (`login/types.go`), but it is initialized empty and
`authorizeAssetAccess` does not check it. To implement: (a) add a `required_credential`
(schema SAID + issuer AID) to `EnrollmentPolicy`; (b) have the user's agent present the
matching ACDC in `PresentedACDCs` during `completeLogin`; (c) verify + enforce it in
`authorizeAssetAccess`. Credential *issuance* already exists (`/credential/issue`). The
`HandleRedeemInvite` / `HandleApproveRequest` member-binding is a related stub to finish.

## Gotchas

- **KERI driver:** use `drivers/keri-core/.venv-keri1117`, not the system Python — the
  system Python may not locate `libsodium`, which surfaces as a `/inception` 500.
- **Local runs:** set `PUBLIC_URL=http://127.0.0.1:PORT` and set the tunnel provider to
  `none` (`PUT /api/settings/tunnel {"provider":"none"}`) so OOBI/callback URLs are
  localhost and don't depend on a tunnel warming up.
- **Multi-instance:** distinct `PORT` and `KERI_DRIVER_PORT` per agent.
