# ADR 008: Grape ID Tunnel Provider — Architecture and Design

**Date:** 2026-03-03
**Status:** Accepted
**Relates to:** ADR-001 (Core Architecture), ADR-003 (Adaptive Architecture), ADR-006 (Standardized Topology), `docs/grapeid-hub-reconnect-spec.md`

## Context

The Identity Agent needs a publicly accessible HTTPS URL so that other agents can discover and interact with it via OOBI (Out-of-Band Introduction) endpoints. This URL must be:

1. **Static and permanent** — the same URL should work across restarts, so contacts don't need to be re-introduced every time the agent reboots.
2. **Cross-platform** — the same URL should work whether the agent is running on desktop (Linux, macOS, Windows) or mobile (Android, iOS).
3. **Portable** — if the user migrates their identity from a phone to a desktop (or vice versa), the URL should continue working on the new device without requiring contacts to update anything.
4. **User-chosen** — the URL path should be a human-readable name the user picks (e.g., `https://grapeid.org/alice`), not a random hash.

The existing tunnel providers (Cloudflare and ngrok) could not satisfy all four requirements. A custom tunnel service was needed.

## Why Not Cloudflare or ngrok?

### Cloudflare

Cloudflare offers two tunnel modes:

- **Quick Tunnel (free, no account):** Generates a random subdomain like `https://abc123-random-words.trycloudflare.com`. The URL changes on every restart. It cannot be transferred between devices. It requires the `cloudflared` binary, which only runs on desktop — there is no embeddable library for mobile.
- **Authenticated Tunnel (requires account + token):** Provides a stable custom domain, but requires a Cloudflare account, a registered domain, and a tunnel token. The free tier does not offer portable named tunnels that can be moved between devices. The `cloudflared` binary is still desktop-only.

**Cloudflare's limitations for the Identity Agent:**
- No mobile support (binary-only, no embeddable SDK).
- Free tier URLs are random and change on every restart.
- No mechanism to transfer a tunnel name from one device to another — the tunnel token is bound to a specific Cloudflare account configuration.

### ngrok

ngrok provides stable URLs on paid plans, but:

- **Free tier ($5/month for static domains):** More expensive than running a custom tunnel service for our needs.
- **Portability:** ngrok URLs are tied to auth tokens and tunnel configurations. Moving a static domain from a mobile device to a desktop requires reconfiguring the ngrok account, not just pointing the same name at a new backend.
- **Mobile support:** ngrok does provide an embeddable Go library (`ngrok-go`), so it works on mobile via gomobile. This is its main advantage over Cloudflare.

**ngrok's limitations for the Identity Agent:**
- Cost: even the cheapest static domain plan exceeds the cost of running a lightweight custom hub.
- No user-chosen vanity paths (URLs are ngrok-assigned subdomains, not `/alice` style paths).
- Portability between devices requires account-level configuration changes, not a simple protocol operation.

### Summary of Provider Capabilities

| Requirement | Cloudflare (free) | ngrok (free) | Grape ID |
|---|---|---|---|
| Static URL across restarts | No (random) | No (random) | Yes |
| User-chosen name | No | No | Yes (`/alice`) |
| Works on mobile | No (binary only) | Yes (Go lib) | Yes (Go lib) |
| Works on desktop | Yes | Yes | Yes |
| Portable between devices | No | No | Yes (AID-based) |
| Cost | Free | $5+/month for static | Self-hosted hub |
| Custom domain | Paid only | Paid only | Hub operator's domain |

## The Decision

Build a custom tunnel provider ("Grape ID") that uses a Chisel reverse proxy to connect the agent to a community-operated hub server. The hub assigns a user-chosen path name (e.g., `/alice`) and routes incoming HTTPS traffic to the agent's local port through the Chisel WebSocket tunnel.

### Why Chisel?

Chisel is a lightweight, single-binary reverse proxy built on WebSockets. It was chosen because:

- **Pure Go:** Compiles into the agent's Go Core binary. Works on mobile via gomobile with no external dependencies.
- **WebSocket transport:** Traverses firewalls and NAT without special configuration. Works behind corporate proxies.
- **Lightweight:** The Chisel client adds minimal overhead to the binary size.
- **Proven:** Mature open-source project with built-in reconnection and keepalive support.

### Why AID-Based Ownership?

Each tunnel name on the hub is associated with the agent's AID (Autonomic Identifier). This provides:

- **Portability:** The AID is part of the agent's identity, not tied to a device. When migrating from phone to desktop, the new device's agent presents the same AID and reclaims the name.
- **Security (TOFU):** The hub uses trust-on-first-use — the first AID to claim a name owns it. Future versions will upgrade to full KERI signature verification.
- **Reconnection:** After a restart, the agent proves ownership by presenting its AID to the `/reconnect` endpoint, avoiding re-registration.

## Architecture

### Components

```
┌─────────────────────┐         ┌──────────────────────────┐
│   Identity Agent    │         │     Grape ID Hub         │
│                     │         │     (grapeid.org)        │
│  ┌───────────────┐  │  WSS    │  ┌────────────────────┐  │
│  │ Chisel Client ├──┼────────►│  │  Chisel Server     │  │
│  └───────┬───────┘  │         │  └────────┬───────────┘  │
│          │          │         │           │              │
│  ┌───────┴───────┐  │         │  ┌────────┴───────────┐  │
│  │ Go Core       │  │         │  │  Reverse Proxy     │  │
│  │ (port 5050)   │  │         │  │  (HTTPS → tunnel)  │  │
│  └───────────────┘  │         │  └────────────────────┘  │
└─────────────────────┘         └──────────────────────────┘
                                           ▲
                                           │ HTTPS
                                    ┌──────┴──────┐
                                    │  Contacts   │
                                    │  resolving  │
                                    │  OOBI URL   │
                                    └─────────────┘
```

**Data flow:**
1. Agent starts → registers name on hub via `/claim-name` or `/reconnect`
2. Hub allocates a port and returns it to the agent
3. Agent opens a Chisel WebSocket to the hub, creating a reverse tunnel from hub port → agent's local port
4. External contacts visit `https://grapeid.org/alice` → hub reverse-proxies the request through the Chisel tunnel → arrives at the agent's Go Core on localhost
5. Agent serves OOBI, KEL, contact exchange responses through the tunnel

### Hub API

The hub exposes three endpoints for name lifecycle management:

| Endpoint | Purpose | When Called |
|---|---|---|
| `POST /claim-name` | First-time registration of a new name | First startup, or after explicit release |
| `POST /reconnect` | Re-establish a previously claimed name | Every subsequent startup |
| `POST /release-name` | Voluntarily give up a name | Future: explicit "release name" UI |

All three accept `{"name": "...", "aid": "..."}` in the request body. See `docs/grapeid-hub-reconnect-spec.md` for the full hub-side specification.

The hub also exposes:
- `GET /health` — Hub reachability probe (used by the agent's settings UI to show AVAILABLE/UNAVAILABLE badges)
- `GET /check-name?name=...` — Name availability check (used by settings UI before saving)

### Connection Flow (Reconnect-First)

On startup, the agent always tries to reconnect before claiming:

```
1. Load saved tunnel settings (provider, domain, extension/name)
2. Load agent AID from identity store

3. Try POST /reconnect {"name": "<extension>", "aid": "<AID>"}
   → 200? Parse response (port, tunnel_path). Done — proceed to Chisel connect.
   → 404 (name not found)? Go to step 4.
   → 403 (AID mismatch)? Fail with error — someone else owns this name.
   → Connection error / other? Go to step 4.

4. Try POST /claim-name {"name": "<extension>", "aid": "<AID>"}
   → 200? Parse response (port, tunnel_path). Done — proceed to Chisel connect.
   → 409 (already taken)? Fail with error.
   → Other error? Fail with error.

5. Open Chisel WebSocket to hub's tunnel_path
   → Remote mapping: hub_port → localhost:agent_port
   → KeepAlive: 25 seconds
   → MaxRetryCount: -1 (infinite reconnect)
```

### Disconnect vs Release (Shutdown Lifecycle)

The `Provider` interface defines two shutdown methods to handle the distinction between a temporary disconnection and a permanent name release:

| Method | Behavior | When Used |
|---|---|---|
| `Disconnect()` | Closes the Chisel WebSocket connection. Does NOT call `/release-name`. The hub keeps the name reserved so the next startup can use `/reconnect`. | All restart paths: SIGTERM, workflow restart, settings changes, mobile app resume. |
| `Stop()` | Calls `/release-name` on the hub (best-effort, 3s timeout), then calls `Disconnect()`. The name becomes available for anyone to claim. | Future: explicit "release name" UI button. Not currently called in any active code path. |

**Why this separation matters:**

Without it, every restart triggered a release → claim cycle. The agent would call `/release-name` during shutdown, then on the next startup `/reconnect` would fail (name already released), forcing a fallback to `/claim-name`. This created unnecessary hub load, introduced a race window where someone else could take the name, and caused port churn on the hub.

With the separation, restarts use `Disconnect()` (no release), the hub keeps the name reserved, and the next startup's `/reconnect` succeeds immediately.

**Call site summary:**

| Call Site | Method | Releases Name? | Reason |
|---|---|---|---|
| `CoreServer.Stop()` (SIGTERM) | `Disconnect()` | No | Process will restart; keep name for reconnect |
| `Manager.Start()` replacing old provider | `Disconnect()` | No | Provider being replaced; keep name |
| `Manager.Restart()` (settings change) | `Disconnect()` | No | Tunnel reconfiguring; keep name |
| `Manager.Stop()` (explicit release) | `Stop()` | Yes | User explicitly releasing the name |

### Mobile Reconnection

On mobile (Android/iOS), the tunnel drops when the app is backgrounded or the phone sleeps. When the app comes back to the foreground:

1. Go Core restarts (via gomobile platform channel)
2. Loads saved tunnel settings from the app's documents directory
3. Follows the reconnect-first flow — `/reconnect` succeeds because the hub kept the name reserved after the WebSocket disconnected
4. Chisel re-establishes the WebSocket tunnel
5. Agent is reachable again at the same URL

This is the primary reason the Disconnect/Release separation exists — mobile devices cycle through connect/disconnect constantly, and each cycle must not release the name.

### Cross-Device Portability

Because name ownership is tied to the agent's AID (not a device-specific token or account), the same name works across devices:

1. **Phone → Desktop migration:** The user exports their identity (AID + keys) from the phone agent and imports it into the desktop agent. The desktop agent starts up, presents the same AID to `/reconnect`, and the hub transfers the tunnel to the new device.
2. **Desktop → Phone migration:** Same process in reverse.
3. **No hub-side reconfiguration needed:** The hub doesn't care which device is connecting — it only checks the AID.

This is a key differentiator from Cloudflare and ngrok, where tunnel configuration is tied to account tokens or binary installations, not to the identity itself.

### Configuration

The Grape ID provider is configured through the Settings UI and persisted in `settings.json`:

| Setting | Description | Example |
|---|---|---|
| `tunnel_domain` | Hub domain | `grapeid.org` |
| `tunnel_extension` | User-chosen name | `alice` |
| `tunnel_auth` | Chisel auth credentials | `user:secret-token` |
| `aid` | Agent's AID (auto-populated) | `ED4zKj...` |

The resulting public URL is `https://{tunnel_domain}/{tunnel_extension}`.

### Error Handling

The provider handles several error conditions:

- **Hub unreachable:** Connection error on `/reconnect` and `/claim-name` → tunnel start fails, agent continues running on local port only.
- **Name taken (409):** Another agent already owns this name → fail with clear error message.
- **AID mismatch (403):** The name exists but belongs to a different AID → fail with clear error message.
- **SSL error (525):** Hub has SSL misconfiguration → fail with message directing user to contact hub administrator.
- **Hub returns 5xx:** Server-side error → the Go backend normalizes this into a structured response so the Flutter UI can show "provider not responsive" instead of false "name taken" errors (see ADR-007).

### Tunnel Module Structure

```
identity-agent-core/tunnel/
├── provider.go              # Provider interface (Start, Stop, Disconnect, URL, Status, Type)
├── manager.go               # Manager: provider lifecycle, config, Start/Stop/Restart/Disconnect
├── grapeid.go               # Grape ID provider: Chisel client, reconnect-first flow, AID ownership
├── cloudflare.go            # Cloudflare provider: cloudflared binary (desktop only)
├── cloudflare_embedded.go   # Cloudflare embedded: placeholder (no importable Go SDK exists)
├── ngrok.go                 # ngrok provider: in-memory via ngrok-go library
└── none.go                  # No-op provider (tunneling disabled)
```

The `Manager` sits between the server and the active provider. It handles:
- Provider creation based on config (`createProvider()`)
- Lifecycle orchestration (Start, Stop, Disconnect, Restart)
- Thread-safe access to provider status and URL
- Config changes from the settings UI (Restart with new config)

## Future Work

- **KERI signature verification:** Replace trust-on-first-use with cryptographic proof of AID ownership on every `/reconnect` and `/claim-name` request (KERI signature headers).
- **Explicit "release name" UI:** A button in the settings screen that calls `Manager.Stop()` (with release) so the user can voluntarily give up a name.
- **Tunnel status indicator:** Dashboard badge showing connected (green), disconnected (amber), error (red) so the user can see at a glance whether their agent is publicly reachable.
- **Multi-hub support:** Allow the user to register names on multiple hubs simultaneously for redundancy.
- **Hub federation:** Hubs exchanging AID ownership records so a name claimed on one hub is recognized by others.

## Related Documents

- `docs/grapeid-hub-reconnect-spec.md` — Hub-side specification for `/reconnect`, `/claim-name`, and `/release-name` endpoints
- `docs/spec-backend-migration.md` — Migration specification (includes tunnel settings portability requirements)
- `docs/adr/003-adaptive-architecture.md` — Multi-provider tunnel system overview and URL priority for OOBI generation
- `docs/adr/007-external-http-routing-and-platform-ports.md` — All external HTTP calls (including hub API) routed through Go backend proxy
