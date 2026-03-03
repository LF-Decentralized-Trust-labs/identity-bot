# ADR 008: Tunnel Lifecycle — Disconnect vs Release

**Date:** 2026-03-03
**Status:** Accepted
**Relates to:** ADR-001 (Core Architecture), ADR-003 (Adaptive Architecture), `docs/grapeid-hub-reconnect-spec.md`

## The Problem This Solved

The Grape ID tunnel provider was doing release → claim cycles on every restart instead of using the hub's `/reconnect` endpoint. This created unnecessary churn on the hub and wasted time re-registering names that the agent already owned.

### What Was Happening

The `Provider` interface had a single shutdown method: `Stop()`. For the Grape ID provider, `Stop()` always called `POST /release-name` on the hub before closing the Chisel connection. Every path that shut down the tunnel — process SIGTERM, workflow restart, settings changes — triggered a full release.

On the next startup, the agent's reconnect-first flow would try `POST /reconnect`, but the hub returned 404 ("name not found") because the name had just been released. The agent then fell back to `POST /claim-name` to re-register.

The hub operator observed this pattern:

```
16:22:28 — Released identity-agent-test-031, re-claimed 2 seconds later
16:26:17 — Released again, re-claimed 3 seconds later
16:28:42 — Released again, re-claimed 2 seconds later
```

### Why It Matters

- **Unnecessary hub load:** Every restart generates two HTTP requests (release + claim) instead of one (reconnect).
- **Race condition window:** Between release and re-claim, the name is available for anyone to take. On a busy hub, another agent could claim it.
- **Port churn:** Each new claim may allocate a different port on the hub, while reconnect can reuse the existing allocation.
- **Mobile reliability:** On mobile, the tunnel drops frequently (app backgrounded, phone sleeps). Each resume was doing a full release → claim instead of a quick reconnect.

## The Decision

Split the `Provider` interface into two shutdown methods:

| Method | Behavior | When Used |
|---|---|---|
| `Disconnect()` | Closes the tunnel connection (Chisel WebSocket). Does NOT release the name on the hub. The hub keeps the name reserved for reconnect. | All restart paths: SIGTERM, workflow restart, settings changes, mobile app resume. |
| `Stop()` | Calls `/release-name` on the hub, then calls `Disconnect()`. The name becomes available for anyone to claim. | Future explicit "release name" UI button. Not currently called in any active code path. |

### Why Not Just Remove the Release?

We want to preserve the ability to explicitly release a name. Use cases:

- The user abandons a name and wants to free it for others.
- The user migrates to a different hub and wants to clean up the old one.
- Testing and development where names need to be recycled.

By keeping `Stop()` with release semantics, we have a clean path for these future scenarios without needing to add the release logic back later.

## Implementation

### Provider Interface (`tunnel/provider.go`)

```go
type Provider interface {
    Start(ctx context.Context, localPort int) error
    Stop() error
    Disconnect() error
    URL() string
    Listener() net.Listener
    Status() Status
    Type() ProviderType
}
```

### GrapeID Provider (`tunnel/grapeid.go`)

The only provider where `Disconnect()` differs from `Stop()`:

```go
func (p *GrapeIDProvider) Disconnect() error {
    // Close Chisel client — do NOT release name
    // Hub keeps the name reserved for /reconnect
}

func (p *GrapeIDProvider) Stop() error {
    p.tryReleaseName()   // POST /release-name
    return p.Disconnect()
}
```

### Other Providers

Cloudflare, ngrok, and the none provider don't have name reservation concepts. Their `Disconnect()` simply delegates to `Stop()`:

```go
func (p *NgrokProvider) Disconnect() error {
    return p.Stop()
}
```

### Manager (`tunnel/manager.go`)

The manager exposes both methods and routes them to the active provider:

- `Manager.Start()` — calls `Disconnect()` on any existing provider before creating a new one.
- `Manager.Restart()` — calls `Disconnect()` on the current provider, updates config, then calls `Start()`.
- `Manager.Stop()` — calls `Stop()` on the provider (with release). Reserved for explicit release.
- `Manager.Disconnect()` — calls `Disconnect()` on the provider (no release). Used by server shutdown.

### Server Shutdown (`server/server.go`)

```go
func (s *CoreServer) Stop() {
    if s.TunnelManager != nil {
        s.TunnelManager.Disconnect()  // NOT Stop() — keep name reserved
    }
    // ... close listener, stop KERI driver, close store
}
```

## Call Site Summary

| Call Site | Method | Releases Name? | Reason |
|---|---|---|---|
| `CoreServer.Stop()` (SIGTERM) | `Disconnect()` | No | Process will restart; keep name for reconnect |
| `Manager.Start()` replacing old provider | `Disconnect()` | No | Provider being replaced; keep name |
| `Manager.Restart()` (settings change) | `Disconnect()` | No | Tunnel reconfiguring; keep name |
| `Manager.Stop()` (explicit release) | `Stop()` | Yes | User explicitly releasing the name |

## Startup Flow (Unchanged)

The reconnect-first startup flow from `grapeid-hub-reconnect-spec.md` remains the same:

```
1. Try POST /reconnect {"name": "<extension>", "aid": "<AID>"}
   → 200? Connect Chisel tunnel. Done.
   → 404? Go to step 2.
   → 403? Fail — name owned by different AID.

2. Try POST /claim-name {"name": "<extension>", "aid": "<AID>"}
   → 200? Connect Chisel tunnel. Done.
   → 409? Fail — name taken by another agent.
```

## Result

After this change, the agent logs on restart show:

```
[tunnel] GrapeID reconnected to existing name 'identity-agent-test-031'
```

Instead of the previous:

```
[tunnel] GrapeID reconnect failed, trying claim: name '...' not found
[tunnel] GrapeID claimed new name '...'
```

The hub sees a single `/reconnect` request instead of a `/release-name` + `/claim-name` pair.

## Files Changed

- `identity-agent-core/tunnel/provider.go` — Added `Disconnect()` to interface
- `identity-agent-core/tunnel/grapeid.go` — Implemented `Disconnect()` (no release) and refactored `Stop()` to call release then `Disconnect()`
- `identity-agent-core/tunnel/manager.go` — Added `Manager.Disconnect()`, changed `Start()` and `Restart()` to use `Disconnect()`
- `identity-agent-core/tunnel/cloudflare.go` — `Disconnect()` delegates to `Stop()`
- `identity-agent-core/tunnel/cloudflare_embedded.go` — `Disconnect()` delegates to `Stop()`
- `identity-agent-core/tunnel/ngrok.go` — `Disconnect()` delegates to `Stop()`
- `identity-agent-core/tunnel/none.go` — `Disconnect()` delegates to `Stop()`
- `identity-agent-core/server/server.go` — `CoreServer.Stop()` calls `TunnelManager.Disconnect()` instead of `TunnelManager.Stop()`
