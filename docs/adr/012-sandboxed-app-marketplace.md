# ADR 012: Sandboxed App Registry (Plugins)

**Date:** 2025-07-14
**Status:** Accepted
**Amended:** 2026-03-10 — Replaced Docker Desktop with Podman as the container runtime (a runtime decision, removed here 2026-10-30)
**Amended:** 2026-03-12 — Replaced Caddy with Go-native MITM proxy; documented agent.internal bypass pattern (a runtime decision, removed here 2026-10-30)
**Amended:** 2026-03-13 — URL namespace convention established; LLM proxy moved to `/sandbox/llm/v1/`; display reverse proxy added (see §Amendment 3)
**Amended:** 2026-10-24 — The display proxy no longer forwards capability calls or the caller's credentials, and serves the owner's conversations only to the owner; a forwarded capability call tells the app who called (see §Amendment 4)
**Amended:** 2026-10-30 — The runtime that installs and runs apps is an add-on kept outside this repository; this record now keeps only the contract an app is written against (see §Note, 2026-10-30)


## Note, 2026-10-30: this repository keeps the contract, not the runtime

The runtime this record designed — the container and binary runtimes, the egress proxy, the policy engine, the credential injection, the resource monitor, the store behind it and its recovery rules — is an add-on. An app built on the core includes it or not, and it is kept outside this repository by whoever makes it. Those parts of this record, and the first two amendments, which were about the runtime alone, are removed here.

What stays is what an app's maker relies on, whichever runtime installs the app:

- **The manifest** (§9) and the rules it is checked against: package `appmanifest`. A manifest that passes `appmanifest.Validate` is one a runtime accepts.
- **How an app is called and told who called** (Amendment 4): package `appcall`.
- **How a caller's grant limits a capability's arguments**: `permission.CheckResourceConstraints`.
- **The URL namespaces an app sees** (Amendment 3) and the internal service alias (§5).

## Context

The Identity Agent currently manages user-controlled identity (KERI AIDs, contacts, OOBIs, tunneling). It is a self-hosted identity agent server with a sandbox container system that allows sandbox plugins to run on it — enabling users to run third-party sandbox plugins inside sandboxed environments where the agent controls all network egress, enforces policy, and mediates resource access. The discovery surface for plugins is the App Registry (not a marketplace; separate from any paid marketplace milestone).

This is a desktop-only feature (Phase 1). Mobile platforms lack container runtimes and the process isolation primitives required for meaningful sandboxing.

The App Registry (sandbox plugin discovery surface) must support two fundamentally different plugin types: OCI containers (for web and GUI applications) and compiled binaries (for lightweight agent-native tools). Both must be network-sandboxed, policy-governed, and displayable in the Flutter UI. "sandbox plugin" terminology is used for the software adhering to the manifest; "sandbox" refers to the container runtime offered by the agent.

Four demo apps prove the architecture works end-to-end:
1. **Chromium** — GUI app streaming via KasmVNC (OCI container)
2. **Open WebUI** — Web app proxying with credential injection (OCI container)
3. **OpenClaw** — Complex containerized TypeScript/Node.js app (OCI container)
4. **Go Demo App** — Agent API communication channel (compiled binary)


## Amendment 3: URL Namespace Convention + Display Reverse Proxy (2026-03-13)

### What changed

Two related changes were made to establish a consistent URL organization and correct the data flow for sandboxed chat apps. See ADR-013 for full details.

**Change 1 — URL namespace convention:**

The Identity Agent's HTTP server now uses four path namespaces organized by caller identity:

| Namespace | Caller | Examples |
|-----------|--------|---------|
| `/api/` | Flutter UI (local) | `/api/contacts`, `/api/ai/conversations`, `/api/trace/*` |
| `/sandbox/` | Sandboxed containers | `/sandbox/llm/v1/*` |
| `/public/` | External KERI agents | `/public/oobi/{aid}` |
| `/apps/` | Flutter WebView (display proxy) | `/apps/{app_id}/*` |

The LLM proxy moved from `/llm/v1/*` to `/sandbox/llm/v1/*`. The OOBI endpoint moved from `/oobi/{aid}` to `/public/oobi/{aid}` (with a 301 redirect from the old path for backward compatibility). All container manifests must update `OPENAI_API_BASE_URL` accordingly.

**Change 2 — Display reverse proxy:**

Container web UIs previously loaded their display port URL directly in the Flutter WebView. The Identity Agent now serves as a reverse proxy for container display traffic:

```
Before: Flutter WebView → http://127.0.0.1:{container_port}/
After:  Flutter WebView → http://127.0.0.1:5050/apps/{app_id}/
                                    ↓
                        Identity Agent display proxy
                           ↓                    ↓
                    Intercept              Forward everything
                /api/v1/chats           else to container port
                    ↓
              Serve from ai-memory.db
```

This makes container data fully ephemeral. The container's own database is empty. Conversations are captured by the LLM proxy and served back via the display proxy — the container never needs to store any user data.

---

## Amendment 4: The display proxy is not a way to a capability or to the owner's conversations, and an app is told who called (2026-10-24)

The "forward everything else" in Amendment 3 no longer holds in full.

- **The display proxy never forwards a capability call.** An app serves its capability API (`POST /v1/capability/{id}`) on the same port as its display, and `/apps/{app_id}/*` admits any caller holding any scope. A path that cleans to `/v1/capability` or below is refused. Capability calls go through `POST /api/capabilities/{id}/invoke`, which checks the caller's scope and records the call. The path forwarded is the cleaned path the proxy checked, never the raw one.
- **It forwards no credential of the Identity Agent's.** Every `X-IA-*` header, the local owner secret, and an `Authorization` header holding an Identity Agent token or browser session are removed. An `Authorization` header that is the app's own login is passed on.
- **A forwarded capability call says who called.** The Identity Agent adds the caller it admitted — owner or AI agent, its identifier, the machine it spoke from, how it proved itself, its grant, and its session — as `X-IA-Call-*` headers, with an HMAC-SHA256 over the capability, a digest of the body, those fields, the time and a nonce, under a key the Identity Agent keeps for that app alone. A launched app finds its key in `IDENTITY_AGENT_CALL_KEY`, which a manifest cannot set. The app refuses a call without a valid, fresh, unseen MAC. The canonical string and a Go verifier are in `identity-agent-core/appcall`.
- **One provider per capability.** Two apps declaring one capability id, two manifests claiming one app id, or an app declaring a capability the registry already provides, are refused at load, and an ambiguous capability is refused at invocation rather than routed to whichever is found first.
- **The intercepted conversation reads follow the conversation read rule.** `GET /apps/{app_id}/api/v1/chats` and the reads below it serve the owner's AI conversations from ai-memory.db, so they are served only to the owner or a machine acting for them. A caller admitted to `/apps/` only for holding some scope is refused them.
- **A container's ports are published on loopback only.**

---

## Decision

### 1. Supported App Types (V1)

| Type | Examples | How It Runs | Display Method |
|------|---------|-------------|---------------|
| **Container (web UI)** | Open WebUI, OpenClaw | OCI container via Podman, agent reverse-proxies HTTP port | WebView in Flutter (via `flutter_inappwebview`) |
| **Container (desktop GUI)** | Chromium (kasmweb) | OCI container with built-in VNC/web streaming via Podman | WebView in Flutter |
| **Compiled binary** | Go Demo App | Binary executed by agent as child process, sandboxed via network namespace (Linux) or proxy env vars (macOS/Windows) | Native Flutter terminal widget |


### 2. What an app can rely on about its network

An app's traffic leaves only as its manifest says: `network_mode` chooses whether it must go through the Identity Agent's egress proxy, may, has no network, or reaches only `agent.internal`. With `tls_mode` `mitm` the proxy terminates TLS with a certificate authority the runtime gives the app; with `sni_only` it sees only the destination's name. `allowed_domains` and `blocked_domains` take `*.` wildcards. An app never holds an API key the owner keeps: where a call needs one, the proxy adds it on the way out.

### 5. Agent API Endpoint — Internal Service Alias

Every sandbox instance accesses the agent via `http://agent.internal` (container internal DNS alias). This decouples the port from the app — we can change ports without breaking apps, and support future services (policy, identity, vault).

Environment variable: `IDENTITY_AGENT_API=http://agent.internal`

Internally: `agent.internal` → `localhost:{dynamic_port}`


### 9. App Manifest Format

```json
{
  "id": "chromium",
  "name": "Chromium Browser",
  "description": "Sandboxed web browser",
  "version": "1.0.0",
  "author": "KasmTech",
  "execution_type": "container",
  "display_method": "webview",
  "network_mode": "proxy_required",
  "container": {
    "image": "kasmweb/chromium:latest",
    "ports": { "6901": "display" },
    "environment": {},
    "volumes": {}
  },
  "resources": {
    "cpu_cores": 2,
    "memory_mb": 4096,
    "disk_mb": 5120,
    "egress_kbps": 10240,
    "ingress_kbps": 10240
  },
  "network": {
    "tls_mode": "mitm",
    "allowed_domains": [
      "*.google.com", "*.googleapis.com", "*.gstatic.com",
      "*.nasa.gov"
    ],
    "blocked_domains": []
  },
  "capabilities": {
    "allowed": ["network"],
    "blocked": ["camera", "microphone", "filesystem"]
  },
  "log_level": "metadata",
  "signature": null,
  "publisher_key": null,
  "signature_algorithm": null
}
```

**Manifest fields:**
- `id` — unique app identifier
- `name`, `description`, `version`, `author` — metadata
- `execution_type` — `"container"` or `"compiled"` (formerly `"docker"` or `"compiled"`)
- `display_method` — `"webview"` or `"terminal"`
- `network_mode` — `"proxy_required"` (all traffic through proxy), `"proxy_optional"` (proxy available but not enforced), `"isolated"` (no network), `"local_only"` (only agent.internal)
- `container` — OCI container config (image, ports, environment, volumes). Formerly `docker` key.
- `binary` — compiled binary config (path, args, platform-specific paths)
- `resources` — CPU, memory, disk, bandwidth limits
- `network` — TLS mode, allowed/blocked domain lists
- `capabilities` — allowed/blocked device capabilities
- `log_level` — default logging level (`"none"`, `"metadata"`, `"full"`)
- `signature`, `publisher_key`, `signature_algorithm` — cryptographic verification (unused in V1, reserved for future audit registry)


The manifest has since gained the plug-in fields (`kind`, `sub_type`, `provides`, `host_control`, `supported_platforms`, `isolation`); `appmanifest.AppManifest` documents each, and `appmanifest.Validate` is the rule for all of them.


### 15. Desktop-Only

Sandboxed apps run on desktop computers. The phone core includes no add-on, so no phone runs them.

## Key Files

- `identity-agent-core/appmanifest/` — the manifest and its rules
- `identity-agent-core/appcall/` — how an app is called and checks who called
- `identity-agent-core/permission/resource_constraints.go` — how a grant limits a capability's arguments
- `manifests/` — example manifests: Chromium, OpenClaw, Open WebUI, the Go demo app
- `sandbox-apps/go-demo/` — an example compiled app

## References

- [ADR 001](001-core-architecture-stack.md) — Core architecture (Go backend, Flutter frontend)
- [ADR 003](003-adaptive-architecture.md) — Adaptive architecture and operating modes
- [ADR 013](013-container-data-architecture-and-api-namespacing.md) — URL namespaces by caller
