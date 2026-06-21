# ADR 012: Sandboxed App Marketplace

**Date:** 2025-07-14
**Status:** Accepted
**Amended:** 2026-03-10 — Replaced Docker Desktop with Podman as the container runtime (see §Amendment)
**Amended:** 2026-03-12 — Replaced Caddy with Go-native MITM proxy; documented agent.internal bypass pattern (see §Amendment 2)
**Amended:** 2026-03-13 — URL namespace convention established; LLM proxy moved to `/sandbox/llm/v1/`; display reverse proxy added (see §Amendment 3)

## Context

The Identity Agent currently manages user-controlled identity (KERI AIDs, contacts, OOBIs, tunneling). The next evolution is to become a **platform** — enabling users to run third-party applications inside sandboxed environments where the agent controls all network egress, enforces policy, and mediates resource access.

This is a desktop-only feature (Phase 1). Mobile platforms lack container runtimes and the process isolation primitives required for meaningful sandboxing.

The marketplace must support two fundamentally different app types: OCI containers (for web and GUI applications) and compiled binaries (for lightweight agent-native tools). Both must be network-sandboxed, policy-governed, and displayable in the Flutter UI.

Four demo apps prove the architecture works end-to-end:
1. **Chromium** — GUI app streaming via KasmVNC (OCI container)
2. **Open WebUI** — Web app proxying with credential injection (OCI container)
3. **OpenClaw** — Complex containerized TypeScript/Node.js app (OCI container)
4. **Go Demo App** — Agent API communication channel (compiled binary)

## Amendment: Docker Desktop → Podman

### Rationale

Docker Desktop requires a commercial license for organizations with >250 employees or >$10M revenue and introduces installation friction (background daemon, system tray app). Podman provides an equivalent OCI-compliant container runtime that is:

- **Free and open source** — no licensing concerns, Apache 2.0 license
- **Daemonless** — no background service on Linux; on macOS/Windows, `podman machine` manages a lightweight VM only when needed
- **Rootless by default** — better security posture than Docker's default root-mode
- **CLI-compatible** — `podman` accepts the same commands as `docker` (drop-in replacement)
- **OCI-compliant** — runs the same container images from the same registries

### What Changes

| Component | Before (Docker) | After (Podman) |
|-----------|-----------------|----------------|
| Container CLI | `docker` | `podman` |
| Daemon detection | Docker socket (`/var/run/docker.sock`, `\\.\pipe\docker_engine`) | `podman machine info` / `podman info` |
| macOS/Windows VM | Docker Desktop (hidden HyperKit/Hyper-V VM) | `podman machine` (QEMU on macOS, WSL2 on Windows) |
| Networking | Docker bridge network + `docker network create` | Podman CNI/Netavark networks + `podman network create` |
| Host access from container | `host.docker.internal` | `host.containers.internal` (Podman 4.1+) |
| Go source file | `docker_runtime.go` | `container_runtime.go` |
| Flutter setup UI | "Docker Desktop needed" | "Podman needed" with platform-specific install guide |
| Image labels | `identity-agent: "true"` | `identity-agent: "true"` (unchanged) |
| Manifest format | Unchanged (OCI images) | Unchanged (OCI images) |
| SQLite schema | Unchanged | Unchanged |

### Known Gotchas

1. **WSL2 on Windows**: Podman requires WSL2. If not enabled, the Go agent cannot silently install it — requires admin (UAC) prompt and reboot. The agent must detect this and guide the user.
2. **First-run initialization**: `podman machine init` + `podman machine start` can take several minutes on first run. The UI must show progress and explain what's happening.
3. **Rootless volume permissions**: Mounting host directories into rootless Podman containers can hit UID/GID mapping issues. The agent must handle `--userns=keep-id` or explicit UID mapping for volume mounts.
4. **Networking differences**: Podman uses Netavark (default in Podman 4+) or CNI for container networking. DNS resolution between containers and `host.containers.internal` may behave differently than Docker's `host.docker.internal`. The Go runtime must test and handle platform-specific networking.

## Amendment 2: Go-native MITM proxy + agent.internal bypass (2026-03-12)

### What changed

The original ADR proposed Caddy (with the `forwardproxy` plugin) as the MITM inspection proxy. The actual implementation uses a **Go-native MITM forward proxy** embedded directly in the Identity Agent binary (`sandbox/proxy.go`). No Caddy subprocess exists.

Additionally, a critical networking issue was identified and fixed: containers were routing requests to `agent.internal` (the Identity Agent itself) through the MITM inspection proxy. The MITM proxy runs on the host and cannot resolve `agent.internal` (which only exists inside the container), causing those requests to fail silently or be held by the policy engine.

### Fix

1. `NO_PROXY=agent.internal` and `no_proxy=agent.internal` are now injected into every container alongside `HTTP_PROXY`/`HTTPS_PROXY`.
2. A hardcoded bypass in `policy.go` auto-approves any domain matching `agent.internal` as belt-and-suspenders.
3. `agent.internal` is now listed in `allowed_domains` in every app manifest (documents intent, defensive redundancy).

### Why this is architecturally correct

Requests from a container to `agent.internal` are **already inside the Identity Agent's control layer** — the LLM proxy, the Agent API server, and the credential vault all live at that address. Routing those requests through the MITM inspection proxy would mean "proxying the proxy," which is both circular and technically impossible (the MITM proxy cannot resolve `agent.internal` from the host side).

The MITM inspection proxy's role is exclusively to police **outbound internet traffic** — traffic leaving to the public internet. Traffic directed at the Identity Agent itself is already controlled.

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

## Decision

### 1. Supported App Types (V1)

| Type | Examples | How It Runs | Display Method |
|------|---------|-------------|---------------|
| **Container (web UI)** | Open WebUI, OpenClaw | OCI container via Podman, agent reverse-proxies HTTP port | WebView in Flutter (via `flutter_inappwebview`) |
| **Container (desktop GUI)** | Chromium (kasmweb) | OCI container with built-in VNC/web streaming via Podman | WebView in Flutter |
| **Compiled binary** | Go Demo App | Binary executed by agent as child process, sandboxed via network namespace (Linux) or proxy env vars (macOS/Windows) | Native Flutter terminal widget |

### 2. Data Flow

Two separate control layers both live inside the Identity Agent process:

```
┌─────────────────────────────────────────────────────────────────┐
│                 IDENTITY AGENT (port 5050)                      │
│                                                                 │
│  ┌────────────────────┐    ┌─────────────────────────────────┐  │
│  │  LLM Proxy         │    │  MITM Inspection Proxy          │  │
│  │  /sandbox/llm/v1/* │    │  (random port per session)      │  │
│  │                    │    │                                 │  │
│  │  Receives LLM API  │    │  Intercepts all other outbound  │  │
│  │  calls directly    │    │  HTTP/HTTPS from container.     │  │
│  │  from container.   │    │  Runs policy engine, logs       │  │
│  │  Injects API keys. │    │  traffic, blocks/holds unknown  │  │
│  │  Streams response. │    │  domains, injects credentials.  │  │
│  └────────────────────┘    └─────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**Container env vars at launch:**
```
OPENAI_API_BASE_URL = http://agent.internal:5050/sandbox/llm/v1   ← direct to LLM Proxy
HTTP_PROXY          = http://<host_ip>:<random_port>       ← all other traffic
HTTPS_PROXY         = http://<host_ip>:<random_port>       ← including HTTPS
NO_PROXY            = agent.internal                       ← bypasses MITM for agent itself
no_proxy            = agent.internal                       ← (lowercase for Linux/Python)
```

```
OUTBOUND — LLM calls (Open WebUI → OpenRouter via Identity Agent):
  Container
    → GET/POST http://agent.internal:5050/sandbox/llm/v1/*
      (direct — NO_PROXY bypasses MITM inspection proxy)
    → Identity Agent LLM Proxy (/sandbox/llm/v1)
        → Looks up API key from credential vault
        → Injects Authorization: Bearer header
        → Forwards to https://openrouter.ai/api/v1/* (direct from host)
        → Streams response back to container

OUTBOUND — all other internet traffic (CDN, telemetry, etc.):
  Container
    → request via HTTP_PROXY env var
    → Identity Agent MITM Inspection Proxy (Go net/http proxy, random port)
        → Policy Engine:
            1. agent.internal → always auto-approved (belt-and-suspenders bypass)
            2. Check manifest allowed_domains → auto-approve if match
            3. Unknown domain → hold for operator (queue in SQLite)
            4. Explicitly blocked → auto-block
        → If approved: forward to internet, log response
        → Egress/Ingress Log (write to sandbox.db)
    → External Destination

  NOTE: The MITM proxy runs on the host. It cannot resolve agent.internal because
  --add-host only injects that hostname inside the container. NO_PROXY=agent.internal
  is therefore both architecturally correct (agent traffic shouldn't be double-proxied)
  and technically necessary (host-side DNS can't resolve agent.internal).

RESOURCE REQUEST (in-sandbox channel):
  Sandboxed App
    → POST http://agent.internal:{agentAPIPort}/request
        { "resources": ["camera", "filesystem:/documents", "network:newdomain.com"] }
    → Agent API Server (per-instance port, bound on host)
        → Policy Engine checks capability rules
        → Known + policy YES → auto-grant, log
        → Unknown → queue for user approval (persisted in SQLite, shown in UI)
    → Response: { "granted": [...], "denied": [...], "pending": [...] }

DISPLAY:
  Container web app (Open WebUI, OpenClaw): Container HTTP port → Flutter WebView
  Container GUI app (Chromium): Container VNC/web port → Flutter WebView
  Compiled binary (Go Demo): HTTP server on dynamic port → Flutter WebView
  Fallback (all): "Open in browser" button loads URL in system default browser
```

### 3. Proxy Architecture

**Implemented as**: A Go-native MITM forward proxy (`sandbox/proxy.go`) embedded directly in the Identity Agent binary — no separate Caddy subprocess. The original ADR proposed Caddy with the forwardproxy plugin; the Go stdlib approach was chosen instead for simplicity, zero external dependencies, and tighter integration with the policy engine.

The proxy handles both HTTP forward proxying (plain `GET http://...` requests) and HTTPS MITM (`CONNECT` tunnel + TLS interception using a per-session CA cert injected into the container).

**Why Caddy was not used**: The `forwardproxy` plugin for Caddy required a custom build, added a managed subprocess with its own lifecycle, and made policy engine integration more complex. The Go net/http + crypto/tls approach achieves the same result with less infrastructure.

#### Two TLS Inspection Modes (selectable per-app in manifest)

- **Mode A — Full MITM** (V1 default for demos): Proxy terminates TLS, agent sees full request/response content. Agent-generated CA cert injected into container via mounted NSS directory volume (preferred for kasmweb/Chromium — the `--ignore-certificate-errors-spki-list` flag may not be passable through KasmVNC's managed entrypoint). Confirm which method works against the real kasmweb/chromium image early in implementation.
- **Mode B — SNI-only** (future production default): Agent inspects TLS handshake SNI field to see destination domain, allows/blocks, forwards encrypted traffic without decrypting.

#### Traffic Coverage

- **DNS**: All container DNS resolves through agent's DNS forwarder (explicit `--dns {agent_dns_ip}` on container create — Podman's default DNS must be overridden)
- **HTTP**: Forward proxy via Caddy
- **HTTPS**: MITM (Mode A) or SNI inspection (Mode B) via Caddy
- **All other traffic**: Two-layer lockdown — Podman network rules + iptables DROP everything except proxy_port and dns_port. **Note: iptables rules only work on Linux hosts.** On macOS/Windows, Podman runs containers inside a VM (QEMU/WSL2), so host iptables don't apply. On those platforms, we rely on Podman network isolation (weaker but functional for demos).
- **SOCKS5**: Deferred to V2

#### Network Bandwidth Limits (per-app)

- `egress_kbps` and `ingress_kbps` caps in manifest
- Enforced via Podman resource controls or `tc` (Linux)
- Prevents data exfiltration, crypto mining, DDoS from sandboxed apps

#### Wildcard Domain Matching

`*.example.com` uses **single-level suffix match** (like TLS certificates). `*.google.com` matches `www.google.com` but NOT `a.b.google.com`. To match subdomains at any depth, use `**.google.com`.

### 4. Container Networking — Platform-Specific Proxy Routing

On Linux, Podman runs natively (daemonless, rootless). `HTTP_PROXY=http://localhost:{port}` works when the container shares the host's network stack or the proxy listens on the bridge gateway.

On **macOS and Windows**, Podman runs containers inside a managed VM (`podman machine`). `localhost` inside a container points to the container itself, not the host. The Go `container_runtime.go` must inject OS-aware proxy environment variables:
- **Linux**: `HTTP_PROXY=http://localhost:{proxy_port}`
- **macOS/Windows**: `HTTP_PROXY=http://host.containers.internal:{proxy_port}`

Similarly, the `agent.internal` DNS alias must resolve to the correct host IP:
- **Linux**: `--add-host agent.internal:{podman_bridge_gateway_ip}` (detected from podman0 interface, fallback 10.88.0.1)
- **macOS**: `--add-host agent.internal:host-gateway` (Podman resolves this to the host VM IP reliably on macOS)
- **Windows/WSL2**: `host-gateway` is unreliable. `container_runtime.go` dynamically detects the WSL2 gateway IP at container launch via: (1) `podman machine ssh "ip route | grep default"`, (2) scanning Windows host interfaces for the WSL vEthernet adapter, (3) fallback to 172.17.0.1.

**agent.internal must bypass the MITM inspection proxy** (`NO_PROXY=agent.internal` injected into every container). The MITM proxy runs on the host and cannot resolve `agent.internal` (which only exists inside the container via `--add-host`). Requests to `agent.internal` go directly to the Identity Agent's own endpoints — they are already inside the Identity Agent's control layer and do not need MITM inspection.

All manifests must include `"agent.internal"` in `allowed_domains` as belt-and-suspenders (in case any app ignores `NO_PROXY`, the policy engine also has a hardcoded bypass for `agent.internal` in `policy.go`).

### 5. Agent API Endpoint — Internal Service Alias

Every sandbox instance accesses the agent via `http://agent.internal` (container internal DNS alias). This decouples the port from the app — we can change ports without breaking apps, and support future services (policy, identity, vault).

Environment variable: `IDENTITY_AGENT_API=http://agent.internal`

Internally: `agent.internal` → `localhost:{dynamic_port}`

### 6. Credential Vault & Secret Injection

External API keys (OpenRouter, OpenAI, etc.) are **never stored inside sandbox containers**. They live in the Identity Agent's control layer.

**Flow:**
1. User enters API keys in the Identity Agent's settings UI (stored encrypted in `agent.db` or `settings.json`).
2. Sandboxed apps are configured to call a local proxy endpoint instead of the real API. Example: Open WebUI points to `http://agent.internal/llm/v1` instead of `https://openrouter.ai/api/v1`.
3. When the request leaves the container, the proxy/middleware layer sees it's an LLM API call, looks up the real API key from the agent's credential vault, and injects the `Authorization: Bearer` header before forwarding to the real API endpoint.
4. The response returns through the proxy to the app. The app never sees or stores the real key.

**Benefits:**
- Keys never enter the sandbox — even a compromised container can't extract them
- Keys survive container restarts (stored in agent, not ephemeral container)
- Policy engine can rate-limit, log, or block API calls
- Pattern works for any external service (OpenRouter, OpenAI, GitHub, Stripe, etc.)
- The agent becomes a credential vault that injects secrets into outbound requests

**V1 Implementation:**
- OpenRouter API key entered in Identity Agent settings, stored in `settings.json` (existing persistence layer)
- Proxy middleware matches requests to `openrouter.ai` and injects the key header
- Open WebUI configured via container environment to use `http://agent.internal:5050/sandbox/llm/v1` as its API base URL
- Future: dedicated credential management UI for multiple services

### 7. Policy Engine

The policy engine evaluates every outbound request and resource request against rules derived from the app manifest and user overrides.

**Policy evaluation order:**
1. Check explicit block rules → auto-block
2. Check explicit allow rules (manifest `allowed_domains` + user overrides) → auto-approve
3. Unknown → hold for operator (queued in `sandbox.db`, shown in Marketplace UI)

**Policy sources:**
- `manifest` — declared by the app author (initial rules)
- `user` — overrides added by the operator via the UI
- `system` — agent-enforced rules (e.g., block known malware domains)

**Policy actions logged:**
- `auto_approved` — matched an allow rule
- `auto_blocked` — matched a block rule
- `held` — queued for operator review
- `operator_approved` — operator explicitly approved
- `operator_blocked` — operator explicitly blocked

### 8. Resource Limit Escalation (V1 — Simplified)

1. App approaches limit (80% threshold) → **warn user** (notification in Marketplace UI)
2. App exceeds limit → **ask user** if they want to allocate more resources
3. No user response within configurable timeout (default 60s) → **kill** (terminate sandbox, log with full context)

Dynamic throttling (`podman update`, `nice`/`ionice`) deferred to V2 — introduces race conditions under load and cross-platform complexity.

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

### 10. Compiled Binary Isolation — Platform Reality (V1)

| Platform | Isolation Level | Method |
|----------|----------------|--------|
| **Linux** | Strong | Network namespace + iptables DROP + proxy env vars |
| **macOS** | Best-effort | Proxy env vars only (HTTP_PROXY/HTTPS_PROXY). No network namespaces. A sophisticated binary can bypass by opening raw sockets. |
| **Windows** | Best-effort | Proxy env vars only. Same limitation as macOS. |

This is an explicit, documented limitation. The Go Demo App is purpose-built to use the Agent API properly and won't bypass. OCI containers have strong isolation on all platforms. True compiled binary isolation on non-Linux requires V2 work (sandboxing frameworks like `pledge`/`unveil` on macOS, AppContainers on Windows).

**Security implication**: Because compiled binaries can potentially bypass the proxy (especially on macOS/Windows), technical sandboxing alone is insufficient to protect users from malicious compiled apps. The long-term solution is a Decentralized App Audit & Trust Registry (see §FW-1 in Future Work).

**Warning UX (V1)**: If a user sideloads a compiled binary manifest without signatures, the UI shows a prominent warning: "This app has not been audited. Compiled apps without verified signatures may bypass network controls. Install at your own risk."

### 11. SQLite Strategy

Two separate databases:
- **`data/agent.db`** — Core Identity Agent data (KERI, identity, contacts, profile, settings, policy rules). Low-volume, security-critical.
- **`data/sandbox.db`** — Sandbox operations (apps, instances, proxy logs, resource requests, policy decisions, events). High-volume, disposable.

#### sandbox.db Schema

```sql
CREATE TABLE apps (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    version TEXT,
    execution_type TEXT NOT NULL,
    display_method TEXT NOT NULL,
    network_mode TEXT DEFAULT 'proxy_required',
    manifest_json TEXT NOT NULL,
    manifest_signature TEXT,
    publisher_key TEXT,
    signature_algorithm TEXT,
    install_status TEXT DEFAULT 'available',
    container_image TEXT,
    container_image_size_bytes INTEGER,
    binary_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE instances (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL REFERENCES apps(id),
    container_id TEXT,
    process_pid INTEGER,
    status TEXT DEFAULT 'starting',
    proxy_port INTEGER,
    display_port INTEGER,
    agent_api_port INTEGER,
    network_name TEXT,
    tls_mode TEXT DEFAULT 'mitm',
    log_level TEXT DEFAULT 'metadata',
    cpu_limit REAL,
    memory_limit_mb INTEGER,
    disk_limit_mb INTEGER,
    egress_kbps INTEGER,
    ingress_kbps INTEGER,
    started_at DATETIME,
    stopped_at DATETIME
);

CREATE TABLE proxy_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL REFERENCES instances(id),
    direction TEXT NOT NULL,
    method TEXT,
    url TEXT,
    domain TEXT,
    status_code INTEGER,
    request_headers TEXT,
    request_body TEXT,
    response_headers TEXT,
    response_body TEXT,
    bytes_sent INTEGER,
    bytes_received INTEGER,
    policy_action TEXT,
    policy_rule TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_proxy_logs_instance ON proxy_logs(instance_id);
CREATE INDEX idx_proxy_logs_domain ON proxy_logs(domain);
CREATE INDEX idx_proxy_logs_timestamp ON proxy_logs(timestamp);
CREATE INDEX idx_proxy_logs_policy ON proxy_logs(policy_action);

CREATE TABLE policy_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT NOT NULL REFERENCES apps(id),
    rule_type TEXT NOT NULL,
    target TEXT NOT NULL,
    source TEXT DEFAULT 'manifest',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE resource_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL REFERENCES instances(id),
    app_id TEXT NOT NULL REFERENCES apps(id),
    resource_type TEXT NOT NULL,
    resource_target TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    resolved_by TEXT
);

CREATE TABLE policy_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT,
    app_id TEXT NOT NULL,
    decision_type TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    reason TEXT,
    decided_by TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT,
    app_id TEXT,
    event_type TEXT NOT NULL,
    event_data TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_events_instance ON events(instance_id);
CREATE INDEX idx_events_type ON events(event_type);
CREATE INDEX idx_events_timestamp ON events(timestamp);
```

### 12. Proxy Log Management

- **Per-app log level** (user configurable in UI):
  - `none` — no logging
  - `metadata` — domain, method, status code, timestamp, byte count (default)
  - `full` — metadata + headers + request/response body
- **Auto-pruning**: Default 7-day retention, 500 MB size cap per app, runs on startup + every 24 hours
- **SQLite indexes**: On `instance_id`, `domain`, `timestamp`, `policy_action` from day one to keep queries fast
- **UI filtering**: Filter by domain, status, time range. Held-for-review items always shown at top.

### 13. Container Runtime Prerequisite Check

Podman detection differs from Docker — there is no persistent daemon to ping. Instead:

**Detection flow:**
1. Find `podman` CLI executable (check `PATH`, platform-specific default locations)
2. Run `podman info --format json` to verify Podman is functional
3. On macOS/Windows: Check `podman machine info` to verify the VM is initialized and running
4. If Podman is installed but the machine is not running, offer to start it (`podman machine start`)
5. If Podman is not installed, show platform-specific install guidance

**Platform-specific install paths:**
- **Windows**: `winget install RedHat.Podman-Desktop` or download from podman-desktop.io. Requires WSL2 (may need admin + reboot).
- **macOS**: `brew install podman` or download Podman Desktop from podman-desktop.io
- **Linux**: Package manager (`apt install podman`, `dnf install podman`, etc.) — no VM needed, runs natively

**Podman Machine lifecycle (macOS/Windows only):**
- `podman machine init` — creates the VM (one-time, can take 2-5 minutes)
- `podman machine start` — starts the VM (needed each session, ~10-30 seconds)
- `podman machine stop` — stops the VM (on agent shutdown)
- The Go agent manages this lifecycle automatically, showing progress in the UI

### 14. Open WebUI LLM Provider Configuration

Open WebUI is configured to call the **Identity Agent's LLM proxy** at `http://agent.internal:5050/sandbox/llm/v1` (not OpenRouter directly). The Identity Agent then forwards to OpenRouter, injecting the user's API key from its credential vault. This means:

- Open WebUI never sees or stores the real API key
- All LLM calls are logged by the Identity Agent
- Conversations are captured to `ai-memory.db` in real time (see ADR-013)
- The user's key can be rotated without touching the container

```
Open WebUI → agent.internal:5050/sandbox/llm/v1 → Identity Agent LLM Proxy → openrouter.ai
```

The `OPENAI_API_BASE_URL` env var points Open WebUI at the Identity Agent's OpenAI-compatible endpoint. Open WebUI thinks it is talking to OpenAI; the Identity Agent proxies to OpenRouter.

The model list (`GET /sandbox/llm/v1/models`) is served from a static catalog in `llm_handlers.go` — no upstream call needed to populate the dropdown.

**URL Namespace:** `/sandbox/llm/v1/` is in the `/sandbox/` namespace, which contains all paths called by containers toward the Identity Agent. See ADR-013 §Decision 3 for the full namespace convention.

Users can reconfigure Open WebUI to use other providers (OpenAI, local Ollama, etc.) — the MITM proxy will hold any new outbound domains for approval.

### 15. Desktop-Only Exclusion

- **Go backend**: Sandbox package uses build tag `//go:build !mobile` so gomobile excludes it
- **Flutter UI**: Marketplace tab gated behind `Platform.isWindows || Platform.isMacOS || Platform.isLinux`
- **Codemagic**: Desktop workflows install Podman dependencies; mobile workflows skip entirely

### 16. Clean Shutdown Checklist

1. Container stopped and removed (`podman stop`, `podman rm`)
2. Custom Podman network deleted (`podman network rm`)
3. Caddy proxy routes for this app removed
4. Agent API endpoint for this app stopped
5. SQLite instance status updated to `stopped`
6. Port bindings released
7. Temporary files (CA certs, NSS volume, config) cleaned up
8. Resource monitor stopped
9. WebSocket connections to Flutter UI closed
10. Event logged: `container_stopped`

### 17. Crash Recovery State Matrix (Startup Reconciliation)

| Container State | sandbox.db Instance | Action |
|-----------------|---------------------|--------|
| Running | Missing | Register instance in DB, attempt graceful stop |
| Stopped | Running | Mark instance stopped in DB, clean up network/ports |
| Running | Stopped | Kill container, clean up network/ports |
| Missing | Running | Mark instance stopped in DB |

**Orphan Caddy process recovery**: On agent crash/force-kill, the Caddy subprocess can become orphaned and hold proxy/DNS ports. On startup:
1. Check `.caddy.pid` lockfile for previous Caddy PID
2. If PID is still running, terminate it
3. If no lockfile but proxy port is in use, find and kill the process holding it
4. Write new Caddy PID to lockfile on successful launch

All containers managed by the agent are labeled with `identity-agent=true` for discovery via `podman ps --filter label=identity-agent=true`.

## Consequences

### Positive

- **Platform evolution**: The Identity Agent becomes a platform, not just an identity manager. Apps run in controlled environments with full network visibility.
- **Strong container isolation**: Containers are network-sandboxed on all platforms via proxy env vars + Podman network rules. Linux adds iptables for defense-in-depth.
- **No licensing concerns**: Podman is Apache 2.0 licensed — no commercial restrictions unlike Docker Desktop.
- **Rootless by default**: Podman's rootless mode provides better security posture than Docker's default root-mode operation.
- **Credential safety**: API keys never enter sandbox containers. The proxy-injection pattern means even a compromised container cannot exfiltrate secrets.
- **Operator control**: Every outbound request is logged, filterable, and reviewable. Unknown domains are held for explicit approval.
- **Extensible manifest format**: Signature fields are reserved for future audit registry integration without schema changes.
- **Reuses proven patterns**: Caddy as managed subprocess follows the same lifecycle pattern as the KERI Python driver (ADR 002).

### Negative

- **Podman Machine lifecycle**: macOS/Windows require `podman machine init/start`, adding first-run latency (2-5 minutes). The Go agent must manage this transparently.
- **WSL2 requirement on Windows**: Podman on Windows needs WSL2. Users without it face admin prompts and a reboot. Cannot be silently installed.
- **Rootless volume permission quirks**: UID/GID mapping between host and rootless containers requires careful handling (`--userns=keep-id` or explicit mappings).
- **Networking differences**: Podman's Netavark networking behaves differently from Docker's bridge networking. DNS, host access, and port forwarding need platform-specific testing.
- **Compiled binary isolation gap**: macOS/Windows cannot strongly isolate compiled binaries at the network level in V1. Mitigation: audit registry (§FW-1) and prominent UI warnings.
- **Caddy complexity**: Custom Caddy builds with the forwardproxy plugin add build pipeline complexity. Fallback to `goproxy` or Go stdlib is available.
- **Resource overhead**: Running OCI containers + Caddy proxy + resource monitors increases the agent's footprint significantly.
- **Desktop-only V1**: Mobile users cannot access the marketplace, creating a feature gap between platforms.

### Risks

- **Caddy forwardproxy compatibility**: The plugin may not support all required MITM scenarios. Evaluated early via technical spike; fallback to `goproxy` documented.
- **KasmVNC CA cert injection**: The method for injecting the MITM CA cert into kasmweb/chromium containers needs validation against the actual image. NSS volume mount is preferred over command-line flags.
- **Podman version fragmentation**: Different Linux distros ship different Podman versions. The agent should require Podman 4.0+ (Netavark default, `host.containers.internal` support).
- **Podman Machine stability**: `podman machine` on macOS (QEMU) and Windows (WSL2) is less battle-tested than Docker Desktop. May encounter edge cases with VM networking.

## Future Work

### §FW-1: Decentralized App Audit & Trust Registry

This is the primary mitigation for the compiled binary isolation gap on macOS/Windows.

**The Problem**: Unlike OCI containers (which have kernel-level isolation), compiled binaries run as native processes and can bypass proxy-based network controls, especially on macOS and Windows. No amount of runtime sandboxing can fully prevent a malicious compiled binary from exfiltrating data or causing harm on these platforms.

**The Solution**: A decentralized code audit and verification system that ensures only verified, audited binaries are available to users through the discoverable app registry.

**Key Design Principles** (aligned with KERI and user-controlled-identity philosophy):
1. **No centralized gatekeeper** — the audit system must not depend on a single entity. A centralized app store would contradict the user-controlled identity model.
2. **Multiple independent auditors** — a set of recognized audit firms/organizations that can independently review and cryptographically sign off on application code and binaries.
3. **User-chosen trust anchors** — each agent operator chooses which auditors they trust (similar to how users choose which certificate authorities to trust, but without a mandatory root).
4. **Cryptographic verification** — the manifest signature fields (`signature`, `publisher_key`, `signature_algorithm`) already in the V1 schema become the foundation. Agents verify signatures before installation.
5. **Reproducible builds** — audited apps must use reproducible/deterministic build pipelines so that the audited source code provably produces the distributed binary.

**Components to Build:**
- **Audit Application Process**: Developers submit source code + build instructions to one or more audit firms. Auditors review for: data exfiltration, unauthorized network access, resource abuse, privacy violations, malware.
- **Auditor Registry**: A decentralized registry of recognized audit organizations, each identified by their own AID (Autonomic Identifier) via KERI. Auditors sign manifests with their AID keys.
- **App Registry / Discovery**: A decentralized, discoverable registry where agents can find available apps. Each app listing includes: manifest, auditor signatures, audit report hash, build reproducibility proof.
- **Trust Policy Engine**: User-configurable trust rules: "I trust apps signed by Auditor A and Auditor B", "I require at least 2 auditor signatures", "I trust apps from Publisher X if signed by any recognized auditor".
- **Revocation**: If an auditor discovers a vulnerability post-audit, they can revoke their signature. Agents that trust that auditor receive the revocation and can warn/disable the app.
- **KERI Integration**: Auditor AIDs, publisher AIDs, and signature chains all use KERI infrastructure — the same trust model used for identity throughout the platform.

### §FW-2: Firecracker Micro-VMs for Headless Workloads

Firecracker micro-VMs provide lightweight, hardware-virtualized isolation for headless (non-GUI) workloads. Faster startup than full VMs (~125ms), strong isolation boundary, minimal resource overhead. Suitable for batch processing, API services, and compute tasks that don't need display.

### §FW-3: QEMU for True VM Isolation

Full QEMU virtual machines for workloads requiring complete OS-level isolation beyond container boundaries. Heavier than Firecracker but supports arbitrary guest OSes, GPU passthrough, and full hardware emulation. Suitable for running untrusted desktop applications or legacy software.

### §FW-4: SOCKS5 Proxy for Non-HTTP TCP Traffic

V1 only proxies HTTP/HTTPS traffic. SOCKS5 proxy support would intercept arbitrary TCP connections (database protocols, custom binary protocols, SSH, etc.). Required for apps that communicate over non-HTTP protocols.

### §FW-5: Device Passthrough (Camera, Mic, GPU)

Selective hardware device passthrough from host to sandbox. Requires per-device permission grants in the policy engine. GPU passthrough enables ML inference workloads. Camera/mic passthrough enables video conferencing apps. Each device type needs platform-specific implementation (Linux: device nodes, macOS: IOKit, Windows: device manager).

### §FW-6: Dynamic Resource Throttling

Replace the V1 warn-ask-kill escalation with dynamic throttling using `podman update` for CPU/memory limits and `nice`/`ionice` for compiled binaries. Allows graceful degradation instead of hard kills. Deferred due to race conditions under load and cross-platform complexity.

### §FW-7: App-to-App Communication Channels

Controlled inter-app messaging via the agent as mediator. Apps register communication capabilities in their manifests. The agent enforces which apps can talk to each other and what data types are allowed. Enables composable app workflows (e.g., data pipeline: Collector → Processor → Visualizer).

### §FW-8: Automatic Manifest Generation from Container Image Inspection

Inspect OCI image metadata (exposed ports, environment variables, volumes, labels) to auto-generate a manifest skeleton. Reduces friction for adding new apps. The auto-generated manifest still requires human review for network permissions and resource limits.

### §FW-9: App Update/Versioning Management

Manifest versioning with update channels (stable, beta). Automatic update checks against the app registry. Delta updates for OCI images (only pull changed layers). Rollback support with instance snapshot/restore.

### §FW-10: Manifest Signature Verification Implementation

The V1 schema includes `signature`, `publisher_key`, and `signature_algorithm` fields (all `null`). This future work implements the actual verification logic: Ed25519 signature validation, publisher key trust chain verification via KERI, rejection of unsigned manifests in strict mode.

### §FW-11: Mode B (SNI-only) as Production Default

V1 defaults to Mode A (Full MITM) for demos. Production deployments should default to Mode B (SNI-only inspection) which provides domain-level visibility without decrypting traffic content. Less invasive, no CA cert injection required, but cannot inspect request/response bodies for content policy.

### §FW-12: Compiled Binary Strong Isolation on macOS/Windows

Platform-specific sandboxing for compiled binaries:
- **macOS**: `pledge`/`unveil` (OpenBSD-style, via `sandbox-exec` or App Sandbox entitlements)
- **Windows**: AppContainers (Windows 10+), or Job Objects with network restrictions

These provide OS-level enforcement that compiled binaries cannot bypass, closing the isolation gap documented in §10 of this ADR.

### §FW-13: Background Container Image Prefetching

Pre-download OCI images in the background when the user browses the marketplace, before they click "Install". Provides instant-feeling installs for common images. Respects bandwidth limits and can be paused/cancelled. Shows estimated download time based on image size and connection speed.

### §FW-14: Custom Resource Types Beyond network/filesystem/device/service

V1 supports four resource types in the resource request channel. Future work extends this to arbitrary custom types defined in manifests (e.g., `identity:sign`, `credential:issue`, `payment:authorize`). Each custom type needs a handler registered with the policy engine.

## Key Files

- `docs/adr/012-sandboxed-app-marketplace.md` — This document
- `identity-agent-core/sandbox/store.go` — SQLite access layer for sandbox.db
- `identity-agent-core/sandbox/manifest.go` — Manifest parsing and validation
- `identity-agent-core/sandbox/runtime.go` — Runtime interface and container engine detection
- `identity-agent-core/sandbox/container_runtime.go` — OCI container lifecycle (Podman)
- `identity-agent-core/sandbox/binary_runtime.go` — Compiled binary lifecycle
- `identity-agent-core/sandbox/resource_monitor.go` — Resource usage monitoring
- `identity-agent-core/sandbox/credentials.go` — Credential vault and injection
- `identity-agent-core/server/sandbox_handlers.go` — API handlers
- `manifests/chromium.json` — Chromium demo manifest
- `manifests/openclaw.json` — OpenClaw demo manifest
- `manifests/openwebui.json` — Open WebUI demo manifest
- `manifests/go-demo.json` — Go Demo App manifest

## References

- [ADR 001](001-core-architecture-stack.md) — Core architecture (Go backend, Flutter frontend)
- [ADR 002](002-keri-driver-pattern.md) — Python KERI driver managed subprocess pattern (reused for Caddy)
- [ADR 003](003-adaptive-architecture.md) — Adaptive architecture and operating modes
