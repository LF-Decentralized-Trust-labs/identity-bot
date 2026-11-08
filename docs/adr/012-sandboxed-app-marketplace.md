# ADR 012: Sandboxed App Registry (Plugins)

**Date:** 2025-07-14
**Status:** Accepted
**Amended:** 2026-03-10 — Replaced Docker Desktop with Podman as the container runtime (a runtime decision, removed here 2026-10-30)
**Amended:** 2026-03-12 — Replaced Caddy with Go-native MITM proxy; documented agent.internal bypass pattern (a runtime decision, removed here 2026-10-30)
**Amended:** 2026-03-13 — URL namespace convention established; LLM proxy moved to `/sandbox/llm/v1/`; display reverse proxy added (see §Amendment 3)
**Amended:** 2026-10-24 — The display proxy no longer forwards capability calls or the caller's credentials, and serves the owner's conversations only to the owner; a forwarded capability call tells the app who called (see §Amendment 4)
**Amended:** 2026-10-30 — The runtime that installs and runs apps is an add-on kept outside this repository; this record now keeps only the contract an app is written against (see §Note, 2026-10-30)
**Amended:** 2026-11-02 — `kind` `"app"` now means an app beside an Identity Agent, which declares its name, release, resources, encrypted machine, store, placement, front end and back end, secrets, behaviour when down, backup and outbound hosts; a manifest missing a row or breaking its rule is refused (see §Amendment 5)


## Note, 2026-10-30: this repository keeps the contract, not the runtime

The runtime this record designed — the container and binary runtimes, the egress proxy, the policy engine, the credential injection, the resource monitor, the store behind it and its recovery rules — is an add-on. An app built on the core includes it or not, and it is kept outside this repository by whoever makes it. Those parts of this record, and the first two amendments, which were about the runtime alone, are removed here.

What stays is what an app's maker relies on, whichever runtime installs the app:

- **The manifest** (§9) and the rules it is checked against: package `appmanifest`. A manifest that passes `appmanifest.Validate` is one a runtime accepts.
- **How an app is called and told who called** (Amendment 4): package `appcall`.
- **How a caller's grant limits a capability's arguments**: `permission.CheckResourceConstraints`.
- **The URL namespaces an app sees** (Amendment 3) and the internal service alias (§5).

## Context

An Identity Agent may let its owner run third-party apps beside it, each confined to what its manifest declares. The discovery surface for them is the App Registry (not a marketplace). An app is either an OCI container (a web or GUI application) or a compiled binary (a small tool), and its maker writes one manifest that any runtime for sandboxed apps reads the same way. "Sandbox plugin" names the software a manifest describes.

The example manifests in `manifests/` cover the kinds of app: Chromium (a GUI app streamed to a web view), Open WebUI (a web chat app that makes model calls), OpenClaw (a larger container app), and the Go demo app (a compiled binary, `sandbox-apps/go-demo/`).


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

An app's web display is loaded through the Identity Agent at `/apps/{app_id}/`, not from its own port. A chat app's conversation reads below `/api/v1/chats` are answered from the owner's AI conversations, and everything else reaches the app. So an app keeps no user data of its own that matters: deleting and reinstalling it loses nothing.

---

## Amendment 4: The display proxy is not a way to a capability or to the owner's conversations, and an app is told who called (2026-10-24)

The "forward everything else" in Amendment 3 no longer holds in full.

- **The display proxy never forwards a capability call.** An app serves its capability API (`POST /v1/capability/{id}`) on the same port as its display, and `/apps/{app_id}/*` admits any caller holding any scope. A path that cleans to `/v1/capability` or below is refused. Capability calls go through `POST /api/capabilities/{id}/invoke`, which checks the caller's scope and records the call. The path forwarded is the cleaned path the proxy checked, never the raw one.
- **It forwards no credential of the Identity Agent's.** Every `X-IA-*` header, the local owner secret, and an `Authorization` header holding an Identity Agent token are removed. An `Authorization` header that is the app's own login is passed on.
- **A forwarded capability call says who called.** The Identity Agent adds the caller it admitted — owner or AI agent, its identifier, the machine it spoke from, how it proved itself, its grant, and its session — as `X-IA-Call-*` headers, with an HMAC-SHA256 over the capability, a digest of the body, those fields, the time and a nonce, under a key the Identity Agent keeps for that app alone. A launched app finds its key in `IDENTITY_AGENT_CALL_KEY`, which a manifest cannot set. The app refuses a call without a valid, fresh, unseen MAC. The canonical string and a Go verifier are in `identity-agent-core/appcall`.
- **One provider per capability.** Two apps declaring one capability id, two manifests claiming one app id, or an app declaring a capability the registry already provides, are refused at load, and an ambiguous capability is refused at invocation rather than routed to whichever is found first.
- **The intercepted conversation reads follow the conversation read rule.** `GET /apps/{app_id}/api/v1/chats` and the reads below it serve the owner's AI conversations from the owner's AI conversations, so they are served only to the owner or a machine acting for them. A caller admitted to `/apps/` only for holding some scope is refused them.

---

## Amendment 5 (2026-11-02): the rows an app beside an Identity Agent declares

*Amended 2026-11-02. Only what this amendment names is changed.*

**What changes.** The manifest `kind` `"app"` was already accepted by `appmanifest.Validate` and meant a sandboxed plug-in. It now means **an app beside an Identity Agent**: an app that runs on a machine of its own (or a shared one), never inside the Identity Agent, with its own encrypted store, and that the Identity Agent calls and serves. No manifest in this project used the old meaning (the four example manifests in `manifests/` carry no `kind`, and nothing else in the repository sets it), so nothing is migrated. The older rows below do not apply to an app on its own machine, and a runtime ignores them for one: the **webview display** (`display_method` stays a required field of the shared manifest format, but for an app it means nothing, since `front_and_back_end` says what the app serves), the **`agent.internal` name** for reaching the Identity Agent (§5), **`{APP_DATA}`** as the place an app keeps data (an app's data is its `store`, and an app's `container.volumes` are not host paths: the one volume an app may declare is `store`, its own encrypted store, whose value is the absolute path inside the container where the runtime mounts it; an app with store format `none` declares none), and the **`/sandbox/llm/v1/`** model-call route (Amendment 3). They still apply to a manifest whose `kind` is not `"app"`.

**The rows.** An app declares every row below except `placement`; a missing row is refused, and the refusal begins with the row's name. The words are the contract; the schema `identity-agent-core/contracts/app-manifest/app-manifest.schema.json` says them again with the exact patterns and limits, and `identity-agent-core/contracts/check_app_manifest_vectors.py` checks the vectors from them without Go.

| Row | What it says, and what is refused |
|---|---|
| `name` | The app's name: at least one character that is not Unicode White_Space. |
| `release_digest` | The one name of the release. **Compiled app:** `blake3:` and 64 lower-case hex digits, the BLAKE3 hash (default 32-byte output) of the executable file's bytes exactly as the runtime launches it, with nothing prepended or appended. **Container app:** `sha256:` and 64 lower-case hex digits, the OCI digest of the image's manifest (of its index for a multi-platform image), the value a registry shows as the image's digest. The other form for the type is refused. The runtime pulls the image by this digest and runs nothing else. |
| `resources` | What the app asks for, as a request and not a cap: a runtime must be able to reserve all of it before it starts the app and refuses to start it otherwise; it may give more. `cpu_cores`: CPUs, whole or fractional (`0.5` is half a CPU), more than 0 and at most 1024. `memory_mb` and `disk_mb`: MiB (1 MiB = 2^20 bytes, despite the name), 1 to 16777216. `egress_kbps`, `ingress_kbps`: kilobits (1000 bits) a second the network is asked to carry, 0 to 100000000, where 0 asks for no reserved rate. |
| `encrypted_machine` | `required`: a runtime refuses to start the app on any machine that has not proved its memory is encrypted (ADR-035). `preferred`: a runtime places the app on a machine that has proved it if one is free; if none is, it starts the app on one that has not, **records that in the owner's view of the app in plain words**, and neither refuses nor stays silent. `not_needed`: placed anywhere, nothing recorded. A machine that cannot prove it counts as not encrypted. A missing row is never read as any of the three. |
| `store` | The app's own encrypted store, `{"format", "size_mb"}`. `format` is a token (a lower-case letter, then lower-case letters, digits, `-` or `_`, at most 32) naming the layout, such as `sqlite`; `none` says the app keeps no store. `size_mb` is the size it asks for in MiB, at most 16777216, in addition to `resources.disk_mb`; it is 0 exactly when the format is `none`. The runtime keeps the store encrypted and the app never holds its key. |
| `placement` | Optional. `own_machine` (a machine of its own) or `shared_machine` (one that runs other apps). Absent means `own_machine`. There is no value for inside the Identity Agent, and any other value is refused. |
| `front_and_back_end` | What the app serves. `static_front_end_url`: a static front end served from a fixed web address, `https://` then a lower-case host name (no wildcard, no IP address), optionally `:port`, optionally a path; no user, query or fragment. `back_end_port`: the TCP port (1 to 65535) of a back end on the app machine, reached only through the relay (no inbound port is open on that machine). At least one of the two is declared. `device_front_ends`: the front ends a person uses, `installed_app` and/or `browser`, each at most once, empty if there is none; a static front end is loaded by a browser, so `browser` must be listed with one. |
| `secrets` | The names of the credentials the app needs: a list of unique names (a lower-case letter, then lower-case letters, digits or `_`, at most 64 characters, at most 64 names). The Identity Agent holds each credential and uses it for the app when the app asks; the value is never handed to the app and never in the manifest. An empty list says none are needed; a missing row is refused. |
| `when_down` | What happens while the app is down. `person_sees`: `notice` (the person is told it is unavailable) or `last_known_data` (the app's own front end shows the last data it provided, read-only and marked out of date; the Identity Agent never shows it). `queue_requests`: whether requests made meanwhile are held until it is back (`true`) or answered at once as unavailable (`false`). `queue_max_seconds`, 1 to 86400, how long a request is held, present exactly when `queue_requests` is true. |
| `backup` | What of the app is backed up and how often. `what`: `store` and/or `settings`, each at most once; secrets are never part of an app's backup; an empty list says nothing is backed up. `every_hours`: whole hours between backups, 1 to 8760, present exactly when `what` is not empty. |
| `network.allowed_domains` | The app's outbound hosts, declared, empty if it reaches none. An entry is exactly one of: a host (`api.example.org`); host and port (`api.example.org:8443`); `*.host` (exactly one label before host, as `vault.MatchHostPort` reads it); `**.host` (one or more labels before host); either wildcard with `:port`. A host is dot-separated labels of lower-case letters, digits and `-` (not at a label's end), 1 to 63 characters each; the entry before the port is at most 253 characters; a host of only digits and dots (an IP address) is refused; a wildcard is followed by at least two labels (`*.com` is refused). A port is 1 to 65535, no leading zero. No port allows any port of the host; a port allows that one. One matcher, `vault.MatchHostPort`, reads an entry for the check, for `IsDomainAllowed` and for the vault. Anything else (a URL, a path, a space, upper case, a wildcard anywhere but the front) is refused. An empty list means the app reaches no outside host and a runtime grants none, in every `network_mode`; `isolated` and `local_only` let an app reach no outside host, so for them a non-empty list is refused. |

**One name for a release.** An app's `release_digest` is its only name for the release. So an app has no `binary.hash`, no `supported_platforms` (one release is one artifact; a build for another operating system is another release with its own manifest), and no digest in `container.image`, which is a name alone. An app is its executable or its image, never both: a compiled app has no `container` block and a container app has no `binary` block. `container.image` has no `@` and no Unicode White_Space character (the set `name` uses). Each is refused, naming the row. A manifest of another kind keeps `binary.hash` and `supported_platforms[].hash` (`blake3:<hex>`, ADR-012 §9) as before. An app is also never `isolation: "host"`.

A key the schema does not declare is refused at every depth, spelt exactly (`placment`, or `Placement`, is not `placement`); null is refused wherever the schema gives none (a key with no value is left out); and an empty string is refused for `kind`, `sub_type`, `isolation`, `release_digest`, `encrypted_machine` and `placement`. `appmanifest.DecodeManifest` does this when a manifest is read.

A manifest whose `kind` is not `"app"` that carries any of `release_digest`, `encrypted_machine`, `store`, `placement`, `front_and_back_end`, `secrets`, `when_down` or `backup` is refused, since the rows mean nothing there. Manifests with no `kind`, or another, are otherwise checked as before.

`appmanifest.Validate` refuses an app manifest that breaks any of this and names the row. Published, and held to the Go types and the check by tests: the schema, which refuses exactly what `Validate` refuses for these rows, and the vectors `identity-agent-core/appmanifest/app-manifest-vectors.json` (accepted manifests, and for each rule one that breaks only it).

**What this does not settle.** How a runtime picks a machine for `encrypted_machine`, how it proves the machine is encrypted (ADR-035), how it checks the release digest against what is installed, and how the Identity Agent uses a secret for an app are the runtime's, and later steps.

## Decision

### 1. Supported App Types (V1)

| Type | Examples | How It Runs | Display Method |
|------|---------|-------------|---------------|
| **Container (web UI)** | Open WebUI, OpenClaw | An OCI image whose display is an HTTP port | A web view, loaded through `/apps/{app_id}/` |
| **Container (desktop GUI)** | Chromium (kasmweb) | An OCI image that streams its desktop over HTTP | A web view |
| **Compiled binary** | Go Demo App | A program run beside the Identity Agent | A terminal |


### 2. What an app can rely on about its network

An app's manifest says how far its traffic may go: `network_mode` says whether it must go through the Identity Agent, may, has no network at all, or reaches only the Identity Agent. `tls_mode` says whether its encrypted traffic may be inspected (`mitm`, under a certificate authority the app is given) or only its destination's name read (`sni_only`). `allowed_domains` and `blocked_domains` take `*.` wildcards. An app is never given an API key the owner keeps.

### 5. Agent API Endpoint — Internal Service Alias

An app reaches the Identity Agent at the address in `IDENTITY_AGENT_API`, which it is given when it starts and must not assume: `http://agent.internal:{port}` inside a container, where `agent.internal` names the computer the Identity Agent runs on, and `http://127.0.0.1:{port}` for a compiled binary. The port is chosen for each running app, so an app reads it from the environment.

The model calls and the conversation routes of ADR-013 are on the Identity Agent's own HTTP port, 5050 unless it was started on another; the example Open WebUI manifest names `http://agent.internal:5050/sandbox/llm/v1`.


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
