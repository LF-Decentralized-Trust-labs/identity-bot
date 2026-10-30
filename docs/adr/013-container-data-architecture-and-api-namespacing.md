# ADR-013: Container Data Architecture and HTTP API Namespace Convention

- **Status:** Accepted
- **Date:** 2026-03-13
- **Supersedes:** Nothing (extends ADR-026 and ADR-012)
- **Related:** ADR-026 (Data Domain Architecture), ADR-012 (Sandboxed App Registry)
- **Amended:** 2026-10-30 — the runtime that serves these routes is an add-on kept outside this repository; this record keeps what an app relies on (see §Note, 2026-10-30)

---

## Context

ADR-026 established the data domain architecture: one SQLite database per data category, never one per app. ADR-012 established the sandboxed app registry (plugins). A key implementation question remained open: **how does a sandboxed app interact with its data domain, and how does data flow between the container and the Identity Agent?**

Two specific problems needed solving:

### Problem 1: Container data is stored inside the container

The naive approach — letting Open WebUI write conversations to its own `webui.db` inside the Podman container — violates the data domain principle:

- If a second AI chat app (LibreChat, OpenClaw) is installed, it gets its own separate database. The user's conversation history is fragmented across N databases, one per app.
- The container's database is ephemeral. If the container is deleted (security incident, reinstall, upgrade), all conversation history is lost.
- Container data cannot be backed up, exported, or searched across apps.

### Problem 2: Inconsistent HTTP URL namespacing

The Identity Agent's Go HTTP server handled requests on paths that had no consistent organizational principle:

| Path | Purpose | Caller |
|------|---------|--------|
| `/api/*` | Management API | Flutter UI |
| `/llm/v1/*` | LLM proxy | Containers |
| `/oobi/{aid}` | KERI OOBI serving | External KERI agents |
| `/apps/{app_id}/*` | Display proxy | Flutter WebView |

`/llm/v1/` was inconsistently named — it looks like a peer to `/api/v1/` but serves a completely different caller with a completely different trust level. A developer reading the route table cannot tell who calls what or why paths are organized as they are.

---

## Note, 2026-10-30: the contract stays, the runtime is an add-on

The code that serves `/sandbox/` and `/apps/`, captures conversations and translates them for a chat app is part of the sandboxed-apps add-on, which an app built on the core includes or not, and which is kept outside this repository. This record keeps what an app is written against: where it sends model calls, where it is loaded from, the namespaces by caller, and the API schema each app's manifest names (`api_schema`, a field of `appmanifest.AppManifest`). The descriptions of how the runtime does each of these are removed here.

---

## Decisions

### Decision 1: An app's model calls go through the Identity Agent, which keeps the conversation

An app makes its model calls to `http://agent.internal:5050/sandbox/llm/v1/` with the OpenAI-compatible API (its `OPENAI_API_BASE_URL`). The Identity Agent adds the key the owner keeps, forwards the call, streams the answer back, and keeps the conversation in the owner's AI conversations, not in the app. An app needs no store of its own for them, and must not rely on keeping one.

### Decision 2: An app's display is loaded through the Identity Agent

An app's web display is loaded from `http://127.0.0.1:5050/apps/{app_id}/`, never from its container's own port. The Identity Agent answers the chat app's conversation reads (`GET /api/v1/chats` and below) from the owner's conversations, under the conversation read rule (ADR-012 Amendment 4), and passes everything else to the app's display port. So a container's own data is disposable: delete and reinstall it, and its conversations reappear.

### Decision 3: HTTP API URL namespace organized by caller identity

Every route on the Identity Agent's HTTP server belongs to one of four namespaces, determined by **who calls it**:

| Namespace | Caller | Trust Level | Examples |
|-----------|--------|-------------|---------|
| `/api/` | Flutter UI (local process) | Trusted, local | `/api/contacts`, `/api/settings/llm`, `/api/ai/conversations`, `/api/trace/*` |
| `/sandbox/` | Sandboxed containers (Podman) | Semi-trusted, controlled | `/sandbox/llm/v1/*` |
| `/public/` | External KERI agents (internet) | Untrusted, public | `/public/oobi/{aid}` |
| `/apps/` | Flutter WebView (display proxy) | Browser context | `/apps/{app_id}/*` |

**Rationale:** Organizing by caller identity makes the security model immediately legible. A developer reading the route table knows:
- `/sandbox/*` — this is called from inside a container; apply container-level trust
- `/public/*` — this is called from the public internet; apply zero trust
- `/api/*` — this is called by the local Flutter UI; apply local trust
- `/apps/*` — this is the reverse proxy into a container's display port

**Legacy OOBI path:** The old `/oobi/{aid}` path redirects to `/public/oobi/{aid}` (HTTP 301) for backward compatibility with existing contacts whose OOBI URLs were stored before this ADR.

**The trace tooling** (`/api/trace/*`, `/dev/trace`, `/ws/trace`) stays as-is — trace routes are already correctly namespaced under `/api/trace/` for management API calls, with a `/dev/trace` page for developer diagnostics and `/ws/trace` for WebSocket streaming.

### Decision 4: API schema document per container app

Every app manifest references an API schema document (`api_schema` field) that enumerates all API paths the app calls, whether each is intercepted, which data domain it maps to, and the direction of flow. This document serves as:

- **Developer specification:** When building a new app integration, the schema shows which paths need Identity Agent interception handlers.
- **Architecture reference:** Shows the full data flow for an app without reading Go code.
- **Future policy engine input:** Interception rules can be driven from the schema rather than hardcoded.

Schema format: `manifests/schemas/{app_id}-api.json`

Each endpoint entry in the schema specifies:
- `path` — URL path pattern
- `method` — HTTP method
- `direction` — `outbound` (container → Identity Agent → internet) or `inbound` (browser → container, via display proxy)
- `namespace` — which namespace this call uses
- `data_domain` — which domain database is read/written, or `null`
- `intercept` — whether the Identity Agent handles this instead of the container
- `capture` — whether request/response data is captured to the data domain

---

## Consequences

### What this enables

- **One canonical store for all AI conversations** regardless of which chat app generated them. Open WebUI, LibreChat, or any future chat app all write to `ai-memory.db` automatically via the LLM proxy.
- **True ephemeral containers.** Delete a container, reinstall it — all conversations reappear. Container compromise means deleting the container; data is safe in `ai-memory.db`.
- **Cross-app search.** `GET /api/ai/search?q=query` searches all conversations from all AI apps via FTS5.
- **Zero app-side integration required.** A new chat app using the OpenAI-compatible API requires only: (1) pointing `OPENAI_API_BASE_URL` at `/sandbox/llm/v1`, and (2) loading through `/apps/{app_id}/`. No app code changes needed.
- **Legible security model.** The namespace structure makes trust levels immediately visible in the route table.

### What this trades off

- **Display proxy adds latency for non-intercepted requests.** Every browser request to the container now passes through the Go reverse proxy. In practice this is negligible (same-host loopback, Go `net/http/httputil.ReverseProxy` is extremely fast), but it is a real hop.
- **Open WebUI conversation CRUD writes are not captured.** The current interception captures conversations as they happen via the LLM proxy. Open WebUI write operations (rename conversation, delete conversation, add tag) that go to the container's own backend are not intercepted and will not be reflected in `ai-memory.db`. Capturing write operations is future work — it requires intercepting additional `/api/v1/chats` write paths in the display proxy.
- **App-specific format translation.** Each chat app has its own expected JSON format for conversations and messages, so a runtime translates the owner's conversations into the format each chat app expects.

---

## Files

| File | Role |
|------|------|
| `identity-agent-core/appmanifest/manifest.go` | `api_schema` and the rest of the manifest |
| `manifests/openwebui.json` | `OPENAI_API_BASE_URL` points to `/sandbox/llm/v1`; `api_schema` field set |
| `manifests/schemas/openwebui-api.json` | Full API schema document for Open WebUI |
| `identity-agent-core/store/ai_memory_store.go` | The owner's AI conversations |

---

## References

- [ADR-026](026-data-domain-architecture.md) — Data domain architecture (one SQLite DB per domain)
- [ADR-012](012-sandboxed-app-marketplace.md) — Sandboxed apps: the manifest and how an app is called
- [ADR-007](007-external-http-routing-and-platform-ports.md) — Flutter only calls local Go backend
