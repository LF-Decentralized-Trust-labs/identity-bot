# ADR-013: Container Data Architecture and HTTP API Namespace Convention

- **Status:** Accepted
- **Date:** 2026-03-13
- **Supersedes:** Nothing (extends ADR-026 and ADR-012)
- **Related:** ADR-026 (Data Domain Architecture), ADR-012 (Sandboxed App Registry)

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

## Decisions

### Decision 1: Capture conversations at the LLM proxy, not at the container

All LLM traffic from containers passes through `handleLLMProxy` in `server/llm_handlers.go`. This is the correct and only interception point:

```
Container → POST http://agent.internal:5050/sandbox/llm/v1/chat/completions
          → Identity Agent LLM Proxy (handleLLMProxy)
              → Parse request (model, messages[])
              → Forward to OpenRouter (inject API key from vault)
              → Stream SSE response back to container
              → Async goroutine: save conversation to ai-memory.db
```

**Conversation ID strategy:** The OpenAI API sends the full message history with every request. A stable conversation ID is derived by hashing the first system message and first user message: `sha256(system_msg + "|" + first_user_msg)[:16]`. This stays constant across all turns of the same conversation, allowing the Identity Agent to accumulate turns correctly regardless of how many turns have occurred.

**Message deduplication:** Each message is identified by `sha256(conv_id + role + content + index)[:16]`. SQLite's `ON CONFLICT DO NOTHING` prevents duplicates if the same request is replayed.

**Non-fatal capture:** Capture runs in a goroutine after the response streams. If capture fails, the user's LLM response is unaffected. Capture errors are logged, never surfaced to the client.

### Decision 2: Serve conversation data back to the chat UI via a display reverse proxy

When a chat app's browser frontend makes API calls to list conversations (`GET /api/v1/chats`), the Identity Agent intercepts those calls before they reach the container and serves from `ai-memory.db`. This is implemented as a reverse proxy at `/apps/{app_id}/*`:

```
Flutter WebView loads: http://127.0.0.1:5050/apps/openwebui/
                                                     ↓
                         Identity Agent display proxy (handleAppDisplayProxy)
                                                     ↓
           GET /api/v1/chats → serve from ai-memory.db (conversation list)
           GET /api/v1/chats/{id} → serve from ai-memory.db (conversation + messages)
           All other paths → forward to container's display port (HTML, JS, CSS, WebSocket)
```

The `GET /api/apps/{id}/display` handler now returns the Identity Agent's proxy URL (`http://127.0.0.1:5050/apps/{app_id}/`) instead of the container's raw port URL. The Flutter WebView loads this proxy URL, unaware of the interception layer.

**Container data is intentionally ephemeral.** Container volumes for chat apps are empty (`"volumes": {}`). If a container is deleted and reinstalled, all conversation history reappears from `ai-memory.db`. The container's internal database never matters.

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

## Data Flow Summary

### Outbound: LLM call (Open WebUI → OpenRouter)

```
Open WebUI frontend
  → POST http://agent.internal:5050/sandbox/llm/v1/chat/completions
    (direct — NO_PROXY bypasses MITM inspection proxy)
  → Identity Agent LLM Proxy (handleLLMProxy)
      → Inject API key from credential vault
      → Forward to https://openrouter.ai/api/v1/chat/completions
      → Stream SSE response back to Open WebUI
      → [goroutine] Capture conversation to ai-memory.db
```

### Inbound: Conversation list (Open WebUI frontend → Identity Agent)

```
Open WebUI frontend (running in Flutter WebView at http://127.0.0.1:5050/apps/openwebui/)
  → GET /api/v1/chats
  → Identity Agent display proxy (handleAppDisplayProxy)
      → Intercept: path matches /api/v1/chats
      → Query ai-memory.db: GetConversations()
      → Translate to Open WebUI JSON format
      → Return conversation list
```

### Inbound: All other Open WebUI assets

```
Open WebUI frontend
  → GET /static/js/app.js (or any other path)
  → Identity Agent display proxy (handleAppDisplayProxy)
      → Not intercepted
      → httputil.ReverseProxy → container:8080/static/js/app.js
      → Return response to browser
```

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
- **App-specific format translation.** Each chat app has its own expected JSON format for conversations and messages. The display proxy must translate between `ai-memory.db`'s canonical schema and whatever the app expects. The `openwebui_chat_list` and `openwebui_chat_detail` translators in `app_display_proxy.go` are Open WebUI-specific.

---

## Files

| File | Role |
|------|------|
| `server/llm_handlers.go` | LLM proxy + conversation capture. Route: `/sandbox/llm/v1/*` |
| `server/app_display_proxy.go` | Display reverse proxy + chat API interception. Route: `/apps/{app_id}/*` |
| `server/sandbox_handlers.go` | `handleAppDisplay` returns proxy URL (`/apps/{app_id}/`) instead of raw container port |
| `server/server.go` | Route registration, OOBI URL generation, `oobiBase()` helper |
| `store/ai_memory_store.go` | `SaveConversation`, `SaveMessage`, `GetConversations`, `GetMessages`, FTS5 search |
| `manifests/openwebui.json` | `OPENAI_API_BASE_URL` points to `/sandbox/llm/v1`; `api_schema` field set |
| `manifests/schemas/openwebui-api.json` | Full API schema document for Open WebUI |
| `sandbox/manifest.go` | `APISchema *string` field added to `AppManifest` |

---

## References

- [ADR-026](026-data-domain-architecture.md) — Data domain architecture (one SQLite DB per domain)
- [ADR-012](012-sandboxed-app-marketplace.md) — Sandbox marketplace, MITM proxy, credential vault
- [ADR-007](007-external-http-routing-and-platform-ports.md) — Flutter only calls local Go backend
