# ADR-026: Data Domain Architecture

- **Status:** Accepted
- **Date:** 2026-03-13
- **Supersedes:** None
- **Related:** ADR-006 (Topology), ADR-012 (Sandboxed App Registry), ADR-013 (Container Data Architecture)

---

## Context

The Identity Agent's original storage layer is `FileStore` — flat JSON files written to `$AGENT_DATA_DIR`. This was appropriate for early development, but breaks down as the system expands:

- **No query capability.** Finding a contact by status requires loading every record into memory and filtering.
- **No atomic multi-record writes.** Two concurrent writes can corrupt a file.
- **No lifecycle management.** There is no way to prune expired pending requests without a full load-rewrite cycle.
- **Single-domain assumption.** All data lives in one directory. There is no structural separation between identity-critical data (KERI keys, KEL) and lower-sensitivity data (AI conversation history, email).

Simultaneously, the system is beginning to manage meaningfully different categories of data — KERI identity, AI conversations, sandboxed app infrastructure — that have different sensitivity levels, size profiles, access patterns, and lifecycle rules. A single storage approach cannot serve all of these well.

The challenge is to define a storage architecture that:
1. Handles the full range of data types a person accumulates over a lifetime
2. Gives users granular control over where each category lives
3. Remains simple enough to implement and operate on a self-hosted device
4. Can be managed by a future Data Manager app without modifying the Identity Agent's core code

---

## Decision

### Organizing Principle: Data Domains

Each database is a **Data Domain** — a distinct SQLite database file organized by data type, lifecycle, and access pattern. This is the developer-facing term. In user-facing surfaces, each domain maps to a "Hub" (e.g., AI Hub, Communications Hub).

One domain per data category. Not one per app, not one monolithic database. Ten, twenty, or fifty domain databases is acceptable and expected as the system grows. Each is a single portable file — trivially backupable, isolatable, and offloadable independently.

### Storage Engine: SQLite

SQLite is the exclusive persistence engine for all structured data across all domains:

- **`modernc.org/sqlite`** — pure Go, no CGO, already in `go.mod`, already used by `sandbox.db`
- WAL journaling mode on every database (`PRAGMA journal_mode=WAL`)
- 5-second busy timeout on every database (`PRAGMA busy_timeout=5000`)
- Foreign keys enabled (`PRAGMA foreign_keys=ON`)
- Schema versioned via a `schema_migrations` table (same pattern as sandbox)

---

## The Data Domains

### Domain 1 — Identity Core (`identity.db`)

| Property | Value |
|----------|-------|
| File | `$AGENT_DATA_DIR/identity.db` |
| Access | Identity Agent core only — no sandboxed app can read this directly |
| Sensitivity | Critical |
| Size | Small (<1 MB typical) |
| On-device | Always — never leaves the device |

**Stores:** KERI AID, Key Event Log (KEL), verifiable credentials, contacts, profile, settings, pending connection requests, public endpoint URL.

This is the only domain with uniquely privileged access. No manifest capability can grant a sandboxed app direct access to `identity.db`. Apps that need identity data receive it via the Identity Agent API, which enforces its own authorization.

**Migration:** On first launch after this ADR is implemented, if `identity.db` does not exist but `$AGENT_DATA_DIR/*.json` files do, the agent automatically migrates all JSON data into SQLite. The JSON files are preserved as a backup but are no longer read.

---

### Domain 2 — AI Memory (`ai-memory.db`)

| Property | Value |
|----------|-------|
| File | `$AGENT_DATA_DIR/ai-memory.db` |
| Access | AI Hub apps with `ai_memory_read` or `ai_memory_crud` manifest capability |
| Sensitivity | Personal |
| Size | Medium, grows continuously |
| On-device | Default; encrypted remote optional |

**Stores:** AI conversation history (messages, roles, models), per-app AI settings and preferences.

AI conversations are fundamentally different from human communications (email, SMS) despite both being "conversations":
- Counterparty is an AI model, not a human
- Access pattern is semantic retrieval, not threaded inbox
- Consumers are AI apps (Open WebUI, OpenClaw), not mail clients

`ai-memory.db` uses SQLite FTS5 for full-text search as an immediate capability. It is the primary feed for future vector embedding pipelines (ChromaDB or LanceDB), which will be embedded components used by the Data Manager — not additional sandboxed apps.

---

### Domain 3 — Communications (`communications.db`)

| Property | Value |
|----------|-------|
| File | `$AGENT_DATA_DIR/communications.db` |
| Access | Communications Hub apps with `communications_read` or `communications_crud` manifest capability |
| Sensitivity | Personal |
| Size | Large (200K+ emails is a normal case) |
| On-device | Default; encrypted remote optional when explicitly configured |

**Stores:** Email, SMS, phone call logs, message threads between humans.

Schema design is deferred to a dedicated planning session. Key design decisions to make at that time: threading model, attachment storage strategy (reference vs. BLOB), and IMAP/Gmail import normalization format.

---

### Domain 4 — Sandbox Infrastructure (`sandbox.db`)

| Property | Value |
|----------|-------|
| File | `$AGENT_DATA_DIR/sandbox.db` |
| Access | Identity Agent core (sandbox subsystem) only |
| Sensitivity | System |
| Size | Small-medium |
| On-device | Always |

**Stores:** App installation metadata, running instance state, network proxy logs, policy rules, resource access decisions, audit events.

This domain already exists (ADR-012). It is the sandbox subsystem's own infrastructure metadata — not per-app user data storage. Containerized apps do **not** store user data inside their Podman volumes — container storage is intentionally ephemeral (volumes are empty `{}`). User data is captured by the Identity Agent at the proxy layer (ADR-013) and stored in the appropriate domain database. Multiple AI chat apps installed as sandboxed apps all write to `ai-memory.db` — they do not get per-app copies.

---

### Data Lake — Staging Area

| Property | Value |
|----------|-------|
| Location | `$AGENT_DATA_DIR/lake/` |
| Access | Data Manager only |
| Sensitivity | Variable (whatever the import contains) |
| Size | Variable; temporary |

**Purpose:** Temporary encrypted holding area for bulk imports before processing. A Facebook export, Gmail export, or 200K email import arrives here first. The Data Manager classifies and routes each record to the correct domain database. Every file in the lake has an associated processing job; once processed, the file is deleted.

Not a permanent store. The Data Lake is not a queryable domain.

---

### Future Domains (Roadmap)

Additional domains will be added as hubs are built out:

| Domain | File | Hub |
|--------|------|-----|
| Health | `health.db` | Health Hub |
| Finance | `finance.db` | Finance Hub |
| Documents | `documents.db` | Documents Hub |
| Social | `social.db` | Social Hub |

Each new domain follows the same pattern: one SQLite file, WAL mode, FTS5 where needed, schema migrations table, manifest capability required for app access.

---

## The Data Manager

The Data Manager is a sandboxed app with a manifest that grants it full CRUD across all domain databases and zero external egress. It is the canonical custodian of data lifecycle operations.

**It is not hardcoded into the Identity Agent.** It is an installable app that happens to be installed by default. Any third party can build a replacement Data Manager that speaks the Identity Agent API — no vendor lock-in.

**Responsibilities:**
- Normalize and import data from the Data Lake into the correct domain
- Manage database housekeeping (pruning, archiving, deduplication)
- Orchestrate bulk import processing jobs (e.g., importing a Gmail export into `communications.db`)

**Note:** AI conversations are **not** exported from container storage by the Data Manager. They are captured directly by the Identity Agent's LLM proxy as they happen — see ADR-013. Container data is intentionally ephemeral. The Data Manager manages bulk historical imports (e.g., importing ChatGPT export files into `ai-memory.db`), not real-time capture.

**It is NOT responsible for:**
- Policy enforcement (that is the policy engine in `sandbox/policy.go`)
- Network access control (that is the proxy in `sandbox/proxy.go`)
- Backups (a separate module, separate ADR)

**Manifest spec:**
```json
{
  "capabilities": {
    "allowed": ["identity_agent_api", "ai_memory_crud", "communications_crud", "tier4_container_read"],
    "blocked": ["network", "camera", "microphone", "filesystem_write_external"]
  },
  "network": {
    "allowed_domains": ["agent.internal"],
    "blocked_domains": ["*"]
  }
}
```

---

## Consequences

### What This Enables

- **Query capability:** SQL queries replace full-file loads. Finding contacts by status is a single indexed query.
- **Atomic writes:** SQLite transactions prevent partial writes.
- **Selective backup:** Each domain is one file. Back up `identity.db` separately from `ai-memory.db`.
- **Independent offload:** A user can move `ai-memory.db` to an encrypted remote store without touching `identity.db`.
- **Incremental growth:** Adding a new hub means adding one new SQLite file. Existing domains are untouched.
- **Data Manager decoupling:** The Data Manager interacts with domain data via the Identity Agent API, not by directly touching files. Swapping the Data Manager implementation requires no Identity Agent changes.

### What This Trades Off

- **Complexity:** Multiple database files instead of one flat directory. Mitigated by each file being self-contained and independently manageable.
- **Migration work:** Existing JSON data must be migrated on first launch. Migration is automatic and one-time.
- **No cross-domain joins:** Each domain is a separate database connection. Data that spans domains must be assembled at the application layer. This is intentional — it enforces domain separation.

---

## Implementation Order

1. **Phase 1 (complete):** Identity Core — migrate `FileStore` to `SQLiteStore` (`identity.db`)
2. **Phase 2 (complete):** AI Memory — create `ai-memory.db` with FTS5, expose via `/api/ai/` routes
3. **Phase 3 (complete):** LLM proxy capture + display reverse proxy — real-time conversation capture from sandboxed chat apps (see ADR-013)
4. **Phase 4 (next):** Data Manager manifest + binary — bulk historical imports (e.g., ChatGPT export → `ai-memory.db`, Gmail export → `communications.db`)
5. **Phase 5 (next):** Communications domain (`communications.db`) — schema design TBD
6. **Phase 6+:** Health, Finance, Documents domains as hubs are built
