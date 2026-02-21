# ADR 005: Control Plane Governance Architecture

## Status
Accepted — February 2026

## Context
Identity Agent needs a governance layer to manage AI agents running in sandboxed environments. The original architecture (ADR 001) defined the Go backend and Flutter UI for identity management. As we move toward deploying AI agents (e.g., OpenClaw) on remote machines, we need:

1. **Visibility** into what sandboxed agents are doing (syscalls, network traffic, file access)
2. **Policy authoring** to define what agents are allowed to do
3. **Enforcement** to block unauthorized behavior in real time
4. **Separation** between the management layer (accessible anywhere) and the execution layer (on the machine running the agent)

The key architectural question: should governance run on the same machine as the agent, or should we split management from execution?

## Decision

### Control Plane / Data Plane Split

We adopt a **Control Plane / Data Plane** architecture, modeled after Kubernetes and service mesh patterns:

```
┌─────────────────────────────────┐     ┌─────────────────────────────────┐
│     CONTROL PLANE (Replit)      │     │     DATA PLANE (VPS/Desktop)    │
│                                 │     │                                 │
│  App Store UI (/app-store)      │     │  eBPF Syscall Tracer            │
│  Telemetry Dashboard            │◄────│  Network Namespace + veth       │
│  Policy Editor (OPA/Rego)       │     │  Firecracker microVM / WASM     │
│  Audit Log Viewer               │     │  OpenClaw Agent Instance        │
│  PostgreSQL (state)             │────►│  Policy Enforcement Agent       │
│  Management API                 │     │  Telemetry Shipper              │
│                                 │     │                                 │
└─────────────────────────────────┘     └─────────────────────────────────┘
         Webhook Ingest                      Sends JSON Batches
         OPA Evaluate API                    Queries for Decisions
```

**Rationale:**
- The Control Plane runs on Replit with a stable URL, PostgreSQL database, and web dashboard — accessible from any browser
- The Data Plane runs on the actual VPS/desktop where agents execute — it has direct access to the kernel (eBPF), network stack, and filesystem
- This split allows managing multiple Data Planes from a single Control Plane
- The Data Plane can operate in "audit mode" (observe only) before enforcement is enabled
- If the Control Plane is unreachable, the Data Plane can cache policies locally and continue enforcing

### PostgreSQL Over File-Based Storage

**Decision:** Replace the original file-based JSON storage with PostgreSQL.

**Rationale:**
- Telemetry data grows unboundedly — file-based JSON doesn't scale for thousands of events per minute
- SQL aggregation queries (top syscalls, destination frequency, protocol breakdown) are natural in PostgreSQL
- Replit provides a managed PostgreSQL instance with automatic backups and rollback
- The ORM-less approach (raw SQL with parameterized queries) keeps dependencies minimal and avoids migration tool complexity

**Tables created (11):**
- `apps` — registered agent applications
- `policies` — governance policies (legacy format)
- `audit_log` — audit trail entries
- `rego_policies` — OPA/Rego policy source code
- `syscall_events` — eBPF syscall trace data
- `network_events` — packet-level network telemetry
- `file_access_events` — filesystem operation traces
- `tunnel_configs`, `oobi_records`, `contacts`, `credentials` — identity/connectivity

### OPA/Rego as the Policy Engine

**Decision:** Embed the Open Policy Agent (OPA) Go SDK for policy evaluation.

**Rationale:**
- OPA is the industry standard for cloud-native policy (used by Kubernetes, Envoy, Terraform)
- Rego is purpose-built for policy rules — far more expressive than JSON config for governance
- The Go SDK allows in-process evaluation (no sidecar needed) with sub-millisecond latency
- Policies can be versioned, simulated against historical data, and validated before deployment
- The same Rego policies can run on both Control Plane (simulation) and Data Plane (enforcement)

**OPA integration points:**
- `POST /api/opa/policies` — CRUD for Rego policy modules
- `POST /api/opa/evaluate` — evaluate loaded policies against an input event
- `POST /api/opa/validate` — syntax-check Rego code before saving
- `POST /api/opa/simulate` — test a policy against a batch of historical events

### Telemetry Schema as the eBPF Contract

**Decision:** Define a structured telemetry schema that serves as the contract between Data Plane and Control Plane.

The schema defines three event types that map directly to eBPF probe outputs:

```json
{
  "app_id": "openclaw-1",
  "syscall_events": [
    {
      "syscall_name": "openat",
      "syscall_num": 257,
      "pid": 1234,
      "comm": "python",
      "args": "/etc/passwd",
      "return_value": 3,
      "success": true,
      "timestamp": "2026-02-21T08:00:00Z"
    }
  ],
  "network_events": [
    {
      "direction": "outbound",
      "protocol": "tcp",
      "dst_ip": "93.184.216.34",
      "dst_port": 443,
      "dns_query": "example.com",
      "bytes_sent": 256,
      "bytes_recv": 1024,
      "action": "allowed",
      "timestamp": "2026-02-21T08:00:02Z"
    }
  ],
  "file_events": [
    {
      "path": "/etc/passwd",
      "operation": "read",
      "pid": 1234,
      "comm": "python",
      "success": true,
      "timestamp": "2026-02-21T08:00:00Z"
    }
  ]
}
```

**Rationale:**
- Schema-first design ensures the VPS agent and Control Plane stay in sync
- Field names match eBPF output conventions (`comm` for process name, `syscall_name`, `pid`)
- The batch format allows efficient bulk ingestion (hundreds of events per POST)
- The webhook pattern (`POST /api/telemetry/ingest`) means the Data Plane pushes data — no polling required

### Three-Phase Rollout Strategy

**Phase 1 — Audit Mode (COMPLETE):**
Collect telemetry from sandboxed agents. Observe behavior without blocking anything. Build a baseline understanding of what the agent does.

**Phase 2 — Policy Engine (COMPLETE):**
Analyze collected telemetry. Author Rego policies that define allowed behavior. Simulate policies against historical events to verify correctness before deployment.

**Phase 3 — Enforcement (NEXT — VPS-side):**
Deploy policies to the Data Plane. The enforcement agent queries OPA before allowing syscalls/network traffic. Deny-by-default mode blocks anything not explicitly permitted.

## Consequences

### Pros
- Clean separation of concerns — UI/management never touches the execution kernel
- Multiple Data Planes can report to one Control Plane
- Policy simulation prevents accidental lockouts before enforcement
- PostgreSQL handles telemetry scale with proper indexing
- OPA/Rego is battle-tested and well-documented

### Cons
- Requires network connectivity between Data Plane and Control Plane (mitigated by local policy caching)
- Two deployment targets to manage (Replit + VPS)
- Telemetry webhook has no authentication yet (should add API key auth before production use)

## Related ADRs
- [ADR 001](001-core-architecture-stack.md) — Core architecture and language stack
- [ADR 002](002-keri-driver-pattern.md) — KERI driver pattern
- [ADR 003](003-adaptive-architecture.md) — Adaptive architecture decisions
