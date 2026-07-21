# ADR-020: Organization Identity Agents

**Status:** Accepted
**Date:** 2026-03-22
**Deciders:** Rob Andersen

---

## Context

The Identity Agent Protocol is designed around individual user-controlled identity — one AID per person, managed on their own device. However, organizations (businesses, schools, hospitals, government agencies) also require verifiable identity, credential issuance authority, and participation in the KERI trust ecosystem.

Key questions this ADR resolves:

1. Do organizations use the same identity agent software as individuals, or a separate one?
2. Where is the boundary between what is open source and what is proprietary?
3. How does the open source core stay verifiable and trustworthy when org-specific applications are built on top of it?
4. How does the protocol handle the fact that org workflows are fundamentally different from individual workflows?

→ *Related: ADR-006 (Topology), ADR-019 (Guardianship), Unknowns #3 (Organization identity agents)*

---

## Decision

### Guiding Principles

1. **KERI Protocol does not distinguish individuals from organizations.** At the KERI/ACDC level, an organization is simply an AID with a KEL. Key rotation, credential issuance, delegation, witnessing, and verification all work identically. There is no "organization KERI."

2. **`entity_type` is an Identity Agent Protocol-level concept, not a product concept.** The `organization` entity type lives in the open source `identity-agent-core` and the protocol specification. It affects profile fields, default multisig thresholds, and delegation defaults — nothing more. It does not gate any protocol capability.

3. **Org identity agent applications are separate products, not forks.** An organization runs its own identity agent instance on its own server infrastructure. The application is built by a service provider on top of the open source `identity-agent-core` — it embeds the core binary as its protocol engine rather than duplicating or forking it.

4. **The open source core is the verifiable trust anchor.** The `identity-agent-core` binary can be hash-verified against the published artifact in the open source repository. Any organization can confirm they are running the authentic protocol implementation regardless of which service provider built their application layer.

5. **Interoperability is guaranteed at the core level.** Because all implementations — individual and organizational — run the same `identity-agent-core` protocol engine, ACDC credential chains, KERI events, and contact relationships are fully interoperable between individuals and organizations without any special handling.

---

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  identity-agent-core  (open source, LF Decentralized Trust)         │
│  Python KERI driver   (open source, LF Decentralized Trust)         │
│                                                                      │
│  Exposes:  /api/* — identical endpoints for all entity types        │
│  entity_type field changes profile schema and a few defaults only    │
│  Binary is hash-verifiable against the published open source build   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │  REST API (same contract for all)
           ┌───────────────────┼────────────────────────┐
           │                   │                        │
    Individual Agent     School Agent             Enterprise Agent
    (open source UI)     (service provider UI)    (service provider UI)
    LF Decentralized     Separate application     Separate application
    Trust repo           Separate repo            Separate repo
                         Org-specific screens     Industry-specific screens
                         Org-specific DB tables   Extended DB schema
                         Hosted on org server     Hosted on org infrastructure
```

The individual identity agent (UI + core) lives entirely in the open source repository. Organizational identity agent applications are built by service providers using the open source core as their protocol foundation. Each org agent runs as an isolated instance on the organization's own server or hosted infrastructure.

---

### What Lives in the Open Source Repository

| Component | In open source? | Notes |
|---|---|---|
| KERI protocol operations (inception, rotation, signing, witnessing) | Yes | Always, for all entity types |
| ACDC credential issuance and verification | Yes | Always, for all entity types |
| ACDC edge block chaining | Yes | Required for interoperability |
| `entity_type: organization` in profile | Yes | Protocol-level concept |
| Org profile fields (org name, jurisdiction, org type) | Yes | Protocol-level schema |
| Default multisig threshold for orgs | Yes | Protocol default only |
| Individual-facing Flutter UI | Yes | This repo |
| Individual-facing Governance Gateway (personal policy engine, personal audit log) | Yes | Open source — individuals control their own agent policies |
| Employee management UI | No | Service provider product |
| Department credential workflow UI | No | Service provider product |
| Org-specific database tables and extensions | No | Service provider product |
| Org-specific governance (internal org policies, inter-department access controls, compliance reporting, proprietary data governance) | No | Service provider product — governance logic that is specific to how an organization structures its internal authority and external data-sharing agreements is not part of the individual protocol |
| Hosted infrastructure management | No | Service provider product |
| Industry-specific credential templates | No | Service provider product |

---

### What Service Providers Build

An Identity Agent service provider creates an organizational identity agent application that:

- **Embeds `identity-agent-core`** as its protocol engine (same binary, hash-verifiable)
- **Extends the REST API** with org-specific endpoints (employee management, department routing, multi-admin, compliance tooling)
- **Provides an industry-specific UI** (a Flutter application or web frontend entirely separate from the individual UI) — examples:
  - School: student enrollment, credential issuance to parents, verifier screen for staff
  - Healthcare: patient identity management, clinical credential issuance, HIPAA audit trail
  - Enterprise: employee delegated AID provisioning, department credential workflows, HR integration
  - Retail: customer identity, loyalty credential management, loyalty tier issuance
- **Extends the database schema** with org-specific tables (employees, departments, org hierarchy, audit records)
- **Provides hosted infrastructure** — each organization runs its own isolated server instance; service providers may offer managed hosting

Service providers may offer these as open source, freemium, or fully proprietary products — the Identity Agent Protocol imposes no restrictions. Their interoperability obligation is only to the core protocol.

---

### Large Enterprise Considerations

Very large organizations (tens of thousands of employees, millions of customer interactions) may require scaled infrastructure that goes beyond what a single `identity-agent-core` instance can handle. In these cases, service providers may build proprietary scaled implementations that:

- Embed `identity-agent-core` as a library rather than a single binary
- Distribute protocol operations across multiple nodes
- Add enterprise-grade infrastructure (load balancing, database clustering, compliance reporting)

These proprietary scaled implementations are NOT forks of `identity-agent-core` — they depend on it. The open source core remains the canonical protocol implementation; scaled deployments simply run it differently. Such implementations are inherently not open source, as they represent significant commercial engineering investment and serve a market with the resources to support proprietary software.

---

### ACDC Edge Block Support

Organizational credential workflows frequently require chained credentials — for example, a School Pickup Authorization that references a Guardianship Credential as its chain-of-trust anchor. This requires proper ACDC edge block (`e`) construction, not just attribute-level SAID references.

Both the Python KERI driver and the Go `KeriDriver` interface expose `edges` as a first-class parameter to `IssueCredential`. This ensures:

- Credentials issued by organizational agents carry proper ACDC-compliant edge blocks
- Any KERI-compliant verifier can traverse the credential chain without knowledge of our specific field names
- Desktop (Python KERI driver) and mobile (delegated to remote KERI service) both support edge-chained credential issuance

---

### Protocol Version and Trust

The Identity Agent Protocol follows semantic versioning. Any identity agent application — individual or organizational — that embeds `identity-agent-core` at a compatible protocol version is considered a conformant implementation. Service providers are expected to:

1. Declare which version of `identity-agent-core` they embed
2. Publish the binary hash of the embedded core alongside their product
3. Upgrade the embedded core when security patches are released

The LF Decentralized Trust project publishes signed release artifacts for each `identity-agent-core` version, allowing any party to verify protocol conformance independently.

---

## Consequences

**What this enables:**
- Any organization can run a protocol-conformant identity agent without building from scratch
- Service providers can differentiate on UI, workflow, and infrastructure without fragmenting the protocol
- Individuals and organizations interoperate seamlessly because they share the same protocol core
- The open source project remains focused on individual use cases — no org workflow complexity bleeds into the individual UI

**What this constrains:**
- The open source repository does not accept contributions of org-specific UI or workflow code (those belong in service provider repos)
- Service providers who extend the database schema must handle their own migration path — `identity-agent-core` migrations are not their concern
- The `entity_type` flag in `identity-agent-core` will never gate protocol capabilities — only profile schema and protocol defaults

**Open questions / future ADRs needed:**
- Protocol certification process: how does the LF project formally certify that a service provider's implementation is conformant?
- Multi-admin model: how do multiple org admins co-manage an org AID within the protocol?
- Org-to-org credential issuance: any additional protocol conventions beyond standard ACDC?
- **Org profile field specification** *(task required before first org demo)*: The current open source org profile includes `org_name`, `org_type`, and `jurisdiction`. The `jurisdiction` format is **RESOLVED (2026-06-13)**: store the **incorporation jurisdiction** as an **ISO 3166 country code** plus an **optional ISO 3166-2 subdivision** (e.g. US state), and keep a **separate optional `operating_jurisdictions[]` list** for where the org operates. Rationale: free-text jurisdiction would break the rights-profile match that the compliance jurisdiction model already uses — structured codes let org profiles bind cleanly to the canonical jurisdiction-keyed Digital Rights Profiles. Still open: what other profile fields are universally applicable vs. industry-specific. This must be resolved before the org onboarding flow is built. Tracked in `tasks.md`.

---

## Amendment (2026-07-21): Core extension seams

The extension model above ("embed `identity-agent-core`, extend the REST API +
schema") is realized through a small, generic set of **extension seams** in
`identity-agent-core` (package `server`), so a service provider's implementation
attaches to the core **without forking it**. These seams are the *public
contract*; the implementation behind them is each provider's own.

| Seam | Purpose |
|---|---|
| `RegisterMembershipResolver(source, resolver)` | Gate a sign-in on your own roster. The core's access check resolves a non-default `EnrollmentPolicy.MembershipSource` (any value other than `""` / `"asset"`) through your registered resolver, which returns admit/deny for a presented pairwise AID. Unregistered sources fail closed. |
| `CoreServer.MountExtraRoutes(fn)` | Mount your own HTTP endpoints under `/api` (your management / invite / redeem routes). |
| `StoreAsk(token, ask)` | Publish an Ask your implementation mints at the canonical `/i/{token}` URL, so scanners fetch it exactly like a core-minted Ask. |
| `CoreServer.AssetStore()` · `MintPairwise()` · `PublicURL()` | The minimal read / mint / URL accessors those endpoints need. |

The **universal action language** (action codes + schemas — ADR-017, `actions/registry.json`)
and the **individual side of every action** are open source; that is what
guarantees any individual agent interoperates with any org agent regardless of
who built it. What a provider keeps to itself is the **implementation** behind the
seams — its roster, approval/lifecycle, access policy, and storage layout (kept in
its own Data Domain per ADR-026).

**Shape of building an org agent (a direction, not a recipe):** embed
`identity-agent-core`; register a membership resolver backed by your own roster;
mount your endpoints via `MountExtraRoutes`; mint invites/QRs as Asks and publish
them with `StoreAsk`; store your org data in its own domain database. How you
model and run any of that is yours to decide.
