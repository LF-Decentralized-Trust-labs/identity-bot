# ADR-019: Guardianship

**Status:** Accepted
**Date:** 2026-03-22
**Deciders:** Rob Andersen

---

## Context

The Identity Agent manages an individual's self-sovereign digital identity. However, many people cannot — or should not — manage their own identity independently:

- **Minor children** have no legal capacity to manage identity; a parent or legal guardian acts on their behalf.
- **Elderly family members** may become incapacitated and need a family member or attorney to manage their identity.
- **People with disabilities** may require ongoing guardianship for identity decisions.
- **Temporary situations** (medical events, travel, short-term care) may require time-limited delegation.
- **End of life** requires a way to transition identity management to an estate executor or designated family members.

KERI already provides the cryptographic primitives needed for all of these scenarios — delegated AIDs, multi-sig, and pre-rotation commitments. This ADR establishes how these primitives are exposed to users through the Guardianship feature, including the device/hosting architecture for dependent identities.

→ *Related: ADR-006 (Topology), ADR-014 (Key Custody), ADR-018 (Desktop Navigation)*

---

## Decision

### Guiding Principles

1. **One AID per Identity Agent instance, always.** A dependent's AID is never co-located on the guardian's device within the same Identity Agent instance. Every identity gets its own isolated instance with its own data directory and key storage.

2. **KERI delegation is the foundation.** Every guardianship relationship maps to a KERI delegated AID. The guardian holds the root AID (delegator); the dependent receives a delegated AID (delegatee). This reuses the existing Topology #2 (Remote Controller WITHOUT Root Keys) pattern from ADR-006.

3. **Jurisdiction-agnostic.** Guardianship templates are behavioral configurations (emancipation triggers, authority levels, multi-sig thresholds), not legal instruments. The Identity Agent does not map to specific legal jurisdictions — the legal layer is handled externally.

4. **Plain language over technical vocabulary.** The feature is called "Guardianship" (not "Delegation"). Templates use consumer terms: "Minor Child", "Elderly Family Member", "Person with a Disability", "Temporary Guardianship". Contact labels are directional plain English: "You are guardian of [Name]".

5. **Infrastructure provider-agnostic.** Cloud-hosted dependent identities are provisioned through an "Identity Agent Infrastructure Service Provider" — a generic concept. Grape ID is the default (first-party) provider, but additional providers can be configured to avoid vendor lock-in.

6. **Phased delivery.** Phase 1 ships guardianship delegation (My Dependents, templates, contact labels). Succession planning and estate management follow in later phases.

---

### Guardianship = KERI Delegated AID

Each guardianship relationship maps to a KERI delegated AID:

| Role | KERI Concept | Identity Agent Topology |
|---|---|---|
| Guardian | Delegator — holds root AID and root signing keys | Topology #1 (Standalone) or existing topology |
| Dependent | Delegatee — receives a delegated child AID | Topology #2 (Remote Controller WITHOUT Root Keys) |
| Co-guardian | Multi-sig participant on the delegation | Multi-sig threshold on the delegated AID |

The guardian can:
- **Rotate** the dependent's keys (e.g., if the dependent's device is lost)
- **Revoke** the delegation entirely (e.g., abuse, court order)
- **Emancipate** — transfer root authority to the dependent (final delegation + new inception)

### Dependent AID Hosting

The dependent's Identity Agent instance runs on a **separate, dedicated device** — either a cloud-hosted instance or a physical device. There are no plans to support running multiple AIDs within a single Identity Agent instance on the same device.

| Hosting Option | Description | Use Case |
|---|---|---|
| **Cloud-hosted** (default) | Provisioned via an Identity Agent Infrastructure Service Provider (default: Grape ID). Isolated instance with TEE-backed key storage. | Newborns, infants, any dependent without their own device, multi-sig guardianship |
| **Separate physical device** | Dependent has their own phone/laptop/desktop with Identity Agent installed. Guardian pairs via OOBI exchange. | Teenagers, elderly with a device, anyone with their own hardware |

**Why cloud-hosted is the default:**
- Instant provisioning — no hardware needed
- Natural multi-sig — multiple guardians connect as remote controllers to the same instance
- Clean emancipation path — transfer root keys, data stays in place
- TEE-backed key security
- No storage burden on the guardian's device

**Identity Agent Infrastructure Service Providers** are configured in Settings > Service Providers. Grape ID is pre-configured as the default. Any service that runs an isolated Identity Agent instance with TEE-backed secure enclave and exposes the standard Identity Agent API qualifies as a provider.

### Guardianship Templates

Four built-in templates pre-configure the KERI delegation parameters, default permissions, and lifecycle triggers:

| Template | Duration | Authority | Emancipation Trigger | Multi-sig Default |
|---|---|---|---|---|
| **Minor Child** | Until emancipation | Full control | Age 18 (configurable) | Optional (other parent) |
| **Elderly Family Member** | Indefinite | Co-sign or full | None (manual revocation) | Recommended (family + attorney) |
| **Person with Disability** | Indefinite | Co-sign or full | None | Recommended |
| **Temporary Guardianship** | Time-limited | Scoped | Expiration date | Optional |

Custom guardianship types are deferred to a later release.

### Emancipation = Authority Transfer

When a dependent is emancipated (age trigger, manual action, or court order):

1. Guardian performs a final delegated rotation transferring signing authority to keys held solely by the dependent
2. Dependent's device performs a new inception to establish a standalone AID
3. The old delegated AID's KEL records the full chain of custody (provenance preserved)
4. Dependent transitions from Topology #2 → Topology #1 (Standalone)

### Contact Role Labels

Contacts involved in guardianship relationships display a directional role label:

| Viewer's Role | Label |
|---|---|
| I am their guardian | "You are guardian of [Name]" |
| They are my guardian | "[Name] is your guardian" |
| We are co-guardians | "Co-guardian with you for [Dependent Name]" |

### Navigation Placement

| Nav Location | Content |
|---|---|
| **Guardianship** (top-level collapsible section) | My Dependents, My Guardians (Coming Soon), Succession Plan (Coming Soon), Estate Management (Coming Soon) |
| **My Data > Family** (future, when My Data is implemented) | Read-only family tree, documents vault, succession status summary |

### Data Model

**GuardianshipRecord** stored in SQLite (`guardianships` table):

| Field | Type | Description |
|---|---|---|
| `id` | TEXT PK | UUID |
| `type` | TEXT | minor_child, elderly, disability, temporary |
| `guardian_aid` | TEXT | Guardian's AID prefix |
| `dependent_aid` | TEXT | Dependent's AID prefix |
| `dependent_name` | TEXT | Display name |
| `delegated_aid_prefix` | TEXT | KERI delegated AID prefix |
| `status` | TEXT | active, expired, revoked, emancipated |
| `hosting_type` | TEXT | cloud, device |
| `hosting_url` | TEXT | Infrastructure provider URL (if cloud) |
| `created_at` | TEXT | ISO 8601 timestamp |
| `updated_at` | TEXT | ISO 8601 timestamp |
| `emancipation_json` | TEXT | JSON: {type, value} |
| `co_guardians_json` | TEXT | JSON array of AID strings |
| `multisig_threshold` | INTEGER | Multi-sig threshold (0 = no multi-sig) |
| `metadata_json` | TEXT | JSON: template-specific fields |

### API Surface

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/guardianship` | List all guardianship relationships |
| `POST` | `/api/guardianship` | Create guardianship (triggers KERI delegation) |
| `GET` | `/api/guardianship/{id}` | Get guardianship detail |
| `PUT` | `/api/guardianship/{id}` | Update guardianship |
| `DELETE` | `/api/guardianship/{id}` | Revoke guardianship |
| `POST` | `/api/guardianship/{id}/emancipate` | Trigger emancipation |

### Future Phases (Not This ADR)

- **Succession Planning** — pre-rotation commitment, multi-sig key holder designation, credential triage configuration
- **Estate Management** — succession activation, credential triage execution, estate AID management
- **Custom Guardianship Types** — user-defined templates with custom parameters

---

## Consequences

1. **New SQLite table** (`guardianships`) added to the identity store via migration.
2. **Store interface extended** with guardianship CRUD methods.
3. **New REST API surface** under `/api/guardianship`.
4. **Desktop sidebar gains a "Guardianship" collapsible section** (ADR-018 canonical structure updated).
5. **Contact cards gain role labels** — directional guardianship badges alongside existing contact type badges.
6. **Identity Agent Infrastructure Service Provider** established as a new provider type in Settings > Service Providers (Grape ID default, additional providers configurable).
7. **One AID per instance rule** is now explicit policy — no same-device multi-AID.

---

## References

- ADR-006: Standardized Topology — 3 States × 2 Device Types
- ADR-014: Key Custody, Backend Server Mode, Migration, and Data Partitioning
- ADR-018: Desktop Navigation Structure
- Plan doc: `2. Plans/guardianship.md`
- Tasks: `1. Strategy/tasks.md` → "Guardianship" section
