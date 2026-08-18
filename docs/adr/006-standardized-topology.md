# ADR 006: Standardized Topology — Two Topologies, Four Configurations

**Date:** 2026-02-22 (revised 2026-05-01)
**Status:** Accepted (revised)
**Supersedes:** Mode definitions in ADR-003 and ADR-005; the original "3 states × 2 device types" formulation in this same ADR (2026-02-22).

## Revision Note (2026-05-01)

The original ADR-006 defined 3 topological states × 2 device types = 6 architectural combinations. That model was structurally accurate but proved too complex for users and contributors to internalize. This revision collapses it into **two topologies** with **four launch configurations**, mapping cleanly to consumer language ("phone with a computer, or computer only — and the computer can be yours or one we provide that's sealed").

Vocabulary update: "Sealed Infrastructure" / "Sealed Desktop" are retired in favor of **"black box infrastructure"** (engineering / architecture term) and **"black box computer"** (consumer-facing noun). See doctrine D10 in `architecture-doctrines.md`.

The 6-combination engineering model is preserved internally as `KeriService` implementation choices, but is no longer the primary mental model for the project.

## The Decision

### Two Topologies

Every Identity Agent instance is in exactly one of two topologies:

| Topology | Description |
|---|---|
| **Phone + Computer** | Identity created on the phone; keys live on the phone. The phone pairs with a computer that handles storage, computing, and always-on services. |
| **Computer only** | Identity and keys live on the computer. No phone required. |

In either topology, the **computer** can be the user's own (laptop, desktop, mini-PC) or a **black box computer** — professionally managed in a data center, sealed via TEE attestation so even the operator cannot read into it. Internal architecture term: **black box infrastructure** (D10).

### Four Launch Configurations

| # | Topology | Computer | Who it suits |
|---|---|---|---|
| 1 | Phone + Computer | Black box computer (data center) | **Most common at launch.** 60-second setup, no hardware to maintain, always-on. The default. |
| 2 | Phone + Computer | Own computer | Willing to leave a laptop/desktop on 24/7 and maintain it. Wants control of hardware. |
| 3 | Computer only | Own computer | Power users, privacy maximalists, people without smartphones, single-device households. |
| 4 | Computer only | Black box computer | No smartphone *and* no personal computer. Needs 24/7 service. Elderly, accessibility-constrained, regions where smartphones aren't practical. |

**Future:** Personal black box infrastructure (single- or multi-tenant TEE hardware operated by you, family, neighbor, or community steward — same protocol, different operator). Backup is orthogonal — any configuration can mirror to a second computer.

### Two Device Types (engineering view)

| Device Type | KERI Engine | Backend Engine |
|---|---|---|
| **Computer** (Linux, macOS, Windows) | Go backend → Python keripy (local child process) | Go Core (local binary) |
| **Phone** (iOS, Android) | Go Core via gomobile (embedded, platform channels) | Go Core via gomobile (embedded, platform channels) |

### Critical Architecture Invariant

In every configuration, **stateful KERI operations always use the LOCAL engine**:

- Computer: Local Go+Python creates and manages the AID
- Phone: Local Rust bridge creates and manages the AID

The remote/paired component is ONLY used for:
- Backend services (persistence, OOBI serving, contacts, tunneling)
- Stateless KERI operations (format-credential, resolve-oobi, generate-multisig-event)

**The remote/paired component NEVER performs stateful KERI operations on behalf of the local device.** This is the fundamental trust invariant of the architecture.

## KeriService Implementations

The 6-combination internal engineering model still exists at the code level, because Phone + Computer behaves differently depending on which device the identity was created on first (this determines which device holds the keys). The code-level mapping:

| Service Class | Used By | What It Does |
|---|---|---|
| `DesktopOnDeviceKeriService` | Configurations 3, 4 (Computer only — own or black box). Also runs on the computer side of Configurations 1 and 2 (Phone + Computer) when the phone is absent or as the backend. | Talks to local Go Core → Python keripy via HTTP. Same class for own computer and black box computer — the difference is the deployment target, not the code. |
| `MobileOnDeviceKeriService` | Phone in Configurations 1 and 2 when keys are on the phone (identity created on phone first). Also covers fully-local Phone-only mode (offline credential verification). | Rust bridge (FFI) for all stateful KERI ops. Embedded Go Core (gomobile) for local backend; paired server for backend when paired. The 3 stateless ops (`format-credential`, `resolve-oobi`, `generate-multisig-event`) go to the paired server if one is configured, otherwise to the public KERI microservice (`keri.grapeid.org`). |
| `MobileRemoteKeriService` | Phone in Configurations 1 and 2 when keys are on the computer (identity created on computer first). Also serves as the fallback when the Rust bridge fails to load on the phone. | Forwards ALL KERI operations to the paired server via HTTP. The Rust bridge is never used. |

### Auto-detection: where do the keys live?

In Phone + Computer topology, the user does not choose between "with keys" and "without keys" modes. Instead:

- **Identity created on phone first** → keys live on phone. Computer (own or black box) is added as paired backend. Phone uses `MobileOnDeviceKeriService(pairedServerUrl:)`.
- **Identity created on computer first** → keys live on computer. Phone (added later) is a thin controller. Phone uses `MobileRemoteKeriService(serverUrl:)`.

The two paths converge to the same UX from the user's perspective; only the implementation differs.

### Fallback Behavior

When the local KERI engine is unavailable (typically during development before native compilation):

- **Phone + Rust bridge unavailable:** Falls back to `MobileRemoteKeriService`, which forwards all operations to the paired server. This breaks the trust invariant but keeps the app functional for development/testing.
- **Computer:** No fallback needed — Go+Python always available on Linux/macOS/Windows.

## Migration Between Configurations

Migration between configurations is reversible and reuses the same primitives.

### Prerequisites

- Source device is in any active configuration with an active identity
- Target configuration's hardware is provisioned (e.g., a black box computer is reserved, or a new own-computer install is ready)
- Network connectivity between source and target

### Steps (high level)

1. **User initiates migration** — Selects the target configuration from the dashboard (e.g., "Move to a black box computer").
2. **Target hardware health confirmed** — The target responds with `status: "active"` and `agent: "identity-agent-core"`.
3. **Device exports public identity data** — AID, public key, current KEL packaged for transfer. Private keys are NEVER included if keys must remain on the source.
4. **Device sends public data to target** — Establishes target as the new backend (or new key holder, depending on direction).
5. **Target acknowledges registration** — Stores the device's public identity data and begins serving its OOBI.
6. **Source switches topology / configuration** — `KeriService` is re-instantiated for the new layout (e.g., `MobileOnDeviceKeriService` re-instantiated with `pairedServerUrl` set when adding a black box computer to a previously phone-only setup).
7. **Persist new configuration** — Server URL and new configuration saved to SharedPreferences.
8. **Verify connection** — Confirm reachability and OOBI continuity.

### Reversibility

Migration is designed to be reversible. The source device retains its root keys and complete KEL locally (when keys must stay with the user). To revert: stop using the new backend, switch the `KeriService` back, fall back to fully local operation.

## AgentEnvironment Enum Mapping

The existing `AgentEnvironment` enum maps to the new model:

| Enum Value | Configuration | Device |
|---|---|---|
| `desktop` | Computer only (Configurations 3, 4) — deployment target distinguishes own vs. black box | Computer |
| `mobileStandalone` | Phone-only fallback / offline-credential-verification mode within Phone + Computer | Phone |
| `mobileRemoteWithoutKeys` | Phone in Configurations 1, 2 when keys are on the computer | Phone |
| `mobileRemoteWithKeys` | Phone in Configurations 1, 2 when keys are on the phone | Phone |

Note: The enum continues to expose the engineering model. Consumer-facing UI does not surface these values.

## Consequences

- The two-topology + four-configuration model replaces the 6-combination model as the **primary** terminology for users, contributors, and documentation.
- The 6-combination engineering view persists internally as `KeriService` implementation choices and `AgentEnvironment` enum values — but is no longer the project's main mental model.
- All configurations use local KERI engines for stateful operations — non-negotiable trust invariant.
- "Black box computer" replaces "Sealed Desktop" in consumer copy. "Black box infrastructure" replaces "Sealed Infrastructure" in engineering / architecture docs.
- Migration between configurations is one workflow with multiple targets, not a separate "Standalone → Remote WITH Keys" special case.
- Future device types (tablets, embedded devices, wearables) extend the model by adding new device entries to the engineering table; the topology model itself does not change.
