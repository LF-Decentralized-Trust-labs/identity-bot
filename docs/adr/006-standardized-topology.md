# ADR 006: Standardized Topology — Two Topologies, Four Configurations

**Date:** 2026-02-22 (revised 2026-05-01)
**Status:** Accepted (revised)
**Supersedes:** Mode definitions in ADR-003 and ADR-005; the original "3 states × 2 device types" formulation in this same ADR (2026-02-22).

## Revision Note (2026-08-22) — three corrections, and a third topology

This document described an implementation that no longer exists, and omitted one
that does. Anybody reading it to learn how the system works was being misled on
all three points.

**1. The `KeriService` class names below are wrong.** `DesktopOnDeviceKeriService`,
`MobileOnDeviceKeriService` and `MobileRemoteKeriService` do not exist in the
codebase. There is one implementation, `LocalCoreKeriService`, and every
configuration uses it — it talks to the local core over HTTP, and the core is
embedded on mobile and a child process on a desktop. The tables that name the
three classes are kept below with a correction beside them rather than deleted,
so a reader who saw an earlier revision can tell the model changed.

**2. There is no Rust bridge.** Mobile stateful KERI ran through a Rust FFI
bridge when this was written. It does not now: the Go core is the KERI engine on
every platform, embedded on mobile through `gomobile`. A second engine on one
platform is where a difference hides, and one did — the Rust bridge ignored the
recovery phrase and minted a random key, so a phone identity could not be
recovered from its words. Any fallback described below as "Rust bridge
unavailable" describes a component that is gone.

**3. A controller is a third topology, not a variant of the other two.** The two
topologies below both assume the device in front of you holds keys or is the
always-on machine. Neither covers the case that matters for a sealed computer
somebody rents: **an application that holds its own key and drives an identity
whose keys live on another machine.** It is described in full under
*Controller* below.

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
- Phone: the embedded Go core creates and manages the AID (`gomobile`). An earlier revision said a Rust bridge did this; it does not exist.

The remote/paired component is ONLY used for:
- Backend services (persistence, OOBI serving, contacts, tunneling)
- Stateless KERI operations (format-credential, resolve-oobi, generate-multisig-event)

**The remote/paired component NEVER performs stateful KERI operations on behalf of the local device.** This is the fundamental trust invariant of the architecture.

## KeriService Implementations

The 6-combination internal engineering model still exists at the code level, because Phone + Computer behaves differently depending on which device the identity was created on first (this determines which device holds the keys). The code-level mapping:

> **The three class names in this table do not exist.** One implementation,
> `LocalCoreKeriService`, serves every configuration; it reaches the local core
> over HTTP, embedded on mobile and a child process on a desktop. Kept for the
> shape of the argument, not as a guide to the code.

| Service Class | Used By | What It Does |
|---|---|---|
| `DesktopOnDeviceKeriService` | Configurations 3, 4 (Computer only — own or black box). Also runs on the computer side of Configurations 1 and 2 (Phone + Computer) when the phone is absent or as the backend. | Talks to local Go Core → Python keripy via HTTP. Same class for own computer and black box computer — the difference is the deployment target, not the code. |
| `MobileOnDeviceKeriService` | Phone in Configurations 1 and 2 when keys are on the phone (identity created on phone first). Also covers fully-local Phone-only mode (offline credential verification). | Rust bridge (FFI) for all stateful KERI ops. Embedded Go Core (gomobile) for local backend; paired server for backend when paired. The 3 stateless ops (`format-credential`, `resolve-oobi`, `generate-multisig-event`) go to the paired server if one is configured, otherwise to the public KERI microservice (`keri.grapeid.org`). |
| `MobileRemoteKeriService` | Phone in Configurations 1 and 2 when keys are on the computer (identity created on computer first). Also serves as the fallback when the Rust bridge fails to load on the phone. | Forwards ALL KERI operations to the paired server via HTTP. The Rust bridge is never used. |

### Auto-detection: where do the keys live?

In Phone + Computer topology, the user does not choose between "with keys" and "without keys" modes. Instead:

- **Identity created on phone first** → keys live on phone. Computer (own or black box) is added as paired backend. Phone uses `MobileOnDeviceKeriService(pairedServerUrl:)`.
- **Identity created on computer first** → keys live on computer. A device added later is a **controller** — see below. It does not forward stateful KERI operations to the computer; it holds its own key and acts under authority the identity granted it.

The two paths converge to the same UX from the user's perspective; only the implementation differs.

### Fallback Behavior

When the local KERI engine is unavailable (typically during development before native compilation):

- **Phone:** there is no such fallback, because there is no second engine to fall back from. The Go core is embedded through `gomobile` and is the only KERI engine on the device. An earlier revision described falling back to a remote service when a Rust bridge failed to load; that bridge no longer exists, and forwarding stateful operations to a paired server would break the trust invariant above rather than degrade gracefully.
- **Computer:** No fallback needed — Go+Python always available on Linux/macOS/Windows.

## Controller — the third topology

A **controller** is an installed application that holds its own key and operates
an identity whose keys live on another machine. It is not a thin proxy: it never
forwards stateful KERI operations, and the machine holding the identity never
signs on the strength of a request simply arriving.

It exists because the two topologies above both assume the device in front of
you is either where the keys live or the always-on machine. Neither describes
somebody sitting at a computer they do not own, operating an identity that lives
on a sealed machine elsewhere — which is the ordinary case for a rented
always-on computer, and the only case for somebody who has no phone.

### Two grades, because the machines differ

| Grade | For | What the identity issues | Lifetime |
|---|---|---|---|
| **Delegated** | a machine somebody keeps — their laptop, an organisation's desktop | a delegated AID, anchored in the identity's key event log | until revoked; visible in the device list |
| **Scoped** | a machine somebody borrowed — a library, a hotel, a colleague's desk | a scoped authorisation over the controller's own public key | expires; nothing permanent is written |

The distinction is not security theatre. A delegation is revocable and *visible*
— it is in a log a third party can read — which is what you want for a machine
that will still be yours next month. Writing one for a computer used once would
put a permanent device on an identity for a session that ended the same
afternoon, so the borrowed case is authorised without being enrolled.

### Rules

- **A controller holds a key, and that key is its own.** It is never handed the
  identity's key material. What it is given is authority to act, which can be
  taken away without touching the identity itself.
- **A controller runs only on hardware with a secure enclave** — the same bar an
  agent must meet. A device that cannot protect a key cannot hold one, and an
  authorisation granted to a key anybody can extract is an authorisation granted
  to anybody.
- **The device holding the identity decides.** Authority is granted by the party
  that holds the keys, and how strongly the person was authenticated at that
  moment is part of the decision — a borrowed machine can be made to require a
  stronger proof than one somebody uses daily.
- **It is an application, never a browser.** A page delivered by the machine it
  is meant to protect you against cannot be checked by the browser receiving it,
  and a browser has no enclave to hold a key in. Browser access is deferred
  entirely, as a single capability rather than a question re-asked for each
  feature.
- **Both kinds of identity use the same mechanism.** What differs is only where
  the application runs.

### What this does not change

The trust invariant above is unchanged and is the reason a controller is
described as authority rather than as a proxy: **the machine holding the keys
performs its own stateful KERI operations, always.** A controller asks; it does
not sign on the identity's behalf.

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
