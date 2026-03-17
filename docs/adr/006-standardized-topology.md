# ADR 006: Standardized Topology — 3 States × 2 Device Types

**Date:** 2026-02-22
**Status:** Accepted
**Supersedes:** Mode definitions in ADR-003 and ADR-005

## The Problem This Solves

ADR-003 described "Four Operating Modes" and ADR-005 described "Three Mobile Operating Modes." These overlapping mode definitions created confusion:

- ADR-003 listed Desktop, Mobile Standalone, Mobile Remote WITHOUT Keys, and Mobile Remote WITH Keys — four modes total, but the first was device-specific while the other three were topology-specific.
- ADR-005 correctly identified three mobile topologies but did not extend them to desktop.
- The term "mode" was overloaded — it sometimes meant device type, sometimes meant topology, sometimes meant both.

In reality, there are **3 fundamental topological states** that apply to **both device types** (desktop and mobile), giving 6 architectural combinations. This ADR standardizes the terminology.

## The Decision

### Three Topological States

Every Identity Agent instance is in exactly one of three topological states, regardless of whether it runs on a desktop or mobile device:

| State | Short Name | Description |
|---|---|---|
| **Standalone** | Root Keys + Backend Brain | The device holds the root AID keys AND runs all backend services (persistence, OOBI, contacts, tunneling) locally. Complete self-contained operation. |
| **Remote Controller WITHOUT Root Keys** | Delegated Device | The device creates a delegated child AID locally. It connects to a remote parent server for backend services and stateless operations. The parent server holds the root AID. |
| **Remote Controller WITH Root Keys** | Sovereign Controller | The device retains the primary parent AID and its root keys locally. It connects to a remote server for compute-heavy backend services. The server never receives private keys. |

### Two Device Types

| Device Type | KERI Engine | Backend Engine |
|---|---|---|
| **Desktop** (Linux, macOS, Windows) | Go backend → Python keripy (local child process) | Go Core (local binary) |
| **Mobile** (iOS, Android) | Rust bridge via flutter_rust_bridge FFI | Go Core via gomobile (embedded, platform channels) |

### 6 Architectural Combinations

| # | Device | Topology | KERI Engine | Backend | KeriService Implementation | How Entered |
|---|---|---|---|---|---|---|
| 1 | Desktop | Standalone | Go → Python keripy | Go Core (local) | `DesktopOnDeviceKeriService()` | "Create New Identity" on desktop |
| 2 | Desktop | Remote WITHOUT Keys | Go → Python keripy (local child AID) | Remote parent server | `DesktopOnDeviceKeriService()` + remote serverUrl passed to screens | "Connect to Existing" on desktop |
| 3 | Desktop | Remote WITH Keys | Go → Python keripy (primary AID) | Remote server for compute | `DesktopOnDeviceKeriService()` + remote serverUrl passed to screens | Migration from Desktop Standalone (planned) |
| 4 | Mobile | Standalone | Rust bridge (FFI) | Go Core (gomobile, embedded) | `MobileOnDeviceKeriService()` | "Create New Identity" on mobile |
| 5 | Mobile | Remote WITHOUT Keys | (none — all ops forwarded) | Remote parent server | `MobileRemoteKeriService(serverUrl:)` | "Connect to Existing" when Rust bridge unavailable |
| 6 | Mobile | Remote WITH Keys | Rust bridge (FFI, primary AID) | Remote parent server (stateless ops only) | `MobileOnDeviceKeriService(pairedServerUrl:)` | "Connect to Existing" when Rust bridge available |

### Critical Architecture Invariant

In ALL 6 combinations, **stateful KERI operations always use the LOCAL engine**:

- Desktop: Local Go+Python creates and manages the AID (whether root or child)
- Mobile: Local Rust bridge creates and manages the AID (whether root or child)

The remote parent server is ONLY used for:
- Backend services (persistence, OOBI serving, contacts, tunneling)
- Stateless KERI operations (format-credential, resolve-oobi, generate-multisig-event)

**The remote server NEVER performs stateful KERI operations on behalf of the local device.** This is the fundamental trust invariant of the architecture.

## KeriService Implementations

Service class naming follows the convention **`{Platform}{KeriLocation}KeriService`**: the platform first, then where KERI logic executes, then the suffix. This makes any class name self-documenting.

| Service Class | Used By | What It Does |
|---|---|---|
| `DesktopOnDeviceKeriService` | Combinations 1, 2, 3 | Talks to local Go Core → Python keripy via HTTP. Same class for all desktop topologies — the difference is which serverUrl the screens use for backend/stateless ops. |
| `MobileOnDeviceKeriService` | Combinations 4, 6 | Rust bridge (FFI) for all stateful KERI ops. Embedded Go Core (gomobile) for standalone backend; paired server for backend in Remote WITH Keys. The 3 stateless ops (`format-credential`, `resolve-oobi`, `generate-multisig-event`) go to the paired server if one is configured, otherwise to the public KERI microservice (`keri.grapeid.org`). |
| `MobileRemoteKeriService` | Combination 5 (and fallback) | Forwards ALL KERI operations to the paired server via HTTP. The Rust bridge is never used. Used when the device intentionally has no local keys (Remote WITHOUT Keys topology), or as a fallback when the Rust bridge fails to load. |

### Fallback Behavior

When the local KERI engine is unavailable (typically during development before native compilation):

- **Mobile + Rust bridge unavailable:** Falls back to `MobileRemoteKeriService`, which forwards all operations to the paired server. This breaks the trust invariant but keeps the app functional for development/testing.
- **Desktop:** No fallback needed — Go+Python always available on desktop platforms.

## Migration: Standalone → Remote Controller WITH Keys

The 9-step migration flow moves a device from Standalone to Remote Controller WITH Keys. This applies to both desktop and mobile, though the initial implementation targets mobile:

### Prerequisites

- Device is in Standalone topology with an active identity
- User has a remote server running Identity Agent in Desktop Standalone mode
- Network connectivity between device and server

### Steps

1. **User initiates migration** — Taps "Migrate to External Server" button on the dashboard (visible only in Standalone topology with an active identity).

2. **User enters remote server URL** — The app validates the server is reachable and running Identity Agent by calling `GET /api/health`.

3. **Server health confirmed** — The server responds with `status: "active"` and `agent: "identity-agent-core"`.

4. **Device exports public identity data** — The device's AID, public key, and current KEL are packaged for transfer. Private keys are NEVER included.

5. **Device sends public data to server** — The device calls the server's identity registration endpoint to establish itself as the primary identity the server will serve.

6. **Server acknowledges registration** — The server stores the device's public identity data and begins serving its OOBI.

7. **Device switches topology** — The app changes from Standalone to Remote Controller WITH Keys:
   - On mobile: Go Core (gomobile) is stopped. `MobileOnDeviceKeriService` is re-instantiated with `pairedServerUrl` set so stateless ops route to the paired server instead of the public microservice.
   - On desktop: No engine changes needed — `DesktopKeriService` continues to use local Go+Python for KERI, but screens switch to using the remote serverUrl for backend operations.

8. **Device persists new configuration** — The server URL and new topology are saved to SharedPreferences.

9. **Device verifies connection** — The app confirms it can reach the server and that the server is correctly serving the device's OOBI.

### Reversibility

Migration is designed to be reversible. The device retains its root keys and complete KEL locally. To revert:
- Mobile: Restart the embedded Go Core, switch back to `MobileStandaloneKeriService`
- Desktop: Stop using the remote server for backend ops, revert to fully local operation

## AgentEnvironment Enum Mapping

The existing `AgentEnvironment` enum maps to the topology model:

| Enum Value | Topology | Device |
|---|---|---|
| `desktop` | Standalone (default) | Desktop |
| `mobileStandalone` | Standalone | Mobile |
| `mobileRemoteWithoutKeys` | Remote WITHOUT Keys | Mobile |
| `mobileRemoteWithKeys` | Remote WITH Keys | Mobile |

Note: Desktop Remote topologies (combinations 2 and 3) currently report as `desktop` since `DesktopKeriService` always reports `AgentEnvironment.desktop`. A future change may add `desktopRemoteWithoutKeys` and `desktopRemoteWithKeys` enum values for more precise reporting.

## Consequences

- The 3-state topology model replaces the 4-mode model from ADR-003 and the 3-mode mobile model from ADR-005 as the authoritative terminology.
- All 6 architectural combinations use local KERI engines for stateful operations — this is the non-negotiable trust invariant.
- `MobileOnDeviceKeriService` covers both Standalone (combination 4) and Remote WITH Keys (combination 6) — the only difference is whether `pairedServerUrl` is set.
- `MobileRemoteKeriService` covers Remote WITHOUT Keys (combination 5) and serves as the fallback when the Rust bridge fails to load.
- Desktop "Connect to Existing" now correctly uses `DesktopKeriService()` (local Go+Python) instead of forwarding stateful operations to the remote server.
- Migration from Standalone → Remote WITH Keys is a planned feature with a defined 9-step process.
- The topology model naturally extends to future device types (tablets, embedded devices) without requiring new "modes."
