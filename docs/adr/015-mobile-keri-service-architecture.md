# ADR-015: Mobile KERI Service Architecture

**Status:** Accepted
**Date:** 2026-03-16
**Related:** ADR-004 (FFI Bridge), ADR-006 (Standardized Topology — revised 2026-05-01), ADR-002 (KERI Driver Pattern)

## Context

ADR-006 (revised 2026-05-01) defines two topologies (Phone + Computer, Computer only) with four launch configurations; the original 6-combination engineering model is preserved internally as `KeriService` implementation choices. ADR-004 established the Rust bridge (flutter_rust_bridge) and Go Mobile Core (gomobile) as the two phone-side native integrations. This ADR documents three decisions made during the March 2026 mobile KERI implementation:

1. **keri_core v0.11 capability constraints** — what operations can and cannot be implemented locally on mobile
2. **Service class consolidation** — how the mobile KeriService classes map to topologies
3. **Naming convention** — how all KERI service classes are named

## Decision

### 1. keri_core v0.11 Capability Constraints

The Rust KERI library (`keri_core` v0.11) does NOT include ACDC (Authentic Chained Data Container) or SAID (Self-Addressing IDentifier) support. These algorithms cannot be implemented in the Rust bridge on mobile, and implementing them in Dart directly causes signing failures (proven by attempted implementation).

**Affected operations:** `format-credential`, `resolve-oobi`, `generate-multisig-event`

These three operations are **stateless** — they transform inputs but do not mutate AID state or require private keys. This makes them safe to delegate to a remote service.

**The delegation rule:**

| Operation type | Where it runs |
|---|---|
| Stateful KERI (inception, rotation, interaction, signing, verification) | Locally, always — Rust bridge |
| The 3 stateless ops (format-credential, resolve-oobi, generate-multisig-event) | Remotely — paired server if configured, otherwise public KERI microservice |

**Public KERI microservice:** `https://keri.grapeid.org` — serves `/health`, `/format-credential`, `/resolve-oobi`, `/generate-multisig-event`. URL can be overridden at compile time via the `KERI_SERVICE_URL` env variable (see `AgentConfig.publicKeriServiceUrl`).

**Priority:** If a paired server URL is configured, the 3 stateless ops go there. The public microservice is the fallback for standalone mode only.

### 2. Rust Bridge Extensions

Two functions were added to `keri_bridge.rs` to support mobile KERI feature parity:

**`interact_aid(name, seal_data_json) → InteractResult`**
Creates a KERI interaction (IXN) event anchoring seal data in the KEL. Returns raw event bytes for the caller to sign. Fully supported by keri_core v0.11.

**`cesr_encode(raw_sig_b64) → String`**
CESR-encodes a raw 64-byte Ed25519 signature into `0B...` format (88 chars). Algorithm:
1. Base64-decode → 64 raw bytes
2. Prepend 2 zero lead bytes → 66 bytes
3. Base64url-encode (no padding) → 88 chars
4. Replace first 2 chars with `0B`

This is a pure encoding transform — no KERI protocol computation, no private keys. It is safe to implement in Rust without keri_core ACDC support.

**Type mapping:** `InteractResult.sequence_number` is declared `i64` in Rust. FRB v2 maps `u64 → BigInt` in Dart (not assignable to `int`); `i64 → int` directly. Using `i64` avoids a runtime type cast failure.

### 3. Go Core Storage Endpoints for Mobile

Three new Go Core endpoints were added to support mobile receipt and credential persistence without requiring the Python KERI driver (which is disabled on mobile):

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/store/receipt` | POST | Store a validated witness receipt |
| `/api/store/receipts` | GET | Retrieve receipts for an event SAID; includes `threshold_met` |
| `/api/store/credential` | POST | Store an issued ACDC credential |

These endpoints are additive — existing desktop routes are unchanged.

### 4. Service Class Consolidation

The original 4-class mobile service design (`MobileStandaloneKeriService`, `MobileRemoteKeriService`, `RemoteServerKeriService`, and implicit standalone-only paths) was consolidated into 2 classes, recognizing that the meaningful distinction is **where private keys live** — not which topology label applies.

**Before:**
- `MobileStandaloneKeriService` — Standalone topology only
- `MobileRemoteKeriService` — Remote WITH Keys (the old meaning was actually closer to "paired but has bridge")
- `RemoteServerKeriService` — fallback / Remote WITHOUT Keys

**After:**
- `MobileOnDeviceKeriService` — device holds keys; covers Standalone (combinations 4) AND Remote WITH Keys (combination 6)
- `MobileRemoteKeriService` — device has no local keys; all ops to paired server (combination 5 + fallback)

The two classes differ only in which URL handles the 3 stateless ops and whether Go Core is started locally. Both use the same Rust bridge for all stateful operations.

### 5. Service Class Naming Convention

All KERI service classes follow the convention:

```
{Platform}{KeriLocation}KeriService
```

| Segment | Values | Meaning |
|---|---|---|
| Platform | `Desktop` / `Mobile` | Which device type the class targets |
| KeriLocation | `OnDevice` / `Remote` | Where KERI cryptography executes |
| Suffix | `KeriService` | Always present |

**Result:**

| Class | Platform | KERI runs at | File |
|---|---|---|---|
| `DesktopOnDeviceKeriService` | Desktop | Local Go + Python keripy | `desktop_on_device_keri_service.dart` |
| `MobileOnDeviceKeriService` | Mobile | Local Rust bridge | `mobile_on_device_keri_service.dart` |
| `MobileRemoteKeriService` | Mobile | Remote paired server | `mobile_remote_keri_service.dart` |

Reading any class name left to right tells you the platform and where cryptography happens. No external documentation is needed to understand what a class does.

## Instantiation Logic (`main.dart`)

```dart
if (mode == AgentMode.connectExisting && serverUrl != null) {
  if (KeriBridge.isAvailable) {
    // Topology #6: Remote WITH Keys — Rust bridge + paired server for stateless ops
    _keriService = MobileOnDeviceKeriService(pairedServerUrl: serverUrl);
  } else {
    // Topology #5 fallback: Remote WITHOUT Keys — forward everything
    _keriService = MobileRemoteKeriService(serverUrl: serverUrl);
  }
} else {
  // Topology #4: Standalone — Rust bridge + public microservice for stateless ops
  _keriService = MobileOnDeviceKeriService();  // pairedServerUrl = null → uses public
}
```

## Consequences

**Positive:**
- Service class names are self-documenting: read left to right to know platform + where KERI runs
- Two classes instead of three eliminate an artificial distinction between topologies that share the same Rust bridge implementation
- The 3 stateless ops cleanly separate from stateful ops — adding future keri_core ACDC support would simply remove the delegation without changing the class interface
- All 6 previously `UnimplementedError`-throwing methods are now fully implemented across all mobile services

**Negative:**
- `MobileOnDeviceKeriService` serves two topologies (#4 and #6); the `pairedServerUrl` parameter implicitly controls which topology is active. This is a slight violation of single-responsibility but justified by the fact that the implementation is identical — only the URL differs.
- The public KERI microservice (`keri.grapeid.org`) must be kept in sync with the desktop Python driver endpoints. If the driver's API changes, the public service must be updated separately.
- `MobileRemoteKeriService` (Remote WITHOUT Keys) breaks the trust invariant: the remote server performs stateful KERI ops on behalf of the device. This is documented and acceptable only as a fallback when the Rust bridge cannot load.

## References

- [ADR-004](004-ffi-bridge-and-ci-pipeline.md) — Rust bridge and Go Mobile Core
- [ADR-006](006-standardized-topology.md) — 3 States × 2 Device Types topology model
- [ADR-002](002-keri-driver-pattern.md) — Python driver endpoint canonical names
- `identity_agent_ui/rust/src/api/keri_bridge.rs` — Rust bridge implementation
- `identity_agent_ui/lib/services/mobile_on_device_keri_service.dart`
- `identity_agent_ui/lib/services/mobile_remote_keri_service.dart`
- `identity_agent_ui/lib/config/agent_config.dart` — `publicKeriServiceUrl`
- `identity-agent-core/server/store_handlers.go` — mobile storage endpoints
