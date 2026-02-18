# ADR 003: Adaptive Architecture — Three Operating Modes

**Date:** 2026-02-18
**Status:** Accepted
**Context:** Phase 2 (Inception) — adding mobile inception capabilities

## Decision

The Identity Agent supports three distinct operating modes, selected at runtime based on platform detection and configuration. Each mode uses a different combination of components to perform KERI protocol operations.

## Three Modes

### 1. Desktop Mode (default on Linux/macOS/Windows/Web)

```
Flutter UI → Go Backend (port 5000) → Python KERI Driver (port 9999/keripy)
```

- Go backend handles orchestration, persistence, and API serving
- Python KERI driver performs all KERI protocol operations using keripy v1.1.17
- Go spawns Python as a child process (development) or connects via KERI_DRIVER_URL (production)
- Full KERI capability — inception, rotation, signing, KEL management, credential issuance

### 2. Mobile Remote Mode (iOS/Android with PRIMARY_SERVER_URL configured)

```
Flutter UI → Remote Primary Server (user's server running Desktop Mode)
```

- Mobile device acts as a remote controller for the user's primary server
- All KERI operations are routed to the remote server's API
- The remote server runs Desktop Mode (Go + Python) and is the authoritative source
- Local Go backend on mobile enters Backup Mode or is stopped
- Full KERI capability — delegated to the remote server

### 3. Mobile Standalone Mode (iOS/Android without PRIMARY_SERVER_URL)

```
Flutter UI → Rust Bridge (FFI, local) + Remote Helper (stateless, public)
```

- Rust bridge (THCLab keriox/keri-core) handles all private key operations locally via FFI
- Go backend runs on mobile in Primary Mode but without Python driver
- Remote Helper is a separate public stateless service for formatting tasks
- Python KERI driver is NOT available — cannot run on mobile OS

## Trust Boundaries

### Primary Server (Mobile Remote Mode)
- **Trust level:** Full trust
- **Relationship:** User's own server, same software
- **Data access:** Full — handles all key material and KERI events
- **Authentication:** Server-to-device trust (to be implemented in Phase 3)

### Remote Helper (Mobile Standalone Mode)
- **Trust level:** Zero trust
- **Relationship:** Public utility service, not user-owned
- **Data access:** Public data only — credential formatting, OOBI resolution, multisig event structuring
- **Constraint:** NEVER receives private keys, signing keys, or sensitive identity material
- **Operations:** format-credential, resolve-oobi, generate-multisig-event

### Rust Bridge (Mobile Standalone Mode)
- **Trust level:** Full trust (runs locally on device)
- **Relationship:** Compiled native library linked via FFI
- **Data access:** Full — handles all private key operations
- **Operations:** incept_aid, rotate_aid, sign_payload, get_current_kel, verify_signature

## Environment Detection

Runtime detection logic (in `KeriService.detectEnvironment()`):

1. **Web platform** → Desktop Mode (always)
2. **Desktop OS** (Linux/macOS/Windows) → Desktop Mode
3. **Mobile OS** (Android/iOS) with `PRIMARY_SERVER_URL` set → Mobile Remote Mode
4. **Mobile OS** (Android/iOS) without `PRIMARY_SERVER_URL` → Mobile Standalone Mode

## Configuration

| Variable | Purpose | Mode |
|---|---|---|
| `CORE_URL` | Go backend URL (default: localhost:5000) | Desktop |
| `PRIMARY_SERVER_URL` | Remote server running Desktop Mode | Mobile Remote |
| `KERI_HELPER_URL` | Public stateless formatting service | Mobile Standalone |

## Key Design Decisions

- **KeriService abstraction:** All three modes implement the same Dart interface, allowing the UI to be mode-agnostic
- **Rust bridge uses THCLab/keriox:** EUPL-1.2 licensed, most mature Rust KERI implementation
- **Remote Helper is injected as dependency:** Not inherited from RemoteServerKeriService — distinct trust relationship
- **Go backend IS available on mobile:** Handles orchestration and persistence. Only the Python driver is absent.

## Consequences

- Flutter UI code is completely mode-agnostic — no platform-specific branching in screens
- Rust native compilation requires flutter_rust_bridge_codegen + native toolchains (Xcode/NDK) — done outside Replit
- Remote Helper URL must be configured before Mobile Standalone Mode can use formatting features
- Future: Go backend Primary/Backup mode switching is a separate backend concern, independent of KERI service layer
