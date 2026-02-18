# ADR 003: Adaptive Architecture — Three Operating Modes

**Date:** 2026-02-18
**Updated:** 2026-02-18
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
- Python KERI driver is always a local child process (never remote)
- Go spawns Python via `exec.Command()` and kills it on exit
- Full KERI capability — all 5 stateful + 3 stateless endpoints

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
Flutter UI → Rust Bridge (FFI, local stateful) + Stateless URL (external)
```

- Rust bridge (THCLab keriox/keri-core) handles all private key operations locally via FFI
- Go backend runs on mobile in Primary Mode but without Python driver
- Stateless operations use a configurable URL that can point to:
  - **External Primary Backend** (preferred) — user's own server running Desktop Mode
  - **Remote Helper** (fallback) — public stateless microservice when no external backend is available
- Python KERI driver is NOT available — cannot run on mobile OS

#### Stateless URL Resolution

On mobile standalone, stateless operations (format-credential, resolve-oobi, generate-multisig-event) need a server. The URL is resolved in this order:

1. If the Go backend is configured as an **external Primary Backend** (serves other devices), its public URL is used
2. If the backend is **internal** (default — only serves the local device), the **Remote Helper URL** (`KERI_HELPER_URL`) is used as fallback

The backend is internal by default. It becomes external when the user explicitly configures it as a Primary Backend during setup (allowing other devices to connect to it).

## Trust Boundaries

### Primary Server (Mobile Remote Mode)
- **Trust level:** Full trust
- **Relationship:** User's own server, same software
- **Data access:** Full — handles all key material and KERI events
- **Authentication:** Server-to-device trust (to be implemented in Phase 3)

### Remote Helper (Mobile Standalone fallback)
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

## Naming Convention

The Python KERI driver (`server.py`) defines the canonical endpoint paths. All other
components match the driver's naming:

| Python Driver Path | Rust Bridge Function | Dart Bridge Method | Type |
|---|---|---|---|
| `/inception` | `incept_aid()` | `inceptAid()` | Stateful |
| `/rotation` | `rotate_aid()` | `rotateAid()` | Stateful |
| `/sign` | `sign_payload()` | `signPayload()` | Stateful |
| `/kel` | `get_current_kel()` | `getCurrentKel()` | Stateful |
| `/verify` | `verify_signature()` | `verifySignature()` | Stateful |
| `/format-credential` | — (stateless, remote) | `formatCredential()` | Stateless |
| `/resolve-oobi` | — (stateless, remote) | `resolveOobi()` | Stateless |
| `/generate-multisig-event` | — (stateless, remote) | `generateMultisigEvent()` | Stateless |

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
| `KERI_HELPER_URL` | Public stateless Remote Helper URL | Mobile Standalone (fallback) |

## Consequences

- Flutter UI code is completely mode-agnostic — no platform-specific branching in screens
- All three modes implement the same `KeriService` abstract class
- Rust native compilation requires flutter_rust_bridge_codegen + native toolchains (Xcode/NDK) — done locally, not on Replit
- Stateless paths are identical between the Python driver, Go proxy, and Remote Helper
- Backend is internal by default; becomes external only when user configures it as a Primary Backend
