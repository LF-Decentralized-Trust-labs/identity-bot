# ADR 003: Adaptive Architecture — Three Operating Modes

**Date:** 2026-02-18
**Updated:** 2026-02-19
**Status:** Accepted
**Context:** Phase 2 (Inception) — enabling identity creation across all device types

## The Problem This Solves

The Identity Agent is software that people install on their own devices — laptops, servers, or phones. It uses a protocol called KERI to manage cryptographic identities. KERI operations (creating identities, rotating keys, signing data) require a KERI engine — a library that understands the protocol and does the math.

The best KERI engine available today is **keripy**, a Python library. Python runs fine on laptops and servers (Linux, macOS, Windows), but it **cannot run on phones** (iOS or Android). This creates a problem: how does the Identity Agent perform KERI operations on a phone?

The answer is **three operating modes**. Each mode is a different strategy for connecting the Identity Agent's user interface to a KERI engine, depending on what the device is capable of running:

| Mode | When it's used | How KERI operations happen |
|---|---|---|
| **Desktop Mode** | Laptops, servers (Linux/macOS/Windows) | Python keripy runs locally on the same machine |
| **Mobile Remote Mode** | Phones connected to a personal server | Phone sends requests to the user's own server, which runs keripy |
| **Mobile Standalone Mode** | Phones with no personal server | A Rust KERI library runs directly on the phone |

All three modes present the same user interface. The user doesn't need to know which mode is active — the app detects it automatically based on the device and configuration.

## How Each Mode Works

### Mode 1: Desktop Mode

**Used on:** Linux, macOS, and Windows — any operating system that can run Python.

**What happens:** The full Identity Agent stack runs on a single machine. The Go backend starts up, launches a Python process running keripy as a child process, and the two communicate over a local HTTP connection. The Flutter user interface talks to the Go backend, which forwards KERI requests to the Python process.

```
┌─────────────────────────────────────────────────────┐
│  User's Computer (Linux, macOS, or Windows)         │
│                                                     │
│  Flutter UI ──→ Go Backend ──→ Python KERI Driver   │
│                 (port 5000)    (port 9999, local)    │
│                                                     │
│  Everything runs on one machine.                    │
│  Python is always a child process of Go.            │
└─────────────────────────────────────────────────────┘
```

- The Go backend handles API requests, data storage, and orchestration.
- The Python KERI driver handles all cryptographic KERI operations using keripy.
- Go spawns the Python process automatically on startup and shuts it down on exit.
- The Python driver only listens on `127.0.0.1:9999` (localhost) — it is never exposed to the network.
- All 9 KERI endpoints are available: 1 health check, 5 stateful, 3 stateless.

**Note about the web build:** The Flutter UI can also be compiled as a web app. When it is, the Go backend serves it as static files. The web UI runs in the user's browser, but the Go + Python backend still runs on a Linux/macOS/Windows machine. So the web build is really just Desktop Mode accessed through a browser rather than a native app window.

### Mode 2: Mobile Remote Mode

**Used on:** iOS or Android phones, when the user has configured `PRIMARY_SERVER_URL` to point to their own server.

**What happens:** The user has a personal server somewhere (a laptop, a home server, a cloud VM) running the Identity Agent in Desktop Mode. Their phone connects to that server over the network. The phone's Flutter UI sends all KERI requests to the remote server's API. The phone itself does not run any KERI engine — it's acting as a remote control for the server.

```
┌───────────────────┐         ┌──────────────────────────────────┐
│  User's Phone     │         │  User's Server (Desktop Mode)    │
│  (iOS / Android)  │         │                                  │
│                   │  HTTPS  │  Go Backend ──→ Python KERI      │
│  Flutter UI ──────┼────────→│  (port 5000)    Driver (9999)    │
│                   │         │                                  │
│  No KERI engine   │         │  All KERI work happens here.     │
│  on the phone.    │         │  User owns and controls this.    │
└───────────────────┘         └──────────────────────────────────┘
```

- The phone acts as a remote controller for the user's own server.
- All KERI operations are performed by the server's Python keripy instance.
- The user must own and control the remote server — it has full access to their keys.
- This mode requires network connectivity between the phone and the server.

### Mode 3: Mobile Standalone Mode

**Used on:** iOS or Android phones, when the user has **not** configured `PRIMARY_SERVER_URL` (no personal server available).

**What happens:** The phone runs KERI operations locally using a Rust library (keriox by THCLab) instead of Python keripy. The Rust code is compiled into the app as a native library and called through FFI (Foreign Function Interface — a way for Dart code to call Rust code directly). This handles all sensitive operations like key creation and signing.

However, some KERI operations are "stateless" — they don't involve private keys and are just formatting or parsing tasks. These stateless operations are sent to an external server because they don't need to be trusted with secrets. The external server is either the user's own backend (if they've made it publicly accessible) or a public helper service.

```
┌──────────────────────────────────────────────┐
│  User's Phone (iOS / Android)                │
│                                              │
│  Flutter UI ──→ Rust Bridge (FFI)            │
│                 Handles private key           │
│                 operations locally.           │
│                                              │        ┌──────────────────┐
│  For stateless tasks ────────────────────────┼──────→ │ External Server  │
│  (formatting, parsing — no secrets)          │        │ (zero trust)     │
│                                              │        └──────────────────┘
└──────────────────────────────────────────────┘
```

- The Rust bridge handles 5 stateful (security-sensitive) operations locally on the phone.
- Stateless operations (3 endpoints: format-credential, resolve-oobi, generate-multisig-event) are sent to an external server.
- The Rust library is compiled locally by the developer using native toolchains (Xcode for iOS, Android NDK for Android). This compilation does not happen on Replit.

**Which external server handles stateless operations?**

The app decides which server to use for stateless work in this order:

1. **User's own Go backend, if it's publicly accessible** (preferred) — If the user has configured their Go backend as an external-facing "Primary Backend" (meaning other devices can reach it over the network), its public URL is used. This is ideal because the user controls it.
2. **Public Remote Helper service** (fallback) — If the Go backend is only running locally on the phone (internal mode, the default), a public helper service at `KERI_HELPER_URL` is used instead. This helper is a stateless utility that never sees private keys — it only does formatting and parsing.

The Go backend is internal (serves only the local device) by default. It becomes external only when the user explicitly configures it as a Primary Backend during initial setup.

## How the App Chooses a Mode

The Flutter app detects the mode automatically at startup. No user action is needed — the logic runs in `KeriService.detectEnvironment()`:

1. **Is this a desktop operating system?** (Linux, macOS, Windows, or web browser) → **Desktop Mode**
2. **Is this a phone (iOS/Android) with `PRIMARY_SERVER_URL` configured?** → **Mobile Remote Mode**
3. **Is this a phone (iOS/Android) without `PRIMARY_SERVER_URL`?** → **Mobile Standalone Mode**

The user interface code doesn't know or care which mode is active. All three modes implement the same set of operations through a shared interface (`KeriService`), so screens and buttons work identically regardless of mode.

## Trust Boundaries

Different components in the system have different levels of trust, depending on who controls them and what data they can see:

### User's Own Server (used in Desktop Mode and Mobile Remote Mode)
- **Trust level:** Full trust — the user owns and operates this machine.
- **Access:** Handles private keys, signing operations, and the full Key Event Log.
- **Why it's trusted:** It's the user's own hardware running their own software.

### Rust Bridge (used in Mobile Standalone Mode)
- **Trust level:** Full trust — it runs directly on the user's phone.
- **Access:** Handles private key creation, signing, and key rotation locally.
- **Why it's trusted:** The code is compiled into the app and never sends private data elsewhere.

### Remote Helper (fallback in Mobile Standalone Mode)
- **Trust level:** Zero trust — this is a public service the user does not control.
- **Access:** Only receives public data for formatting and parsing. Never sees private keys.
- **Operations:** format-credential, resolve-oobi, generate-multisig-event.
- **Why it's not trusted:** It's a public utility. The system is designed so that even if this service were compromised, no private identity data would be at risk.

## Endpoint Naming Convention

The Python KERI driver (`server.py`) defines the canonical names for all endpoints. Every other component — the Rust bridge, the Dart services, the Go proxy — uses matching names so they are interchangeable:

| Python Driver Path | Rust Bridge Function | Dart Service Method | Type |
|---|---|---|---|
| `/inception` | `incept_aid()` | `inceptAid()` | Stateful |
| `/rotation` | `rotate_aid()` | `rotateAid()` | Stateful |
| `/sign` | `sign_payload()` | `signPayload()` | Stateful |
| `/kel` | `get_current_kel()` | `getCurrentKel()` | Stateful |
| `/verify` | `verify_signature()` | `verifySignature()` | Stateful |
| `/format-credential` | — (handled by server) | `formatCredential()` | Stateless |
| `/resolve-oobi` | — (handled by server) | `resolveOobi()` | Stateless |
| `/generate-multisig-event` | — (handled by server) | `generateMultisigEvent()` | Stateless |

"Stateful" means the operation involves private keys or identity state that must stay on a trusted device. "Stateless" means the operation is pure data formatting — no secrets involved, safe to delegate to any server.

## Configuration Variables

| Variable | What it does | Which mode uses it |
|---|---|---|
| `CORE_URL` | URL of the local Go backend (default: `http://localhost:5000`) | Desktop Mode |
| `PRIMARY_SERVER_URL` | URL of the user's remote server running Desktop Mode | Mobile Remote Mode |
| `KERI_HELPER_URL` | URL of the public stateless Remote Helper service | Mobile Standalone Mode (fallback only) |

## Consequences

- The Flutter UI is completely mode-agnostic — screen code never checks which mode is active.
- All three modes implement the same abstract `KeriService` interface with 5 stateful + 3 stateless methods.
- Rust native compilation (for Mobile Standalone) requires local developer toolchains (Xcode for iOS, Android NDK for Android) and does not happen on Replit.
- The Python driver's endpoint paths are the single source of truth — all other components match them exactly.
- The Go backend defaults to internal mode (serving only the local device). It only becomes externally accessible when the user explicitly configures it during setup.
