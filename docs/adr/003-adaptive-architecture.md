# ADR 003: Adaptive Architecture — Four Operating Modes

**Date:** 2026-02-18
**Updated:** 2026-02-22
**Status:** Superseded in part by ADR-006 (mode definitions, 2026-05-01) and by
ADR-037 (2026-08-18) — every reference below to a Rust bridge on mobile is
historical. That engine is removed; mobile runs the embedded Go core.
**Context:** Phase 3 (Connectivity) — OOBI serving, contact management, and tunneling

> **Note:** The four-mode model described in this ADR has been superseded twice: first by the 3-state × 2-device-type model in ADR-006 (2026-02-22), then by the two-topology + four-configuration model in ADR-006's 2026-05-01 revision. This ADR remains the authoritative source for OOBI serving, contact management, tunneling, endpoint naming conventions, trust boundaries, and configuration variables. The terms "Mobile Standalone," "Mobile Remote WITHOUT Keys," and "Mobile Remote WITH Keys" used below are historical — the current model is "Phone + Computer" / "Computer only" (with auto-detection of key location). See ADR-006 for the current architectural topology.

## The Problem This Solves

The Identity Agent is software that people install on their own devices — laptops, servers, or phones. It uses a protocol called KERI to manage cryptographic identities. KERI operations (creating identities, rotating keys, signing data) require a KERI engine — a library that understands the protocol and does the math.

The best KERI engine available today is **keripy**, a Python library. Python runs fine on laptops and servers (Linux, macOS, Windows), but it **cannot run on phones** (iOS or Android). This creates a problem: how does the Identity Agent perform KERI operations on a phone?

The answer is **four operating modes**. Each mode is a different strategy for connecting the Identity Agent's user interface to a KERI engine and backend services, depending on what the device is capable of running and how the user configures their setup:

| Mode | When it's used | How KERI operations happen | How backend services work |
|---|---|---|---|
| **Desktop Mode** | Laptops, servers (Linux/macOS/Windows) | Python keripy runs locally on the same machine | Go Core runs locally |
| **Mobile Standalone Mode** | Phones with no personal server ("Create New Identity" onboarding) | Rust KERI bridge runs directly on the phone via FFI | Go Core runs embedded on the phone via gomobile platform channels |
| **Mobile Remote Controller WITHOUT Keys** | Phones connecting to an existing server ("Connect to Existing Identity" onboarding) | Rust bridge creates a delegated child AID locally; remote server handles parent AID operations | Remote server provides backend services |
| **Mobile Remote Controller WITH Keys** | Phones migrated from Standalone mode ("Migrate to External Server" dashboard button) | Rust bridge manages the primary parent AID locally (keys stay on phone) | Remote server provides compute-heavy backend services |

All four modes present the same user interface through the abstract `KeriService` interface. The user chooses their mode during onboarding (or via migration), and the app configures the correct service implementation.

## How Each Mode Works

### Mode 1: Desktop Mode

**Used on:** Linux, macOS, and Windows — any operating system that can run Python.

**What happens:** The full Identity Agent stack runs on a single machine. The Go backend starts up, launches a Python process running keripy as a child process, and the two communicate over a local HTTP connection. The Flutter user interface talks to the Go backend, which forwards KERI requests to the Python process.

```
┌─────────────────────────────────────────────────────┐
│  User's Computer (Linux, macOS, or Windows)         │
│                                                     │
│  Flutter UI ──→ Go Backend ──→ Python KERI Driver   │
│                 (port 5050)    (port 9999, local)    │
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

### Mode 2: Mobile Standalone Mode

**Used on:** iOS or Android phones, when the user chooses "Create New Identity" during onboarding.

**What happens:** This is the primary mobile onboarding path. BOTH the Rust KERI bridge AND the Go Core backend run locally on the phone:

- **Rust bridge** (`keriox/keri-core` via `flutter_rust_bridge` FFI) handles all cryptographic KERI operations (inception, rotation, signing, verification, KEL retrieval) directly on the device.
- **Go Core** (compiled via gomobile into `.aar` for Android and `.xcframework` for iOS) runs as an embedded server on the phone, providing data persistence, OOBI serving, contact management, and tunneling. It communicates with the Flutter layer through platform channels (Kotlin `MethodChannel` on Android, Swift `FlutterMethodChannel` on iOS).

The Go Core's KERI driver is **disabled** on mobile (`ServerConfig.EnableKeriDriver = false`). All crypto operations go through the Rust bridge instead, while the Go Core provides everything else.

```
┌────────────────────────────────────────────────────┐
│  User's Phone (iOS / Android)                      │
│                                                    │
│  Flutter UI ──→ Rust Bridge (FFI)                  │
│  │               Handles KERI crypto locally:      │
│  │               inception, rotation, signing,     │
│  │               verification, KEL retrieval.      │
│  │                                                 │
│  └─→ Go Core (gomobile, via platform channels)     │
│       Handles backend services locally:            │
│       data persistence, OOBI serving,              │
│       contact management, tunneling.               │
│       KERI driver DISABLED.                        │
│                                                    │
│  Both engines run entirely on the phone.           │
│  No external server required.                      │
└────────────────────────────────────────────────────┘
```

- The `MobileStandaloneKeriService` coordinates between the Rust bridge (for KERI) and Go Core (for persistence).
- After inception via the Rust bridge, the service stores the identity and events in Go Core's file-based JSON store.
- The `MobileCoreService` Dart wrapper manages starting/stopping the Go Core via platform channels.
- For stateless operations (format-credential, resolve-oobi, generate-multisig-event), the embedded Go Core or a public Remote Helper service at a configured URL handles them.

### Mode 3: Mobile Remote Controller WITHOUT Keys

**Used on:** iOS or Android phones, when the user chooses "Connect to Existing Identity" during onboarding.

**What happens:** The user has a personal server somewhere (a laptop, a home server, a cloud VM) running the Identity Agent in Desktop Mode. Their phone connects to that server by entering the server's URL during onboarding. The Rust bridge creates a **delegated child AID** locally — the phone holds only the child AID's keys, while the parent AID and its keys remain on the remote server.

Backend operations (data persistence, OOBI serving, contacts) are handled by the remote server. The phone is acting as a remote controller with a limited, delegated identity.

```
┌───────────────────────────┐       ┌──────────────────────────────────┐
│  User's Phone             │       │  User's Server (Desktop Mode)    │
│  (iOS / Android)          │       │                                  │
│                           │ HTTPS │  Go Backend ──→ Python KERI      │
│  Rust Bridge (FFI)        │──────→│  (port 5050)    Driver (9999)    │
│  Creates delegated child  │       │                                  │
│  AID locally. Phone has   │       │  Parent AID and full KEL live    │
│  child keys only.         │       │  here. User owns and controls    │
│                           │       │  this server.                    │
│  Remote server provides   │       │                                  │
│  backend services.        │       │                                  │
└───────────────────────────┘       └──────────────────────────────────┘
```

- Entered via "Connect to Existing Identity" onboarding flow.
- The `RemoteServerKeriService` forwards backend operations to the remote server.
- The Rust bridge is always initialized on mobile for local key management.
- The user must own and control the remote server.
- Network connectivity between phone and server is required.

### Mode 4: Mobile Remote Controller WITH Keys

**Used on:** iOS or Android phones, migrated from Mobile Standalone Mode.

**What happens:** The user initially set up their identity in Standalone Mode (all local). They later decide to offload compute-heavy backend operations to an external server while keeping their primary parent AID and keys on the phone. This is reached via the "Migrate to External Server" button on the dashboard (visible only in Standalone mode with an active identity).

```
┌───────────────────────────┐       ┌──────────────────────────────────┐
│  User's Phone             │       │  User's Server (Desktop Mode)    │
│  (iOS / Android)          │       │                                  │
│                           │ HTTPS │  Go Backend provides compute-    │
│  Rust Bridge (FFI)        │──────→│  heavy backend services:         │
│  Manages primary parent   │       │  OOBI, contacts, tunneling.      │
│  AID locally. Phone has   │       │                                  │
│  the primary keys.        │       │  Server does NOT hold the        │
│                           │       │  phone's private keys.           │
│  All signing happens      │       │                                  │
│  on the phone.            │       │                                  │
└───────────────────────────┘       └──────────────────────────────────┘
```

- Reached via dashboard "Migrate to External Server" button (currently shows informational dialog; full migration flow is planned).
- The phone retains full key sovereignty — the remote server never receives private keys.
- The remote server handles OOBI serving, contact management, and tunneling on behalf of the phone.
- This is the most sovereign mobile mode: user keeps their keys locally but gains the network presence of a server.

## How the App Chooses a Mode

Mode selection happens through the **onboarding flow**, not automatic environment detection. The user makes an explicit choice:

1. **Desktop platforms** (Linux, macOS, Windows, web) → Always **Desktop Mode**. No user choice needed — the `BackendProcessService` starts the bundled Go binary with the Python KERI driver automatically.

2. **Mobile platforms** (iOS, Android) → User chooses during onboarding:
   - "Create New Identity" → **Mobile Standalone Mode** (Rust bridge + embedded Go Core)
   - "Connect to Existing Identity" → **Mobile Remote Controller WITHOUT Keys** (Rust bridge + remote server URL)
   - After identity creation in Standalone mode, "Migrate to External Server" dashboard button → **Mobile Remote Controller WITH Keys** (planned)

The user's choice is persisted via `PreferencesService` (SharedPreferences). On subsequent app launches, `_loadSavedState()` in `main.dart` restores the saved mode and initializes the correct `KeriService` implementation.

The `_initializeServiceForMode()` method in `main.dart` handles the topology-to-service mapping:
- Desktop (all topologies): `DesktopKeriService()` (local Go+Python for KERI ops; remote serverUrl passed to screens for backend ops in Remote topologies)
- Mobile Standalone: `MobileStandaloneKeriService` (Rust bridge + embedded Go Core)
- Mobile Remote WITHOUT Keys: `MobileRemoteKeriService` (Rust bridge for local child AID + remote parent server URL)
- Fallback (Rust bridge unavailable): `RemoteServerKeriService` (all ops forwarded to remote server)

## Trust Boundaries

Different components in the system have different levels of trust, depending on who controls them and what data they can see:

### User's Own Server (Desktop Mode, target of Remote Controller modes)
- **Trust level:** Full trust — the user owns and operates this machine.
- **Access:** Handles private keys (in Desktop Mode), the full Key Event Log, contacts, and OOBI serving.
- **Why it's trusted:** It's the user's own hardware running their own software.

### Rust Bridge (all mobile modes)
- **Trust level:** Full trust — it runs directly on the user's phone.
- **Access:** Handles private key creation, signing, and key rotation locally.
- **Why it's trusted:** The code is compiled into the app and never sends private data elsewhere.

### Go Core on Mobile (Mobile Standalone Mode)
- **Trust level:** Full trust — it runs embedded on the user's phone via gomobile.
- **Access:** Handles data persistence (file-based JSON store in the app's documents directory), OOBI serving, contact management, and tunneling.
- **Why it's trusted:** It runs locally with no network exposure by default. The KERI driver is disabled; it only provides backend services.
- **Platform channels:** Accessed via Dart `MobileCoreService` → Kotlin/Swift `MethodChannel` → gomobile-compiled Go library.

### Remote Server (in Remote Controller modes)
- **Trust level:** Full trust for "WITHOUT Keys" (server holds parent AID keys). Partial trust for "WITH Keys" (server only provides backend services, no keys).
- **Access (WITHOUT Keys):** Server manages the parent AID and provides backend services. Phone has a delegated child AID.
- **Access (WITH Keys):** Server provides OOBI, contacts, and tunneling only. Phone retains the primary AID and all keys.

### Remote Helper (stateless fallback)
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

## Phase 3: Connectivity — OOBI, Contacts, and Tunneling

Phase 3 adds the ability for Identity Agents to discover and connect with each other using OOBI (Out-of-Band Introduction) URLs. An OOBI URL is a web address that points to an agent's public identity data (its Key Event Log). When Agent A shares its OOBI URL with Agent B, Agent B can fetch Agent A's public keys and verify its identity.

### OOBI Endpoints

- **`GET /oobi/{aid}`** — Public OOBI serving endpoint. Returns the KEL (Key Event Log) for the given AID. This is what other agents fetch when resolving an OOBI URL.
- **`GET /api/oobi`** — Returns this agent's own OOBI URL, constructed using the public URL (tunnel URL > `PUBLIC_URL` env var > auto-detected from request headers).

### Contact Management Endpoints

- **`GET /api/contacts`** — List all saved contacts.
- **`POST /api/contacts`** — Add a contact by providing an OOBI URL. The backend resolves the URL, fetches the remote agent's KEL, and saves the contact. Blocks self-adds.
- **`GET /api/contacts/{aid}`** — Get a specific contact by AID.
- **`DELETE /api/contacts/{aid}`** — Remove a contact.

### Tunneling

For OOBI URLs to work, the agent needs a publicly accessible URL. In environments like Replit, this is provided automatically by the platform's proxy. For users running the agent on their own machine, the Go backend includes a multi-provider tunnel system:

- **Cloudflare (`cloudflared`):** The default tunnel provider. Uses the `cloudflared` binary to create a quick tunnel without requiring an account or auth token. Preferred for its simplicity and reliability.
- **ngrok:** Alternative tunnel provider. Requires `NGROK_AUTHTOKEN` environment variable. Uses the `ngrok-go` library for in-process tunnel creation.

Tunnel provider selection and settings are managed via the Settings UI and persisted in `settings.json`. The active tunnel URL is used in OOBI generation so the agent's identity is discoverable from anywhere.

If no tunnel is configured, the backend falls back to the `PUBLIC_URL` env var or auto-detection from request headers (`X-Forwarded-Proto`, `X-Forwarded-Host`). Tunneling is non-fatal — if it fails, the backend continues running normally on the local port.

### URL Priority for OOBI Generation

The `getPublicURL()` function resolves the agent's externally-reachable URL in this order:

1. `PUBLIC_URL` environment variable (explicit override, highest priority)
2. Active tunnel URL (if a Cloudflare or ngrok tunnel is running)
3. Auto-detected from request headers (`X-Forwarded-Proto` + `X-Forwarded-Host`)
4. Fallback to `https://{request.Host}`

## Configuration Variables

| Variable | What it does | Which mode uses it |
|---|---|---|
| `CORE_URL` | URL of the local Go backend (default: `http://localhost:5050`) | Desktop Mode |
| `PUBLIC_URL` | Explicit public URL override for OOBI generation | Desktop Mode |
| `NGROK_AUTHTOKEN` | ngrok auth token for automatic tunnel creation | Desktop Mode (optional) |
| `TUNNEL_PROVIDER` | Which tunnel provider to use (`cloudflare` or `ngrok`) | Desktop Mode (optional) |

Note: Server URLs for Remote Controller modes are entered by the user during onboarding and stored in SharedPreferences, not in environment variables.

## Consequences

- The Flutter UI is mode-agnostic — screen code interacts with the abstract `KeriService` interface regardless of which mode is active.
- All four modes implement the same `KeriService` interface with 5 stateful methods.
- Mobile Standalone mode runs BOTH Rust bridge (KERI crypto) AND Go Core (backend services) locally on the phone.
- Remote Controller modes use the Rust bridge locally for key management while connecting to a remote server for backend services.
- Rust native compilation (for the bridge) and Go mobile compilation (for Go Core) require local developer toolchains and CI/CD (Codemagic). These do not happen on Replit.
- The Python driver's endpoint paths are the single source of truth — all other components match them exactly.
- Mode selection happens through explicit user choice during onboarding, not automatic environment detection.
