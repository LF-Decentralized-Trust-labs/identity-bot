# ADR 005: Onboarding Flow and Mode Selection

**Date:** 2026-02-21
**Updated:** 2026-02-22
**Status:** Accepted
**Related:** ADR-003 (Adaptive Architecture — Three Operating Modes)

## The Problem This Solves

ADR-003 established the three operating modes (Desktop, Mobile Remote, Mobile Standalone) and explained how the app detects the correct mode automatically based on the device and environment variables. However, the app previously dropped users directly into the identity creation wizard on first launch, with no choice about how their identity would be set up.

This creates two problems:

1. **New users vs. existing users.** Someone launching the app for the first time on a phone might want to create a brand new identity from scratch. But someone who already has an Identity Agent running on their laptop might want to connect this phone to that existing identity — not create a second one. The app had no way to distinguish these two scenarios.

2. **Identity type matters for future features.** An individual person's identity and an organization's identity will eventually behave differently — organizations need multi-signature governance, delegated authority, and group management. Capturing this choice at the start (even before those features are fully built) means the system can structure the identity correctly from day one, avoiding costly migrations later.

## The Decision

The app now guides users through a multi-step onboarding flow before any identity is created. The flow captures two key decisions: **what kind of setup** (new identity vs. connect to existing) and **what kind of entity** (individual vs. organization). These choices are persisted to local storage so the app remembers them across restarts.

### The Onboarding Steps

The flow is a state machine with five states:

```
┌──────────┐
│ LOADING  │  ← App startup. Check local storage for saved state.
└────┬─────┘
     │
     ▼ (no saved state)                    (setup already complete)
┌─────────────────┐                    ┌───────────┐
│ MODE SELECTION  │                    │ DASHBOARD │
│                 │                    └───────────┘
│ • Create New    │
│ • Connect to    │
│   Existing      │
└──┬──────────┬───┘
   │          │
   ▼          ▼
┌──────────┐  ┌──────────────┐
│ ENTITY   │  │ CONNECT      │
│ TYPE     │  │ SERVER       │
│          │  │              │
│ • Indiv. │  │ Enter URL,   │
│ • Org.   │  │ validate via │
└────┬─────┘  │ /api/health  │
     │        └──────┬───────┘
     ▼               │
┌──────────┐         │
│ SETUP    │         │
│ WIZARD   │         │
│ (create  │         │
│ identity)│         │
└────┬─────┘         │
     │               │
     ▼               ▼
┌────────────────────────┐
│      DASHBOARD         │
└────────────────────────┘
```

### Step 1: Mode Selection

The user sees two options:

- **"Create New Identity"** (recommended) — For users setting up a brand new digital identity on this device. This is the primary path for first-time users. The app will generate a BIP-39 mnemonic seed phrase and create a root identity. On mobile, this operates in **Standalone Mode** — the phone creates and holds the identity keys locally via the Rust KERI bridge. No remote server is required.

- **"Connect to Existing Identity"** — For users who already have an Identity Agent running on another machine (their laptop, a cloud server, etc.) and want this device to connect to it as an additional device. On mobile, the phone still uses the **local Rust KERI bridge** to create its own AID, which becomes a delegated identity under the parent server's identity. The remote server is used for stateless KERI operations (formatting, OOBI resolution, etc.).

### Step 2a: Entity Type Selection (for "Create New Identity")

If the user chose "Create New Identity," they are asked what kind of entity this identity represents:

- **Individual** — A personal identity for a single human being. Used for personal credentials, communications, and self-sovereign identity management.

- **Organization** — An identity representing a group, company, or institution. This choice enables future features like multi-signature key management, delegated authority hierarchies, and group credential issuance.

**Why capture this now?** The entity type is not heavily used in the current codebase — both types currently go through the same identity creation process. However, KERI supports different governance structures for individuals vs. organizations (e.g., multi-sig inception events for organizations, delegation hierarchies for departments). Capturing the intent at onboarding allows the system to:

1. Store the entity type for use when those features are implemented.
2. Avoid requiring a migration or identity re-creation later.
3. Potentially customize the KERI inception event structure in the future (single-sig for individuals, multi-sig threshold for organizations).

After selecting an entity type, the user proceeds to the existing Setup Wizard (BIP-39 mnemonic generation → identity creation). On mobile, no server URL is needed — the Rust bridge handles all KERI operations locally.

### Step 2b: Server Connection (for "Connect to Existing Identity")

If the user chose "Connect to Existing Identity," they are prompted to enter the URL of their existing Identity Agent server. The app validates the connection by calling `GET /api/health` on the provided URL. The health endpoint must return:

```json
{
  "status": "active",
  "agent": "identity-agent-core",
  "version": "0.1.0"
}
```

If the server responds with `status: "active"`, the connection is confirmed and the user proceeds directly to the Dashboard — no seed phrase or identity creation happens.

If the server cannot be reached, returns an error, or has a non-"active" status, the user sees a clear error message and can retry or go back.

The server URL can be any publicly reachable address: a Cloudflare tunnel URL, an ngrok URL, a static IP, or a domain name. The app automatically prepends `https://` if no protocol is specified.

## Three Mobile Operating Modes

On mobile devices, there are actually **three** operating modes, though only two are presented to the user during onboarding. The third mode is a natural evolution of the first:

### 1. Standalone Mode (user-facing: "Create New Identity")

The phone creates and holds its own identity locally. The Rust KERI bridge handles all stateful operations (key creation, signing, rotation) directly on-device via FFI. Stateless operations (formatting, parsing) are sent to a default helper service or, if available, the user's own publicly accessible backend.

This is the default mobile experience. The phone is the primary key holder and identity owner.

### 2. Remote Controller WITH Keys (user-facing: migration from Standalone)

This is **not** a setup option — it is a **migration path** from Standalone Mode. When the user decides to offload computing power to a dedicated server, they migrate their backend to a separate machine. When this happens:

- The **keys remain on the phone**. The phone continues to be the primary key holder and identity owner.
- The remote server creates **its own AID** that becomes a **delegated identity** acting on behalf of the phone's root identity.
- The phone delegates heavy computation (OOBI resolution, credential formatting, etc.) to the remote server while retaining full authority over the identity.
- The Rust KERI bridge on the phone continues to handle all local stateful operations (signing, key rotation).

This mode is the natural upgrade path for users who start with Standalone and later want dedicated server infrastructure.

### 3. Remote Controller WITHOUT Keys (user-facing: "Connect to Existing Identity")

The phone connects to an existing Identity Agent running on another device. The existing device retains the root identity and keys. The phone:

- Uses the **local Rust KERI bridge** to create its own AID, which becomes a **delegated device** under the parent identity.
- Uses the **remote parent server** for all stateless KERI operations (formatting, OOBI resolution, etc.).
- Does not hold the root identity keys — it operates under delegated authority.

### How the user-facing options map to these modes:

| User's Choice | Initial Mode | Future Migration |
|---|---|---|
| "Create New Identity" | Standalone Mode | Can migrate to Remote Controller WITH Keys |
| "Connect to Existing Identity" | Remote Controller WITHOUT Keys | N/A (already connected) |

### Key insight: The Rust KERI bridge is always needed on mobile

Both "Create New" and "Connect to Existing" on mobile require the local Rust KERI bridge:

- **Create New (Standalone):** The bridge creates and manages the root identity locally.
- **Connect to Existing (Remote Controller WITHOUT Keys):** The bridge creates a local delegated AID that connects to the parent identity on the remote server.

The difference is in what the **remote server** provides:

- **Standalone:** No remote server needed for core operations. A stateless helper handles formatting/parsing only.
- **Remote Controller WITHOUT Keys:** The parent server provides stateless KERI operations AND is the target for delegation.

## How Mode Selection Relates to Operating Modes (ADR-003)

The onboarding mode selection ("Create New" vs. "Connect to Existing") is a **user-facing** concept that sits above the **technical** operating modes from ADR-003. They are related but not the same:

| User's Onboarding Choice | Device | Technical Mode | What Happens |
|---|---|---|---|
| "Create New Identity" | Desktop | Desktop Mode | Go + Python run locally, identity created on this machine |
| "Create New Identity" | Mobile | Mobile Standalone | Rust bridge handles KERI locally; stateless ops go to default helper |
| "Connect to Existing" | Desktop | Desktop Mode (remote URL) | `DesktopKeriService` initialized with the remote server's URL; all KERI operations forwarded there |
| "Connect to Existing" | Mobile | Mobile Standalone + Remote | Rust bridge for stateful ops (delegated AID creation); remote server for stateless ops |

**Desktop "Connect to Existing"** uses `DesktopKeriService` pointed at the remote URL — all operations (stateful and stateless) are forwarded to the remote server. This works because the desktop doesn't need local key operations when connecting to an existing identity.

**Mobile "Connect to Existing"** uses `MobileStandaloneKeriService` with the remote server URL as the stateless helper — stateful operations (AID creation for delegation) happen locally via the Rust bridge, while stateless operations go to the parent server.

## Persistence

All onboarding decisions are persisted using **SharedPreferences** (via `PreferencesService`), a key-value store that survives app restarts:

| Key | Type | What It Stores |
|---|---|---|
| `agent_mode` | String | `"createNew"` or `"connectExisting"` |
| `entity_type` | String | `"individual"` or `"organization"` |
| `server_url` | String | The remote server URL (only for "Connect to Existing") |
| `setup_complete` | Boolean | `true` once the user has finished onboarding |

On subsequent app launches, the startup logic checks `setup_complete`. If `true`, it skips the entire onboarding flow and goes directly to the Dashboard (or Setup Wizard if identity creation wasn't finished). If `false` or absent, the onboarding flow starts from the beginning.

A `clearAll()` method exists on `PreferencesService` for future use — for example, a "Reset Agent" feature in Settings that wipes the saved state and returns the user to mode selection.

## Graceful Degradation on Mobile

When the user selects "Create New Identity" on a mobile device, the app attempts to load the Rust KERI library via FFI (as described in ADR-003 and ADR-004). If the native library is not available — which happens during development because the Rust cross-compilation only runs in the Codemagic CI/CD pipeline — the app falls back to Desktop Mode, communicating with the Go backend over HTTP.

The same graceful degradation applies to "Connect to Existing" on mobile. If the Rust bridge is unavailable, the app falls back to `DesktopKeriService` pointed at the remote server, forwarding all operations (including stateful ones) to the remote server. This means the phone loses local key management but remains functional.

This fallback is handled in `KeriBridge.ensureInitialized()`, which catches library load failures gracefully:

```
try {
  RustLib.init();        // Try loading the native Rust library
  _isAvailable = true;   // Success — use Mobile Standalone Mode
} catch (e) {
  _isAvailable = false;  // Failed — fall back to Desktop Mode (Go backend)
}
```

This means the app always works, even in environments where the Rust library hasn't been compiled. The user experience is identical — only the underlying engine differs.

## Settings Display

The Settings screen displays an "Agent Configuration" card showing the user's current setup:

- **Mode** — "Primary (New Identity)" or "Connected Device"
- **Identity Type** — "Individual" or "Organization" (only for new identities)
- **Engine** — The technical operating mode (Desktop, Mobile Remote, or Mobile Standalone)
- **Server** — The connected server URL (only for "Connect to Existing")

This gives the user visibility into how their agent is configured without requiring them to understand the technical details.

## File Inventory

| File | Purpose |
|---|---|
| `lib/services/preferences_service.dart` | SharedPreferences wrapper for persisting onboarding state |
| `lib/screens/mode_selection_screen.dart` | "Create New Identity" vs. "Connect to Existing Identity" |
| `lib/screens/entity_type_screen.dart` | "Individual" vs. "Organization" selection |
| `lib/screens/connect_server_screen.dart` | Server URL input with health-check validation |
| `lib/main.dart` | `AgentRouter` state machine that orchestrates the onboarding flow |
| `lib/screens/settings_screen.dart` | Updated to display agent configuration info |

## Consequences

- Users now explicitly choose their setup path before any identity is created, preventing accidental identity creation on devices that should be connected to an existing server.
- The entity type is captured early, allowing future KERI features (multi-sig, delegation) to be built on a correct foundation without requiring data migration.
- The "Connect to Existing" path validates server connectivity before proceeding, providing clear feedback if the server is unreachable.
- All onboarding state is persisted locally — the app never asks the same questions twice after a successful setup.
- The onboarding flow is purely a UI-layer concern. It does not change any backend APIs, KERI protocol logic, or the three operating modes themselves. It simply determines which `KeriService` implementation gets initialized and with what parameters.
- Back navigation is supported at every step, so users can change their mind without restarting the app.
- The "Remote Controller with Keys" mode (migration from Standalone to delegated server) is intentionally omitted from the onboarding UI. It will be implemented as a migration feature accessible from Settings, allowing users to upgrade their Standalone setup to a server-backed configuration without re-creating their identity.
