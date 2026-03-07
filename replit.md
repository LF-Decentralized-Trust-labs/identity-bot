# Identity Agent

## Overview

The Identity Agent is a self-sovereign digital identity platform that unifies identity, data, communications, and assets using the KERI (Key Event Receipt Infrastructure) protocol. Its primary purpose is to empower users with full control over their digital identities, enhancing privacy and security across digital interactions. Key capabilities include identity creation, KERI inception events, Key Event Log (KEL) persistence, adaptive mobile architecture, OOBI serving/sharing, QR code generation/scanning, contact management, multi-provider tunneling, and user onboarding with OOBI-based server connection for cryptographic trust establishment.

## User Preferences

Preferred communication style: Simple, everyday language.
Design theme: Dark cyberpunk aesthetic with monospace fonts, dark blue/green color scheme.
Build/Distribution: No App Store or Play Store submissions. All builds are for local testing only — iOS uses Codemagic's built-in simulator/virtual testing (no TestFlight, no Apple Developer account signing). Android produces unsigned APKs/debug builds. Do not add code signing, provisioning profiles, or store-related configuration.

## System Architecture

The system employs a standardized topology model based on three topological states (Standalone, Remote Controller WITHOUT Root Keys, Remote Controller WITH Root Keys) and two device types (Desktop, Mobile), resulting in six architectural combinations. A critical invariant is that stateful KERI operations always use the local engine, with remote servers handling only backend services and stateless operations.

### Topological States

1.  **Standalone**: Device holds root AID keys and runs all backend services locally.
2.  **Remote Controller WITHOUT Root Keys**: Device creates a delegated child AID locally and connects to a remote parent server for backend services.
3.  **Remote Controller WITH Root Keys**: Device retains primary parent AID and keys locally, using a remote server for compute-heavy backend operations.

### Device Types

-   **Desktop** (Linux/macOS/Windows): Utilizes a Go backend with Python `keripy` for KERI and Go Core for backend services.
-   **Mobile** (iOS/Android): Employs a Rust bridge via FFI for KERI and Go Core via `gomobile` for backend services (Standalone only).

### Core Components and Technologies

-   **Go Backend (`identity-agent-core/`):** Handles core orchestration, public API, file-based data persistence, OOBI management, contact management, and optional tunnel providers. Compiles for mobile via `gomobile` (with KERI driver disabled).
-   **Python KERI Driver (`drivers/keri-core/`):** The `keripy` (v1.1.17) engine for desktop KERI operations.
-   **Flutter Frontend (`identity_agent_ui/`):** Cross-platform UI with two modes: Desktop Mode (dark cyberpunk theme, 5-tab bottom nav) and Mobile Mode (clean light theme with blue accents, 3-button bottom nav). Features multi-step onboarding, BIP-39 mnemonic generation, contact management, OOBI sharing, profile management (jCard), and a mode-aware dashboard. Platform detection via `Platform.isAndroid || Platform.isIOS` routes to the appropriate UI mode. On web, screen width < 768px also triggers Mobile Mode.
-   **Rust Bridge (`identity_agent_ui/rust/`):** Implements the mobile KERI engine (`keriox/keri-core`) via `flutter_rust_bridge` for Dart ↔ Rust FFI, providing core KERI crypto functions.
-   **Tunnel Module (`identity-agent-core/tunnel/`):** Manages multi-provider tunnels (Cloudflare, ngrok, Grape ID) for public HTTPS URL acquisition.
-   **Endpoint Service (`identity-agent-core/endpoint/`):** Single source of truth for the agent's current public base URL. Provider hierarchy: override URL → active tunnel → `PUBLIC_URL` env → local network IP → localhost fallback. Persists to `endpoint.json`; all consumers (OOBI generation, OOBI serving, exchange introductions) call `EndpointService.CurrentURL()`. Exposed via `GET /api/endpoint` returning `{url, source, updated_at}`.
-   **AgentConfig (`identity_agent_ui/lib/config/agent_config.dart`):** Platform-aware Go backend URL for Flutter UI ↔ Go Core communication. Desktop = `localhost:5000`, Mobile = `127.0.0.1:8642`, Web = relative (same origin). Uses conditional import (`platform_helper_stub.dart` / `platform_helper_io.dart`) for web-safe `dart:io` Platform detection. All screens resolve server URL via `_resolveServerUrl()` → `widget.serverUrl` → `MobileStandaloneKeriService.baseUrl` → `AgentConfig.coreBaseUrl` fallback chain.

### Key Design Decisions

-   **Go for Backend:** Chosen for orchestration, single binary compilation, and driver lifecycle management, with `gomobile` for mobile integration.
-   **Python for KERI (Desktop):** Leverages the established `keripy` implementation.
-   **Rust for KERI (Mobile):** Provides native mobile KERI capabilities via FFI with `keriox` across all mobile modes.
-   **Local-First Storage:** Emphasizes user sovereignty and data control, defaulting to file-based JSON storage.
-   **AID Hierarchy:** Differentiates between delegated child AIDs for "Remote WITHOUT Keys" and retaining primary parent AIDs for "Remote WITH Keys."
-   **Consent-based Contact Flow:** Implements a two-step resolve and consent process for adding contacts, including placeholder avatars and pending request management.
-   **Mutual OOBI Contact Relationships:** Supports mutual relationships with jCard schema (RFC 7095) for rich contact information and reverse introduction flows.

## External Dependencies

### Backend (Go)

-   `github.com/go-chi/chi/v5`: HTTP router.
-   `github.com/go-chi/cors`: CORS middleware.
-   `golang.ngrok.com/ngrok`: In-memory tunnel client.
-   `github.com/jpillora/chisel` v1.9.1: Chisel client for Grape ID reverse proxy tunnels.
-   `cloudflared`: System dependency for Cloudflare desktop tunnels.

### KERI Driver (Python, desktop only)

-   `flask`: Lightweight HTTP server.
-   `keri`: WebOfTrust reference KERI library v1.1.17.

### Rust Bridge (mobile only)

-   `keri-core` 0.11: THCLab KERI implementation.
-   `flutter_rust_bridge` 2.11.1: Dart ↔ Rust FFI bridge.
-   `base64`: Base64 encoding/decoding.
-   `serde`, `serde_json`: JSON serialization.

### Frontend (Flutter/Dart)

-   Flutter SDK (v3.22.0).
-   `http`: HTTP client.
-   `crypto`: SHA-256 for key derivation.
-   `ed25519_edwards`: Ed25519 key generation.
-   `shared_preferences`: Onboarding state persistence.
-   `mobile_scanner`: QR code scanning.
-   `qr_flutter`: QR code generation.

### Onboarding Modes

The app initializes services based on saved mode and platform:
-   `desktop` — Full Go Core + Python KERI driver
-   `mobileStandalone` — Go Core (via gomobile) + Rust bridge, both local
-   `mobileRemoteWithKeys` — Rust bridge (parent AID) + remote server URL
-   `mobileRemoteWithoutKeys` — Rust bridge (child AID) + remote server URL

### Persistence Layer

Defaults to a file-based JSON store in `./data/` (`identity.json`, `kel.json`, `contacts.json`, `settings.json`, `pending_requests.json`, `profile.json`, `endpoint.json`), with a modular `store.Store` interface for swappable backends. On mobile standalone, Go Core stores data in the app's documents directory. Onboarding state (mode, entity type, setup completion) is persisted via SharedPreferences. Profile data (jCard fields + photo) is stored in `profile.json` and served via OOBI endpoints and exchange introductions so contacts receive the user's display name and rich identity info.

## CI/CD (Codemagic)

Defined in `codemagic.yaml`. Builds include:
-   Go Core compilation via gomobile for Android (.aar) and iOS (.xcframework)
-   Rust bridge compilation via cargo-ndk (Android) and cargo-lipo (iOS)
-   Flutter build for all platforms (Android, iOS, macOS, Windows, Linux, Web)
-   Gomobile outputs placed in `identity_agent_ui/android/app/libs/mobilecore.aar` and `identity_agent_ui/ios/Frameworks/Mobilecore.xcframework`
-   iOS: Mobilecore.framework extracted from xcframework to `ios/Frameworks/Mobilecore/` before pod install; integrated via CocoaPods podspec (vendored_frameworks)

## Mobile UI Architecture

The mobile UI (`lib/screens/mobile/`) is a separate screen set from the desktop UI, activated when `Platform.isAndroid || Platform.isIOS` is true OR when the screen width is below 768px (responsive web support). It uses a clean light theme (`MobileTheme`) with IBM Blue 60 (`#4589FF`) as primary color.

### Mobile File Structure
- `lib/theme/mobile_theme.dart` — Light ThemeData with MobileColors design tokens
- `lib/screens/mobile/mobile_app.dart` — Root container, overlay management (drawer, share, scanner, chatbot)
- `lib/screens/mobile/mobile_dashboard.dart` — Main scrollable view with identity card, 3-tab area (Alerts/Tasks/Activity)
- `lib/screens/mobile/bottom_nav.dart` — Fixed bottom bar with Share, Scan (elevated center), Chatbot
- `lib/screens/mobile/drawer_menu.dart` — Left-slide drawer with profile, contacts, placeholder items
- `lib/screens/mobile/share_menu.dart` — Bottom sheet with 5 share options (all stubbed as "Coming Soon")
- `lib/screens/mobile/mobile_qr_scanner.dart` — Fullscreen dark scanner with OOBI resolution + consent flow
- `lib/screens/mobile/chatbot_panel.dart` — Dialog-based chat panel with dummy bot responses
- `lib/screens/mobile/mobile_profile_screen.dart` — Card-based profile editor with real backend data
- `lib/screens/mobile/mobile_contacts_screen.dart` — Searchable contact list with detail view

### Mobile Widgets
- `lib/widgets/identity_card.dart` — Profile photo, name, agent URL, confidence ring
- `lib/widgets/confidence_ring.dart` — Circular progress ring with color-coded score
- `lib/widgets/alert_card.dart` — Connection request / pending request cards with Approve/Deny
- `lib/widgets/task_card.dart` — Background task cards with progress bars (dummy data)
- `lib/widgets/activity_entry.dart` — Timestamped activity log entries (dummy data)

### Mobile Models
- `lib/models/background_task.dart` — Task model with dummy data generator
- `lib/models/activity_log_entry.dart` — Activity model with dummy data generator

### Backend Integration (Mobile)
Real backend data: Profile (GET/PUT /api/profile), Identity (GET /api/identity), Endpoint (GET /api/endpoint), Alerts (GET /api/alerts), Contacts (GET /api/contacts), OOBI resolution (POST /api/contacts/resolve), Contact add (POST /api/contacts), Accept/Reject (POST /api/contacts/{aid}/accept|reject).
Dummy data: Tasks tab, Activity tab. Stubbed: All Share menu items, Wallet, Data Vault, Security Settings, My Devices.

## Specification Documents

-   `docs/spec-backend-migration.md`: Backend migration specification (mobile-to-desktop). Living document tracking all data and settings that must transfer during migration, including tunnel settings, identity data, contacts, and provider continuity requirements. New features should append their migration requirements to the "Future Additions" table.

## Grape ID Tunnel Integration

The Grape ID tunnel provider uses a Chisel reverse proxy to expose the agent's OOBI endpoints via a permanent public URL (e.g., `https://grapeid.org/alice`). Works on both desktop and mobile platforms via the Go Core tunnel module.

-   **Connection flow (reconnect-first):** On startup, the agent first tries `POST /reconnect {"name": ..., "aid": ...}` to re-establish a previously claimed name. If that fails (hub doesn't support it yet, or name not found), it falls back to `POST /claim-name {"name": ..., "aid": ...}` for initial registration. Both requests include the agent's AID for ownership tracking.
-   **AID-based ownership:** Each tunnel name is associated with the claiming agent's AID. The hub uses this to verify reconnection requests — only the original AID holder can reclaim a name. See `docs/grapeid-hub-reconnect-spec.md` for the hub-side implementation specification.
-   **Disconnect vs Release:** The `Provider` interface has two shutdown methods: `Disconnect()` (closes tunnel connection, keeps name reserved on hub for reconnect) and `Stop()` (releases name on hub, then disconnects). All restart paths (SIGTERM, workflow restart, settings changes) use `Disconnect()` so the hub keeps the name reserved and the next startup successfully uses `/reconnect`. `Stop()` with explicit release is available for future use (e.g., explicit "release name" UI button).
-   **Mobile reconnection:** On mobile, the tunnel drops when the app closes or the phone sleeps. When the app reopens, Go Core restarts and uses the reconnect-first flow (via `Disconnect()` semantics) to re-establish the tunnel with the same name.
-   **Future: KERI signatures:** The `aid` field will eventually be accompanied by KERI signature headers for cryptographic proof of ownership (currently trust-on-first-use).
-   **UI requirement (pending):** Dashboard needs a tunnel status indicator — connected (green), disconnected (amber), error (red) — so the user can confirm their agent is reachable.
-   **Migration:** Tunnel settings (provider, domain, extension) must transfer during backend migration so the same URL continues working on the new device. See `docs/spec-backend-migration.md`.