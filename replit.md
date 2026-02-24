# Identity Agent

## Overview

The Identity Agent is a self-sovereign digital identity platform designed to unify identity, data, communications, and assets using the KERI (Key Event Receipt Infrastructure) protocol. The project aims to provide a single, integrated environment for digital identity, empowering users with full control over their digital identities, enhancing privacy and security across various digital interactions. Key capabilities include identity creation, KERI inception events, Key Event Log (KEL) persistence, adaptive mobile architecture, OOBI serving/sharing, QR code generation/scanning, contact management, multi-provider tunneling, and user onboarding flows with OOBI-based server connection for cryptographic trust establishment.

## User Preferences

Preferred communication style: Simple, everyday language.
Design theme: Dark cyberpunk aesthetic with monospace fonts, dark blue/green color scheme.
Build/Distribution: No App Store or Play Store submissions. All builds are for local testing only — iOS uses Codemagic's built-in simulator/virtual testing (no TestFlight, no Apple Developer account signing). Android produces unsigned APKs/debug builds. Do not add code signing, provisioning profiles, or store-related configuration.

## System Architecture

The system uses a standardized topology model: **3 topological states × 2 device types = 6 architectural combinations** (see ADR-006 for full details).

### Three Topological States

1.  **Standalone** (Root Keys + Backend Brain): Device holds root AID keys AND runs all backend services locally.
2.  **Remote Controller WITHOUT Root Keys** (Delegated Device): Device creates a delegated child AID locally, connects to remote parent server for backend services.
3.  **Remote Controller WITH Root Keys** (Sovereign Controller): Device retains primary parent AID and keys locally, uses remote server for compute-heavy backend operations.

### Two Device Types

-   **Desktop** (Linux/macOS/Windows): Go backend → Python keripy for KERI, Go Core for backend services.
-   **Mobile** (iOS/Android): Rust bridge via FFI for KERI, Go Core via gomobile for backend services (Standalone only).

### Critical Architecture Invariant

In ALL combinations, stateful KERI operations (inception, rotation, signing, verification, KEL retrieval) ALWAYS use the LOCAL engine. The remote server is only for backend services and stateless operations. The remote server NEVER performs stateful KERI operations on behalf of the local device.

A `KeriService` Dart abstract class provides a topology-agnostic interface for KERI operations, ensuring UI code remains independent of the underlying topology.

### KeriService Implementations

-   `DesktopKeriService`: All desktop topologies — talks to local Go+Python. Remote serverUrl passed to screens for backend ops in Remote topologies.
-   `MobileStandaloneKeriService`: Mobile Standalone — Rust bridge (KERI) + embedded Go Core (backend).
-   `MobileRemoteKeriService`: Mobile Remote WITHOUT Keys — Rust bridge for local child AID, stores parentServerUrl for backend delegation. No embedded Go Core.
-   `RemoteServerKeriService`: Fallback only — forwards all ops to remote server when local KERI engine unavailable.

### Component Details

-   **Go Backend (`identity-agent-core/`):** Core orchestration, public API serving, file-based data persistence, OOBI serving/generation, contact management, and optional tunnel providers. On desktop, also spawns the Python KERI driver. On mobile, compiled via gomobile and accessed through platform channels (KERI driver disabled, crypto handled by Rust bridge).
-   **Go Mobile Core (`identity-agent-core/mobilecore/`):** Gomobile-compatible package exporting `StartServer`, `StopServer`, `GetHealth`, `GetPort`, `GetDataDir` for use from Kotlin/Swift platform channels. Runs Go Core with KERI driver disabled on mobile.
-   **Go Server Package (`identity-agent-core/server/`):** Extracted reusable HTTP server with `ServerConfig` supporting optional KERI driver, configurable ports, storage-only endpoints (`/api/store/identity`, `/api/store/event`), and OOBI/contact management.
-   **Python KERI Driver (`drivers/keri-core/`):** The KERI protocol engine (`keripy` v1.1.17) for desktop only, exposing stateful and stateless KERI endpoints.
-   **Flutter Frontend (`identity_agent_ui/`):** Cross-platform UI with a dark cyberpunk theme, multi-step onboarding, BIP-39 mnemonic generation, contact management, OOBI URL sharing, and mode-aware dashboard with migration support.
-   **Rust Bridge (`identity_agent_ui/rust/`):** The mobile KERI engine (THCLab `keriox/keri-core`) integrated via `flutter_rust_bridge` for Dart ↔ Rust FFI, providing core KERI crypto functions (inception, rotation, signing, verification).
-   **Tunnel Module (`identity-agent-core/tunnel/`):** Multi-provider tunnel system (e.g., Cloudflare, ngrok) for public HTTPS URL acquisition, with settings persisted and configurable via the Settings UI and API.
-   **Platform Channels (`android/.../MainActivity.kt`, `ios/.../AppDelegate.swift`):** Native bridge code that loads the gomobile-compiled Go Core library and exposes `startServer`, `stopServer`, `isRunning`, `getHealth`, `getPort`, `getDataDir` methods to Dart.
-   **Dart Mobile Core Service (`lib/services/mobile_core_service.dart`):** Dart wrapper around platform channels for starting/stopping/querying the embedded Go Core server on mobile.

### Key Design Decisions

-   **Go for Backend:** Orchestration, single binary compilation, and driver lifecycle management. Gomobile enables compilation to .aar (Android) and .xcframework (iOS).
-   **Python for KERI (Desktop):** Leverages `keripy` as the established KERI implementation.
-   **Rust for KERI (Mobile):** Provides native mobile KERI capabilities via FFI with `keriox`. Used in ALL mobile modes (standalone, remote with keys, remote without keys).
-   **Go Core on Mobile (Standalone):** Runs embedded via platform channels for data persistence, OOBI serving, contacts, and tunneling. KERI driver is disabled — Rust bridge handles all crypto.
-   **Driver Pattern:** Ensures consistent HTTP-based internal communication across modes.
-   **Flutter for Frontend:** Cross-platform UI development.
-   **Local-First Storage:** Emphasizes user sovereignty and data control.
-   **Migration Path:** Standalone → Remote Controller WITH Keys via dashboard "Migrate to External Server" button (stubbed, coming soon).
-   **AID Hierarchy:** Remote WITHOUT Keys creates a delegated child AID; Remote WITH Keys retains the primary parent AID.

### AgentEnvironment Enum

-   `desktop` — Full Go Core + Python KERI driver
-   `mobileStandalone` — Go Core (via gomobile) + Rust bridge, both local
-   `mobileRemoteWithKeys` — Rust bridge (parent AID) + remote server URL
-   `mobileRemoteWithoutKeys` — Rust bridge (child AID) + remote server URL

### Persistence Layer

Defaults to a file-based JSON store in `./data/` (`identity.json`, `kel.json`, `contacts.json`, `settings.json`), with a modular `store.Store` interface for swappable backends. On mobile standalone, Go Core stores data in the app's documents directory.

## Recent Changes

-   **2026-02-22:** Standardized topology model and architecture fixes.
    -   Created ADR 006 (Standardized Topology): 3 topological states × 2 device types = 6 architectural combinations. Supersedes mode definitions in ADR 003 and ADR 005.
    -   Created `MobileRemoteKeriService`: Uses Rust bridge for local child AID operations, stores `parentServerUrl` for backend delegation. No embedded Go Core.
    -   Fixed Desktop "Connect to Existing": Now uses `DesktopKeriService()` (local Go+Python) instead of `DesktopKeriService(baseUrl: serverUrl)`. Child AID created locally, remote server used only for backend/stateless ops.
    -   Fixed Mobile "Connect to Existing": Now uses `MobileRemoteKeriService` (Rust bridge) instead of `RemoteServerKeriService`. `RemoteServerKeriService` demoted to fallback-only.
    -   Updated ADR 003: Added superseded note, fixed mode-to-service mapping to reflect new `MobileRemoteKeriService`.
    -   Updated ADR 005: Added superseded note, fixed Desktop/Mobile "Connect to Existing" code references.
-   **2026-02-22:** ADR documentation audit and dead code cleanup.
    -   Updated ADR 001 to fix outdated references (keri-go → keripy/keriox, BadgerDB → file-based JSON, port 8080 → 5000). AI governance kept as future work.
    -   Updated ADR 002 to document optional KERI driver (`ServerConfig.EnableKeriDriver`), extracted `server` package, and updated Key Files section.
    -   Rewrote ADR 003 from "Three Operating Modes" to "Four Operating Modes" — added Go Core on mobile via gomobile/platform channels, split old "Mobile Remote Mode" into Remote Controller WITH Keys and WITHOUT Keys, added Cloudflare as default tunnel provider, updated trust boundaries.
    -   Updated ADR 004 to include Go Mobile Core (gomobile builds, platform channel bridge, MobileCoreService wrapper) alongside the existing Rust bridge documentation.
    -   Removed dead code: `keri_helper_client.dart` (unused HTTP client), `server_config_screen.dart` (superseded by `connect_server_screen.dart`), `AgentConfig.primaryServerUrl` and `AgentConfig.keriHelperUrl` (unused env var configs), `KeriService.detectEnvironment()` (unused static method — mode detection now happens through onboarding flow in `main.dart`).

## Recent Changes (continued)

-   **2026-02-23:** iOS Mobilecore integration fix — CocoaPods-managed with pre-extracted .framework.
    -   **Architectural lesson:** Never bypass CocoaPods with manual project.pbxproj FRAMEWORK_SEARCH_PATHS — it breaks CocoaPods integration for ALL pods (caused `Module 'mobile_scanner' not found`). CocoaPods must manage ALL native dependencies uniformly.
    -   Mobilecore restored as a CocoaPods pod with podspec referencing pre-extracted `.framework` (not `.xcframework`).
    -   Podspec at `ios/Frameworks/Mobilecore.podspec` uses `vendored_frameworks = 'Mobilecore/Mobilecore.framework'`.
    -   Codemagic.yaml step "Extract Mobilecore.framework from XCFramework" runs BEFORE pod install, copying simulator slice to `ios/Frameworks/Mobilecore/Mobilecore.framework/`.
    -   Reverted all manual FRAMEWORK_SEARCH_PATHS and `-framework Mobilecore` linker flags from project.pbxproj.
    -   CocoaPods EXCLUDED_ARCHS fixes retained for other pods (Google MLKit, etc.).

## CI/CD (Codemagic)

Defined in `codemagic.yaml`. Builds include:
-   Go Core compilation via gomobile for Android (.aar) and iOS (.xcframework)
-   Rust bridge compilation via cargo-ndk (Android) and cargo-lipo (iOS)
-   Flutter build for all platforms (Android, iOS, macOS, Windows, Linux, Web)
-   Gomobile outputs placed in `identity_agent_ui/android/app/libs/mobilecore.aar` and `identity_agent_ui/ios/Frameworks/Mobilecore.xcframework`
-   iOS: Mobilecore.framework extracted from xcframework to `ios/Frameworks/Mobilecore/` before pod install; integrated via CocoaPods podspec (vendored_frameworks)

## External Dependencies

### Backend (Go)

-   `github.com/go-chi/chi/v5`: HTTP router.
-   `github.com/go-chi/cors`: CORS middleware.
-   `golang.ngrok.com/ngrok`: In-memory tunnel client.
-   System dependency: `cloudflared` for Cloudflare desktop tunnels.

### KERI Driver (Python, desktop only)

-   `flask`: Lightweight HTTP server.
-   `keri`: WebOfTrust reference KERI library v1.1.17.

### Rust Bridge (mobile only)

-   `keri-core` 0.11: THCLab KERI implementation.
-   `flutter_rust_bridge` 2.11.1: Dart ↔ Rust FFI bridge.
-   `base64` 0.13: Base64 encoding/decoding.
-   `serde` 1.0 + `serde_json` 1.0: JSON serialization.

### Frontend (Flutter/Dart)

-   Flutter SDK (v3.22.0).
-   `http`: HTTP client.
-   `crypto`: SHA-256 for key derivation.
-   `ed25519_edwards`: Ed25519 key generation.
-   `shared_preferences`: Onboarding state persistence.
-   `mobile_scanner`: QR code scanning.
-   `qr_flutter`: QR code generation.
