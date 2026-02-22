# Identity Agent

## Overview

The Identity Agent is a self-sovereign digital identity platform designed to unify identity, data, communications, and assets using the KERI (Key Event Receipt Infrastructure) protocol. The project aims to provide a single, integrated environment for digital identity, empowering users with full control over their digital identities, enhancing privacy and security across various digital interactions. Key capabilities include identity creation, KERI inception events, Key Event Log (KEL) persistence, adaptive mobile architecture, OOBI serving/sharing, QR code generation/scanning, contact management, multi-provider tunneling, and user onboarding flows with OOBI-based server connection for cryptographic trust establishment.

## User Preferences

Preferred communication style: Simple, everyday language.
Design theme: Dark cyberpunk aesthetic with monospace fonts, dark blue/green color scheme.

## System Architecture

The system uses an adaptive architecture to integrate the KERI engine, resulting in four distinct operating modes:

1.  **Desktop Mode (Linux/macOS/Windows):** The Flutter UI communicates with a Go backend (`identity-agent-core`), which drives a Python KERI engine (`keripy`) running as a local child process. Full-featured mode with tunneling, OOBI serving, contact management, and all KERI operations.
2.  **Mobile Standalone Mode (iOS/Android):** BOTH the Rust KERI bridge (crypto/key operations via FFI) AND the Go Core backend (data persistence, OOBI, contacts, tunneling via gomobile platform channel) run locally on the device. This is the primary mobile onboarding path ("Create New Identity").
3.  **Mobile Remote Controller WITHOUT Keys:** The phone creates a delegated child AID locally using the Rust bridge, then connects to a remote Identity Agent server URL for backend operations. The server manages the parent AID; the phone holds only the child AID keys. Entered via "Connect to Existing Identity" onboarding flow.
4.  **Mobile Remote Controller WITH Keys:** The phone retains the primary parent AID and its keys locally (via Rust bridge), connecting to a remote server URL for compute-heavy backend operations. Reached by migrating from Standalone mode via the "Migrate to External Server" dashboard button.

A `KeriService` Dart abstract class provides a mode-agnostic interface for KERI operations, ensuring UI code remains independent of the underlying operating mode.

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

## CI/CD (Codemagic)

Defined in `codemagic.yaml`. Builds include:
-   Go Core compilation via gomobile for Android (.aar) and iOS (.xcframework)
-   Rust bridge compilation via cargo-ndk (Android) and cargo-lipo (iOS)
-   Flutter build for all platforms (Android, iOS, macOS, Windows, Linux, Web)
-   Gomobile outputs placed in `identity_agent_ui/android/app/libs/mobilecore.aar` and `identity_agent_ui/ios/Frameworks/Mobilecore.xcframework`

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
