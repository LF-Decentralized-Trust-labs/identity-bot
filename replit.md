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
-   **Flutter Frontend (`identity_agent_ui/`):** Cross-platform UI with two modes: Desktop Mode (dark cyberpunk theme, 5-tab bottom nav) and Mobile Mode (clean light theme with blue accents, 3-button bottom nav). Features multi-step onboarding, BIP-39 mnemonic generation, contact management, OOBI sharing, profile management (jCard), and a mode-aware dashboard.
-   **Rust Bridge (`identity_agent_ui/rust/`):** Implements the mobile KERI engine (`keriox/keri-core`) via `flutter_rust_bridge` for Dart ↔ Rust FFI, providing core KERI crypto functions.
-   **Tunnel Module (`identity-agent-core/tunnel/`):** Manages multi-provider tunnels (Cloudflare, ngrok, Grape ID) for public HTTPS URL acquisition.
-   **Endpoint Service (`identity-agent-core/endpoint/`):** Single source of truth for the agent's current public base URL, persisting to `endpoint.json`.
-   **AgentConfig (`identity_agent_ui/lib/config/agent_config.dart`):** Platform-aware Go backend URL for Flutter UI ↔ Go Core communication.

### Key Design Decisions

-   **Go for Backend:** Chosen for orchestration, single binary compilation, and driver lifecycle management, with `gomobile` for mobile integration.
-   **Python for KERI (Desktop):** Leverages the established `keripy` implementation.
-   **Rust for KERI (Mobile):** Provides native mobile KERI capabilities via FFI with `keriox` across all mobile modes.
-   **Local-First Storage:** Emphasizes user sovereignty and data control, defaulting to file-based JSON storage.
-   **AID Hierarchy:** Differentiates between delegated child AIDs for "Remote WITHOUT Keys" and retaining primary parent AIDs for "Remote WITH Keys."
-   **Consent-based Contact Flow:** Implements a two-step resolve and consent process for adding contacts.
-   **Mutual OOBI Contact Relationships:** Supports mutual relationships with jCard schema for rich contact information and reverse introduction flows.

### Persistence Layer

Defaults to a file-based JSON store in `./data/` (`identity.json`, `kel.json`, `contacts.json`, `settings.json`, `pending_requests.json`, `profile.json`, `endpoint.json`), with a modular `store.Store` interface for swappable backends. On mobile standalone, Go Core stores data in the app's documents directory. Onboarding state (mode, entity type, setup completion) is persisted via SharedPreferences. Profile data (jCard fields + photo) is stored in `profile.json` and served via OOBI endpoints and exchange introductions.

### Mobile UI Architecture

The mobile UI (`lib/screens/mobile/`) is a separate screen set from the desktop UI, activated when `Platform.isAndroid || Platform.isIOS` is true OR when the screen width is below 768px (responsive web support). It uses a clean light theme (`MobileTheme`) with IBM Blue 60 (`#4589FF`) as primary color. It includes a dashboard, bottom navigation, drawer menu, share menu, QR scanner, chatbot panel, profile editor, contacts screen, settings screen, and various onboarding screens.

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
-   `image_picker`: Native photo selection on iOS/Android for profile avatar upload.
-   `qr_flutter`: QR code generation.
-   `web_socket_channel`: WebSocket client for real-time event streaming.

### Real-Time Event System

The Go backend includes a WebSocket-based EventHub (`identity-agent-core/server/events.go`) using `gorilla/websocket`. The Flutter frontend connects via `EventService` singleton (`lib/services/event_service.dart`).

-   **WebSocket endpoint**: `GET /api/ws/events` — upgrades to WebSocket, pushes events to all connected clients.
-   **Event types**: `introduction_received` (new inbound contact request), `contact_accepted` (contact upgraded to mutual), `pending_request_received` (OOBI-unreachable sender).
-   **Architecture**: Same WebSocket URL works for both standalone (localhost) and remote controller (tunnel URL) modes. EventService auto-reconnects with exponential backoff and generation-based connection tracking.
-   **Popup behavior**: Connection request popups only appear on the OOBI QR sharing screen (`_AddContactScreen` in `share_menu.dart`). The dashboard updates alert badge counts silently via WebSocket events with a 60-second HTTP fallback poll.