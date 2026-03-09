# Identity Agent

## Overview

The Identity Agent is a self-sovereign digital identity platform that unifies identity, data, communications, and assets using the KERI protocol. Its core purpose is to empower users with full control over their digital identities, enhancing privacy and security across digital interactions. Key capabilities include identity creation, KERI inception events, Key Event Log (KEL) persistence, adaptive mobile architecture, OOBI serving/sharing, QR code generation/scanning, contact management, multi-provider tunneling, and user onboarding with OOBI-based server connection for cryptographic trust establishment.

## User Preferences

Preferred communication style: Simple, everyday language.
Design theme: Dark cyberpunk aesthetic with monospace fonts, dark blue/green color scheme.
Build/Distribution: No App Store or Play Store submissions. All builds are for local testing only — iOS uses Codemagic's built-in simulator/virtual testing (no TestFlight, no Apple Developer account signing). Android produces unsigned APKs/debug builds. Do not add code signing, provisioning profiles, or store-related configuration.

## System Architecture

The system uses a standardized topology model based on three topological states (Standalone, Remote Controller WITHOUT Root Keys, Remote Controller WITH Root Keys) and two device types (Desktop, Mobile), resulting in six architectural combinations. A critical invariant is that stateful KERI operations always use the local engine, with remote servers handling only backend services and stateless operations.

### Topological States

1.  **Standalone**: Device holds root AID keys and runs all backend services locally.
2.  **Remote Controller WITHOUT Root Keys**: Device creates a delegated child AID locally and connects to a remote parent server for backend services.
3.  **Remote Controller WITH Root Keys**: Device retains primary parent AID and keys locally, using a remote server for compute-heavy backend operations.

### Device Types

-   **Desktop** (Linux/macOS/Windows): Utilizes a Go backend with Python `keripy` for KERI and Go Core for backend services.
-   **Mobile** (iOS/Android): Employs a Rust bridge via FFI for KERI and Go Core via `gomobile` for backend services (Standalone only).

### Core Components and Technologies

-   **Go Backend (`identity-agent-core/`):** Handles core orchestration, public API, file-based data persistence, OOBI management, contact management, and optional tunnel providers. Compiles for mobile via `gomobile`.
-   **Python KERI Driver (`drivers/keri-core/`):** The `keripy` engine for desktop KERI operations.
-   **Flutter Frontend (`identity_agent_ui/`):** Cross-platform UI featuring a dark cyberpunk theme, multi-step onboarding, BIP-39 mnemonic generation, contact management, OOBI sharing, profile management, and a mode-aware dashboard.
-   **Rust Bridge (`identity_agent_ui/rust/`):** Implements the mobile KERI engine (`keriox/keri-core`) via `flutter_rust_bridge` for Dart ↔ Rust FFI, providing core KERI crypto functions.
-   **Tunnel Module (`identity-agent-core/tunnel/`):** Manages multi-provider tunnels (Cloudflare, ngrok, Grape ID) for public HTTPS URL acquisition.
-   **Endpoint Service (`identity-agent-core/endpoint/`):** Single source of truth for the agent's current public base URL, with a defined hierarchy for resolution.
-   **AgentConfig (`identity_agent_ui/lib/config/agent_config.dart`):** Platform-aware Go backend URL for Flutter UI ↔ Go Core communication, handling desktop, mobile, and web variations.

### Key Design Decisions

-   **Go for Backend:** Chosen for orchestration, single binary compilation, and driver lifecycle management, with `gomobile` for mobile integration.
-   **Python for KERI (Desktop):** Leverages the established `keripy` implementation.
-   **Embedded Python (Desktop Builds):** All desktop builds (Windows, macOS, Linux) embed a self-contained Python environment with pre-installed `flask` and `keri` packages. Windows uses the Python embeddable package; macOS/Linux use `python3 -m venv`. Users never need to install Python separately. The `BackendProcessService` checks for bundled Python at `backend/python/` (Windows/macOS) or `backend/python-env/` (Linux) before falling back to system Python.
-   **Backend Startup Error Dialog:** Desktop builds show a modal error dialog with RETRY button if the bundled Go backend fails to start (missing binary, Python not installed, dependency issues).
-   **Rust for KERI (Mobile):** Provides native mobile KERI capabilities via FFI with `keriox` across all mobile modes.
-   **Local-First Storage:** Emphasizes user sovereignty and data control, defaulting to file-based JSON storage.
-   **AID Hierarchy:** Differentiates between delegated child AIDs for "Remote WITHOUT Keys" and retaining primary parent AIDs for "Remote WITH Keys."
-   **Consent-based Contact Flow:** Implements a two-step resolve and consent process for adding contacts.
-   **Mutual OOBI Contact Relationships:** Supports mutual relationships with jCard schema for rich contact information and reverse introduction flows.
-   **IPv4 Loopback for Desktop:** All desktop backend connections use `127.0.0.1` (not `localhost`) to avoid Windows IPv6 resolution issues where `localhost` can map to `::1` while the Go backend binds IPv4 only.
-   **Backend Startup Error Dialog:** Desktop builds show a modal error dialog with RETRY button if the bundled Go backend fails to start (missing binary, Python not installed, dependency issues).
-   **Port Conflict Handling:** On startup, checks if port 5000 is occupied. Stale Identity Agent processes are auto-killed; other apps trigger a user confirmation dialog with "CLOSE IT AND RETRY" option.
-   **libsodium Bundling (Windows):** `libsodium.dll` is downloaded from the official release and bundled into the embedded Python dir, backend dir, and keri-driver dir. The KERI driver's `server.py` has Windows-specific detection logic to find the DLL.
-   **Docker Setup UX (APPS tab):** When Docker is not available, the marketplace shows a friendly setup guide instead of an error banner, with a "GET DOCKER DESKTOP" or "CHECK AGAIN" button and an explanatory "Why Docker?" section.

### Sandboxed App Marketplace (Desktop-Only)

This desktop-only feature enables sandboxed application execution via Docker containers and compiled binaries. It includes a comprehensive sandbox package for storage, manifest loading, runtime abstraction, networking, policy enforcement, and resource monitoring. Key features include a pure Go forward proxy with MITM TLS interception, a policy engine for domain access, a credential vault, and resource monitoring with escalation.

### Sandbox Trace Debugger (Developer-Only)

A developer-only diagnostic tool providing real-time visibility into sandbox request pipelines. It features a trace core with an in-memory ring buffer, trace taps for instrumentation, a dedicated API, and an embedded HTML/JS UI for live viewing with filtering and session management. Sensitive headers are redacted for security.

### Persistence Layer

Defaults to a file-based JSON store for identity, KEL, contacts, settings, pending requests, profile, and endpoint data, with a modular `store.Store` interface for swappable backends. Onboarding state is persisted via SharedPreferences.

### Grape ID Tunnel Integration

This integration provides a permanent public URL for the agent's OOBI endpoints using a Chisel reverse proxy. It supports a reconnect-first flow on startup to re-establish previously claimed names, with AID-based ownership for security. It handles tunnel reconnection on mobile app restart, ensuring continuous availability.

## External Dependencies

### Backend (Go)

-   `github.com/go-chi/chi/v5`: HTTP router.
-   `github.com/go-chi/cors`: CORS middleware.
-   `golang.ngrok.com/ngrok`: In-memory tunnel client.
-   `github.com/jpillora/chisel` v1.9.1: Chisel client for Grape ID reverse proxy tunnels.
-   `github.com/gorilla/websocket` v1.5.3: WebSocket connections.
-   `github.com/mattn/go-sqlite3`: SQLite driver for sandbox.db (desktop only).
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
-   `flutter_inappwebview` ^6.0.0: WebView for sandbox app display (desktop only).
-   `url_launcher`: Open URLs in system browser.
-   `web_socket_channel` ^3.0.1: WebSocket client.