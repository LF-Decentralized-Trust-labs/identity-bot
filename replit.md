# Identity Agent

## Overview

The Identity Agent is a user-controlled digital identity agent that unifies identity, data, communications, and assets using the KERI protocol. Its core purpose is to empower users with full control over their digital identities, enhancing privacy and security across digital interactions. Key capabilities include identity creation, KERI inception events, Key Event Log (KEL) persistence, adaptive mobile architecture, OOBI serving/sharing, QR code generation/scanning, contact management, multi-provider tunneling, and user onboarding with OOBI-based server connection for cryptographic trust establishment.

## User Preferences

Preferred communication style: Simple, everyday language.
Design theme: Dark cyberpunk aesthetic with monospace fonts, dark blue/green color scheme.
Build/Distribution: No App Store or Play Store submissions. All builds are for local testing only — iOS uses Codemagic's built-in simulator/virtual testing (no TestFlight, no Apple Developer account signing). Android produces unsigned APKs/debug builds. Do not add code signing, provisioning profiles, or store-related configuration.
Build versioning: All Codemagic workflows pass `--build-number=$BUILD_NUMBER` (Codemagic auto-incrementing) to `flutter build` commands. This ensures Android APKs can be installed over previous versions without uninstalling first (versionCode must increase). Same pattern applied to iOS, Windows, macOS, and Linux for consistent version tracking.
**Development phase (current)**: Auto-increment build number via `$BUILD_NUMBER`. Version in `pubspec.yaml` stays at `1.0.0+1`. Build counts (1, 2, 3, ... thousands) are fine for internal/development use.
**Official releases (future)**: When publishing to Play Store/App Store, switch to semantic versioning in `pubspec.yaml` (e.g., `1.0.0+1`, `1.0.1+2`, `1.1.0+3`, `2.0.0+4`). At that point, remove `--build-number=$BUILD_NUMBER` from Codemagic and manually specify versions for each official release build.

## System Architecture

The system uses a two-topology model with four launch configurations. Every Identity Agent instance is in one of two topologies: **Phone + Computer** (keys on phone, computer handles storage and always-on services) or **Computer only** (keys and data on the computer). In either topology, the computer can be the user's own or a **black box computer** — professionally managed in a data center, sealed via TEE attestation so the operator provably cannot read into it. Internal/architecture term: **black box infrastructure** (doctrine D10). A critical invariant is that stateful KERI operations always use the local engine, with paired/remote computers handling only backend services and stateless operations.

### Topologies and Configurations

**Two topologies:**
1. **Phone + Computer**: Identity created on the phone; keys live on the phone. The phone pairs with a computer that handles storage, computing, and always-on services.
2. **Computer only**: Identity and keys live on the computer. No phone required.

**Four launch configurations:**
1. Phone + Computer (black box computer) — recommended default; 60-second setup, no hardware to maintain, always-on.
2. Phone + Computer (own computer) — willing to leave a laptop/desktop on 24/7 and maintain it.
3. Computer only (own computer) — power users, privacy maximalists, single-device households.
4. Computer only (black box computer) — no smartphone *and* no personal computer.

### Device Types

-   **Computer** (Linux/macOS/Windows): Utilizes a Go backend with Python `keripy` for KERI and Go Core for backend services.
-   **Phone** (iOS/Android): Employs a Rust bridge via FFI for KERI and Go Core via `gomobile` for embedded backend (used in phone-only fallback / offline credential verification mode within Phone + Computer).

### Core Components and Technologies

-   **Go Backend (`identity-agent-core/`):** Handles core orchestration, public API, file-based data persistence, OOBI management, contact management, and optional tunnel providers. Compiles for mobile via `gomobile` (with KERI driver disabled).
-   **Python KERI Driver (`drivers/keri-core/`):** The `keripy` (v1.1.17) engine for desktop KERI operations.
-   **Flutter Frontend (`identity_agent_ui/`):** Cross-platform UI with two modes: Desktop Mode (dark cyberpunk theme, 5-tab bottom nav) and Mobile Mode (clean light theme with blue accents, 3-button bottom nav). Features multi-step onboarding, BIP-39 mnemonic generation, contact management, OOBI sharing, profile management (jCard), and a mode-aware dashboard.
-   **Rust Bridge (`identity_agent_ui/rust/`):** Implements the mobile KERI engine (`keriox/keri-core`) via `flutter_rust_bridge` for Dart ↔ Rust FFI, providing core KERI crypto functions.
-   **Tunnel Module (`identity-agent-core/tunnel/`):** Manages multi-provider tunnels (Cloudflare, ngrok, Grape ID) for public HTTPS URL acquisition.
-   **Endpoint Service (`identity-agent-core/endpoint/`):** Single source of truth for the agent's current public base URL, persisting to `endpoint.json`.
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
-   **Port Conflict Handling:** Default port is 5050. On startup, the Go backend auto-detects port conflicts and falls back to 5051–5059 if needed. The actual port is written to `data/.port` for the Flutter UI to discover. Stale Identity Agent processes are auto-killed.
-   **libsodium Bundling (Windows):** `libsodium.dll` is downloaded from the official release and bundled into the embedded Python dir, backend dir, and keri-driver dir. The KERI driver's `server.py` has Windows-specific detection logic to find the DLL.
-   **Podman Setup UX (APPS tab):** When Podman is not available, the marketplace shows a multi-step setup wizard that automatically installs Podman and configures the Podman machine. The wizard uses platform-specific package managers (`winget` on Windows, `brew` on macOS, `apt`/`dnf` on Linux) and handles machine init/start on macOS/Windows. Users only need to approve system prompts (UAC/password). Falls back to manual download links if no supported package manager is detected. Backend endpoints: `POST /api/sandbox/podman/setup` (actions: `install`, `init-machine`, `start-machine`) and `GET /api/sandbox/podman/setup-status` for progress polling.
-   **Sandbox Security:** Runtime-injected environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `IDENTITY_AGENT_API`) are reserved and cannot be overridden by manifest-defined environment variables. This prevents sandbox bypass via manifest manipulation. Applied in both binary and container runtimes.
-   **IPv4 Loopback Enforcement (Sandbox):** All sandbox proxy URLs, agent API URLs, and display URLs use `127.0.0.1` (not `localhost`) to avoid Windows IPv6 resolution issues.
-   **Marketplace Apps:** Chromium Browser (KasmVNC), Go Demo (compiled binary), Excalidraw (collaborative whiteboard), Open WebUI (AI chat interface via OpenRouter proxy).

### Sandboxed App Marketplace (Desktop-Only)

This desktop-only feature enables sandboxed application execution via OCI containers (Podman) and compiled binaries. It includes a comprehensive sandbox package for storage, manifest loading, runtime abstraction, networking, policy enforcement, and resource monitoring. Key features include a pure Go forward proxy with MITM TLS interception, a policy engine for domain access, a credential vault, and resource monitoring with escalation. The marketplace UI uses compact ListView cards (~90px height) with inline status badges, install progress bars (polling `GET /api/apps/{id}/install-progress` every 2s), mini CPU/RAM resource indicators for running apps, and full lifecycle actions (INSTALL → LAUNCH → VIEW/STOP → UNINSTALL). Uninstall resets app status to `available` (not deleted) so users can reinstall in-session. The Go demo binary (`sandbox-apps/go-demo/`) is built and placed at `bin/go-demo` relative to the working directory; `binary_runtime.go` auto-appends `.exe` on Windows. Container runtime uses Podman CLI (not Docker API) for all container operations — rootless, daemonless, and free of licensing concerns.

### Sandbox Trace Debugger (Developer-Only)

A developer-only diagnostic tool providing real-time visibility into sandbox request pipelines. It features a trace core with an in-memory ring buffer, trace taps for instrumentation, a dedicated API, and an embedded HTML/JS UI for live viewing with filtering and session management. Sensitive headers are redacted for security.

### Persistence Layer

Defaults to a file-based JSON store in `./data/` (`identity.json`, `kel.json`, `contacts.json`, `settings.json`, `pending_requests.json`, `profile.json`, `endpoint.json`), with a modular `store.Store` interface for swappable backends. In phone-only fallback mode (offline credential verification within Phone + Computer), Go Core stores data in the app's documents directory. Onboarding state (mode, entity type, setup completion) is persisted via SharedPreferences. Profile data (jCard fields + photo) is stored in `profile.json` and served via OOBI endpoints and exchange introductions.

### Mobile UI Architecture

The mobile UI (`lib/screens/mobile/`) is a separate screen set from the desktop UI, activated when `Platform.isAndroid || Platform.isIOS` is true OR when the screen width is below 768px (responsive web support). It uses a clean light theme (`MobileTheme`) with IBM Blue 60 (`#4589FF`) as primary color. It includes a dashboard, bottom navigation, drawer menu, share menu, QR scanner, chatbot panel, profile editor, contacts screen, settings screen, and various onboarding screens.

### Grape ID Tunnel Integration

This integration provides a permanent public URL for the agent's OOBI endpoints using a Chisel reverse proxy. It supports a reconnect-first flow on startup to re-establish previously claimed names, with AID-based ownership for security. It handles tunnel reconnection on mobile app restart, ensuring continuous availability.

### Windows Desktop Build Optimization

Windows builds from Codemagic no longer embed Python to reduce build time (13 min → 6 min) and ZIP size (1GB → 300MB). Users must install Python 3.10+ locally with `flask` and `keri==1.1.17` via pip. The app automatically finds Python from the system PATH at runtime. See `DESKTOP_SETUP.md` for detailed instructions.

## External Dependencies

### Backend (Go)

-   `github.com/go-chi/chi/v5`: HTTP router.
-   `github.com/go-chi/cors`: CORS middleware.
-   `golang.ngrok.com/ngrok`: In-memory tunnel client.
-   `github.com/jpillora/chisel` v1.9.1: Chisel client for Grape ID reverse proxy tunnels.
-   `github.com/gorilla/websocket` v1.5.3: WebSocket connections.
-   `github.com/mattn/go-sqlite3`: SQLite driver for sandbox.db (desktop only).
-   `cloudflared`: System dependency for Cloudflare desktop tunnels.
-   Podman: System dependency for sandboxed app container runtime (desktop only).

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
-   `flutter_inappwebview` ^6.0.0: WebView for sandbox app display (desktop only).
-   `url_launcher`: Open URLs in system browser.
-   `web_socket_channel` ^3.0.3: WebSocket client for real-time event streaming.

### Real-Time Event System

The Go backend includes a WebSocket-based EventHub (`identity-agent-core/server/events.go`) using `gorilla/websocket`. The Flutter frontend connects via `EventService` singleton (`lib/services/event_service.dart`).

-   **WebSocket endpoint**: `GET /api/ws/events` — upgrades to WebSocket, pushes events to all connected clients.
-   **Event types**: `introduction_received` (new inbound contact request), `contact_accepted` (contact upgraded to mutual), `pending_request_received` (OOBI-unreachable sender).
-   **Architecture**: Same WebSocket URL works for both standalone (localhost) and remote controller (tunnel URL) modes. EventService auto-reconnects with exponential backoff and generation-based connection tracking.
-   **Popup behavior**: Connection request popups only appear on the OOBI QR sharing screen (`_AddContactScreen` in `share_menu.dart`). The dashboard updates alert badge counts silently via WebSocket events with a 60-second HTTP fallback poll.

### Two-Layer OOBI Exchange Architecture

The OOBI exchange process is designed as two conceptual layers:

-   **Layer 1 (Cryptographic Trust)**: Mandatory KERI handshake — resolves the remote agent's AID, verifies the KEL. Strictly protocol-level, independent of user intent. No profile data (jCard/photo) is exchanged at this layer.
-   **Layer 2 (Application Intent)**: After Layer 1 succeeds, the user's interaction purpose is executed (e.g., Add Contact, Request Payment, Verify Credential). Profile data (jCard, photo) is fetched and displayed only at this layer. The `intent` parameter in OOBI URLs will route to the appropriate interaction flow (currently only `add_contact` is implemented; others show "Coming Soon").

### Contact Photo Flow

-   `ContactRecord` in Go (`store.go`) has a `Photo` field for base64-encoded profile photos.
-   The OOBI serve endpoint (`/oobi/{aid}`) includes `photo` and `jcard` in its response.
-   The resolve endpoint (`/api/contacts/resolve`) forwards `photo` and `jcard` from the OOBI response.
-   The reverse introduction exchange payload includes `sender_photo` and `sender_jcard`.
-   WebSocket `introduction_received` events carry `sender_photo` and `sender_jcard` for real-time UI display.
-   All Flutter contact UI surfaces (QR consent dialog, connection popup, contact cards, contact detail screen, dashboard alert cards) display photos when available, with initials fallback.
