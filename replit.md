# Identity Agent

## Overview

The Identity Agent is a self-sovereign digital identity platform designed to unify identity, data, communications, and assets using the KERI (Key Event Receipt Infrastructure) protocol. The project aims to provide a single, integrated environment for digital identity, empowering users with full control over their digital identities, enhancing privacy and security across various digital interactions. Key capabilities include identity creation, KERI inception events, Key Event Log (KEL) persistence, adaptive mobile architecture, OOBI serving/sharing, QR code generation/scanning, contact management, multi-provider tunneling, and user onboarding flows with OOBI-based server connection for cryptographic trust establishment.

## User Preferences

Preferred communication style: Simple, everyday language.
Design theme: Dark cyberpunk aesthetic with monospace fonts, dark blue/green color scheme.

## System Architecture

The system uses an adaptive architecture to integrate the KERI engine, resulting in distinct operating modes:

1.  **Desktop Mode (Linux/macOS/Windows):** The Flutter UI communicates with a Go backend, which drives a Python KERI engine (`keripy`) running as a local child process.
2.  **Mobile Standalone Mode (iOS/Android):** The Flutter UI interacts with a local Rust KERI library (`keriox/keri-core`) via FFI for all stateful/private key operations.
3.  **Mobile Remote Controller Modes (With/Without Keys):** These modes allow the phone to connect to an existing Identity Agent server, delegating computing power while potentially retaining root keys or relying on the server for key management.

A `KeriService` Dart abstract class provides a mode-agnostic interface for KERI operations, ensuring UI code remains independent of the underlying operating mode.

### Component Details

-   **Go Backend (`identity-agent-core/`):** Core orchestration, public API serving, file-based data persistence, spawning the Python KERI driver (desktop), serving Flutter web assets, OOBI serving/generation, contact management, and optional tunnel providers.
-   **Python KERI Driver (`drivers/keri-core/`):** The KERI protocol engine (`keripy` v1.1.17) for desktop, exposing stateful and stateless KERI endpoints.
-   **Flutter Frontend (`identity_agent_ui/`):** Cross-platform UI with a dark cyberpunk theme, multi-step onboarding, BIP-39 mnemonic generation, contact management, and OOBI URL sharing.
-   **Rust Bridge (`identity_agent_ui/rust/`):** The mobile KERI engine (THCLab `keriox/keri-core`) integrated via `flutter_rust_bridge` for Dart ↔ Rust FFI, providing core KERI functions.
-   **Tunnel Module (`identity-agent-core/tunnel/`):** Multi-provider tunnel system (e.g., Cloudflare, ngrok) for public HTTPS URL acquisition, with settings persisted and configurable via the Settings UI and API.

### Key Design Decisions

-   **Go for Backend:** Orchestration, single binary compilation, and driver lifecycle management.
-   **Python for KERI (Desktop):** Leverages `keripy` as the established KERI implementation.
-   **Rust for KERI (Mobile):** Provides native mobile KERI capabilities via FFI with `keriox`.
-   **Driver Pattern:** Ensures consistent HTTP-based internal communication across modes.
-   **Flutter for Frontend:** Cross-platform UI development.
-   **Local-First Storage:** Emphasizes user sovereignty and data control.

### Persistence Layer

Defaults to a file-based JSON store in `./data/` (`identity.json`, `kel.json`, `contacts.json`, `settings.json`), with a modular `store.Store` interface for swappable backends.

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