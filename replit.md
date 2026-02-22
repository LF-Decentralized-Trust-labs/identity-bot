# Identity Agent

## Overview

The Identity Agent is a self-sovereign digital identity platform designed to unify identity, data, communications, and assets using the KERI (Key Event Receipt Infrastructure) protocol. The project aims to provide a single, integrated environment for digital identity, empowering users with full control over their digital identities, enhancing privacy and security across various digital interactions. Key capabilities include identity creation, BIP-39 mnemonic generation, KERI inception events, Key Event Log (KEL) persistence, adaptive mobile architecture, OOBI serving/sharing, QR code generation/scanning, contact management, multi-provider tunneling, Settings UI, tunnel configuration persistence, user onboarding flows, and OOBI-based server connection for cryptographic trust establishment. The project is currently in **Phase 3 ("Connectivity")**.

## User Preferences

Preferred communication style: Simple, everyday language.
Design theme: Dark cyberpunk aesthetic with monospace fonts, dark blue/green color scheme.

## System Architecture

The system utilizes an adaptive architecture to integrate the KERI engine, primarily due to `keripy` (Python) not being mobile-compatible, leading to distinct operating modes:

-   **Desktop Mode:** The full stack (Flutter UI, Go backend, Python KERI engine) runs on a single machine. The Go backend orchestrates, persists data, and serves the API, while the Python KERI engine handles core KERI operations.
-   **Mobile Standalone Mode:** The Flutter UI interacts with a local Rust KERI library via FFI for all stateful/private key operations. The phone acts as the primary key holder and identity owner.
-   **Mobile Remote Controller WITH Keys:** A migration path where keys remain on the phone, but a remote server creates a delegated AID, offloading computing.
-   **Mobile Remote Controller WITHOUT Keys:** The phone connects to an existing Identity Agent server, and the remote server retains the root keys and handles most KERI operations.

A `KeriService` Dart abstract class provides a mode-agnostic interface for KERI operations, ensuring UI code remains independent of the underlying operating mode.

**Trust Boundaries:**
-   **User's own server & Rust Bridge:** Full trust, as key material is handled directly by user-owned infrastructure or local device.
-   **Remote Helper:** Zero trust, only handles stateless tasks.

**Component Details:**
-   **Go Backend:** Orchestration layer, public API (port 5000), data persistence (file-based), Python KERI driver management (desktop), Flutter web asset serving, OOBI handling, contact management, and optional ngrok tunneling.
-   **Python KERI Driver:** KERI protocol engine (`keripy` v1.1.17) for desktop, running locally.
-   **Flutter Frontend:** Cross-platform UI with a dark cyberpunk theme, multi-step onboarding (mode selection → entity type → setup wizard / server connection), BIP-39 mnemonic generation, contact management, and OOBI URL sharing. On mobile, "Create New" goes directly to the Setup Wizard (Standalone mode, Rust bridge handles KERI locally, no server URL needed). "Connect to Existing" prompts for a server URL, validates via `/api/health`, and uses `MobileStandaloneKeriService` with the remote server as the stateless helper (Rust bridge for stateful ops, remote server for stateless ops). On desktop, "Connect to Existing" uses `DesktopKeriService` pointed at the remote URL. All dashboard screens accept an optional `serverUrl` parameter for proper backend connectivity. See ADR-005.
-   **Rust Bridge:** Mobile KERI engine (`keriox/keri-core`) integrated via `flutter_rust_bridge` for Dart ↔ Rust FFI.
-   **KeriHelperClient:** HTTP client for stateless operations in Mobile Standalone Mode.
-   **Tunnel Module:** Multi-provider tunnel system supporting Cloudflare and ngrok, with configuration persistence.

**Driver Pattern:** The Go backend always spawns the Python KERI driver as a local child process, communicating via HTTP. The Python driver dictates KERI-related endpoint naming and functionality across all implementations.

**Cryptographic Key Hierarchy:** A 3-level hierarchy consisting of Root Authority (BIP-39 mnemonic), Device Authority (Secure Enclave keys), and Delegated Agent (encrypted database keys).

**Persistence Layer:** Defaults to a file-based JSON store in `./data/`, with a modular `store.Store` interface for swappable backends.

**Key Design Decisions:**
-   **Go for Backend:** Orchestration, single binary.
-   **Python for KERI (Desktop):** Leverages `keripy`.
-   **Rust for KERI (Mobile):** Native mobile KERI via FFI with `keriox`.
-   **Driver Pattern:** Consistent internal communication.
-   **Flutter for Frontend:** Cross-platform capabilities.
-   **Local-First Storage:** User sovereignty, no third-party accounts.

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

-   `keri-core` 0.11.1: THCLab KERI implementation.
-   `flutter_rust_bridge` 2.11.1: Dart ↔ Rust FFI bridge.
-   `base64` 0.13: Base64 encoding/decoding.
-   `serde` 1.0 + `serde_json` 1.0: JSON serialization.

### Frontend (Flutter/Dart)

-   Flutter SDK (v3.22.0).
-   `http`: HTTP client.
-   `crypto`: SHA-256 for key derivation.
-   `ed25519_edwards`: Ed25519 key generation.