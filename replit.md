# Identity Agent

## Overview

The Identity Agent is a self-sovereign digital identity platform designed to unify identity, data, communications, and assets. It leverages the KERI (Key Event Receipt Infrastructure) protocol for decentralized identity management, aiming to provide a single, integrated environment for digital identity. The project is currently in **Phase 3 ("Connectivity")**, with core functionalities like identity creation, BIP-39 mnemonic generation, KERI inception events, Key Event Log (KEL) persistence, adaptive mobile architecture, OOBI serving/sharing, contact management, and optional ngrok tunneling already implemented. The business vision is to empower users with full control over their digital identities, enhancing privacy and security across various digital interactions.

## User Preferences

Preferred communication style: Simple, everyday language.
Design theme: Dark cyberpunk aesthetic with monospace fonts, dark blue/green color scheme.

## System Architecture

### Adaptive Architecture: Three Operating Modes

The system uses an adaptive architecture to integrate the KERI engine, primarily due to `keripy` (Python) not being mobile-compatible. This results in three distinct operating modes:

1.  **Desktop Mode (Linux/macOS/Windows):** The full stack runs on a single machine. The Flutter UI communicates with a Go backend (port 5000), which in turn drives a Python KERI engine (`keripy` v1.1.17) running as a local child process (port 9999). The Go backend handles orchestration, persistence, and API serving, while Python performs all KERI operations.

2.  **Mobile Remote Mode (iOS/Android):** For users with their own server running Desktop Mode. The mobile Flutter UI sends all KERI requests over HTTPS to the user's remote primary server, which executes the operations. No KERI engine runs on the phone.

3.  **Mobile Standalone Mode (iOS/Android):** For users without a personal server. The Flutter UI interacts with a local Rust KERI library (THCLab `keriox/keri-core`) via a Foreign Function Interface (FFI) for private key operations. Stateless tasks (e.g., formatting, parsing) are offloaded to an external server, which can be the user's publicly accessible Go backend or a zero-trust public Remote Helper service.

### Trust Boundaries

-   **User's own server (Desktop/Mobile Remote) & Rust Bridge (Mobile Standalone):** Full trust, as key material is handled directly by the user's owned infrastructure or local device.
-   **Remote Helper (Mobile Standalone fallback):** Zero trust, only handles stateless tasks without access to private keys.

### KeriService Abstraction Layer

A `KeriService` Dart abstract class provides a mode-agnostic interface for KERI operations (`inceptAid`, `rotateAid`, `signPayload`, `getCurrentKel`, `verifySignature`), ensuring UI code remains independent of the underlying operating mode.

### Component Details

-   **Go Backend (`identity-agent-core/`):** The core orchestration layer, serving the public API on port 5000, managing file-based data persistence, spawning the Python KERI driver (desktop), serving Flutter web assets, OOBI serving/generation, contact management, and optional ngrok tunneling for public HTTPS URL acquisition.
-   **Python KERI Driver (`drivers/keri-core/`):** The KERI protocol engine (keripy v1.1.17) for desktop, running locally on `127.0.0.1:9999`.
-   **Flutter Frontend (`identity_agent_ui/`):** The cross-platform user interface featuring a dark cyberpunk theme, BIP-39 mnemonic generation, Setup Wizard for identity creation, bottom navigation with Dashboard/Contacts/OOBI tabs, contact management, and OOBI URL sharing, utilizing `KeriService` for backend interaction.
-   **Rust Bridge (`identity_agent_ui/rust/`):** The mobile KERI engine (THCLab `keriox/keri-core`) integrated via `flutter_rust_bridge` for Dart ↔ Rust FFI.
-   **KeriHelperClient:** An HTTP client for the remote helper, used for stateless operations in Mobile Standalone Mode.
-   **Tunnel Module (`identity-agent-core/tunnel/`):** Optional ngrok-go integration for automatic public HTTPS URL acquisition. Activated when `NGROK_AUTHTOKEN` env var is set.

### Driver Pattern

The Go backend always spawns the Python KERI driver as a local child process, communicating via HTTP on `127.0.0.1:9999`. The Python driver dictates the naming and functionality of all KERI-related endpoints across all implementations (Go proxy, Rust bridge, Remote Helper).

### Cryptographic Key Hierarchy

A 3-level hierarchy:
1.  **Root Authority:** 128-bit salt / 12-word BIP-39 mnemonic (never stored on active devices).
2.  **Device Authority:** Keys generated in device Secure Enclave for daily operations.
3.  **Delegated Agent:** Operational keys stored in the backend's encrypted database.

### Persistence Layer

Defaults to a file-based JSON store in `./data/` (`identity.json`, `kel.json`, `contacts.json`), with a modular `store.Store` interface allowing for swappable backends (e.g., BadgerDB, PostgreSQL).

### Key Design Decisions

-   **Go for Backend:** Selected for orchestration, single binary compilation, and driver lifecycle management.
-   **Python for KERI (Desktop):** Leverages `keripy` as the battle-tested KERI implementation.
-   **Rust for KERI (Mobile):** Provides native mobile KERI capabilities via FFI with `keriox`.
-   **Driver Pattern:** Ensures consistent HTTP-based internal communication across modes.
-   **Flutter for Frontend:** Chosen for its cross-platform capabilities (mobile, desktop, web).
-   **Local-First Storage:** Emphasizes user sovereignty and eliminates third-party account requirements.

## External Dependencies

### Backend (Go)

-   `github.com/go-chi/chi/v5`: HTTP router.
-   `github.com/go-chi/cors`: CORS middleware.
-   `golang.ngrok.com/ngrok`: Optional tunnel client for automatic public HTTPS URL.
-   Standard Go library for networking, JSON encoding, cryptography, and process execution.

### KERI Driver (Python, desktop only)

-   `flask`: Lightweight HTTP server.
-   `keri`: WebOfTrust reference KERI library v1.1.17 (hard requirement).

### Rust Bridge (mobile only)

-   `keri-core` 0.11: THCLab KERI implementation (EUPL-1.2 licensed).
-   `flutter_rust_bridge` 2.7.0: Dart ↔ Rust FFI bridge.
-   `said` 0.5, `cesrox` 0.6: KERI supporting crates.

### Frontend (Flutter/Dart)

-   Flutter SDK (v3.22.0).
-   `http`: HTTP client for API calls.
-   `crypto`: SHA-256 for key derivation.
-   `ed25519_edwards`: Ed25519 key generation.