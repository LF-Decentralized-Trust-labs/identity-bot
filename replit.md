# Identity Agent

## Overview

The Identity Agent is a self-sovereign digital identity platform that unifies identity, data, communications, and assets into a single environment. It implements the KERI (Key Event Receipt Infrastructure) protocol for decentralized identity management. The system uses an adaptive architecture with three operating modes: Desktop (Go + Python keripy), Mobile Remote (remote primary server), and Mobile Standalone (Rust bridge + Remote Helper).

The project is currently in **Phase 2 ("Inception")** — identity creation, BIP-39 mnemonic, KERI inception events, KEL persistence, and adaptive mobile architecture are all working.

## User Preferences

Preferred communication style: Simple, everyday language.
Design theme: Dark cyberpunk aesthetic with monospace fonts, dark blue/green color scheme.

## System Architecture

### Adaptive Architecture: Three Operating Modes

The system detects the runtime environment and selects the appropriate KERI service implementation:

#### 1. Desktop Mode (Linux/macOS/Windows/Web)
```
Flutter UI → Go Backend (port 5000) → Python KERI Driver (port 9999/keripy)
```
- Go backend handles orchestration, persistence, API serving
- Python KERI driver performs all KERI operations using keripy v1.1.17 (hard requirement)
- Go spawns Python as child process (dev) or connects via KERI_DRIVER_URL (prod)

#### 2. Mobile Remote Mode (iOS/Android + PRIMARY_SERVER_URL)
```
Flutter UI → Remote Primary Server (user's own server running Desktop Mode)
```
- Mobile device acts as remote controller for user's primary server
- All KERI operations routed to remote server's API
- Local Go backend on mobile enters Backup Mode or is stopped

#### 3. Mobile Standalone Mode (iOS/Android, no PRIMARY_SERVER_URL)
```
Flutter UI → Rust Bridge (FFI, local) + Remote Helper (stateless, public)
```
- Rust bridge (THCLab keriox/keri-core) handles private key operations locally via FFI
- Go backend runs on mobile in Primary Mode but without Python driver
- Remote Helper is a separate public stateless service for formatting tasks only (zero trust)

### Trust Boundaries
- **Primary Server:** Full trust — user's own server, handles all key material
- **Remote Helper:** Zero trust — public utility, never sees private keys. Only does: format-credential, resolve-oobi, generate-multisig-event
- **Rust Bridge:** Full trust — runs locally on device, handles all crypto

### KeriService Abstraction Layer

All three modes implement the same `KeriService` Dart abstract class:
- `inceptAid()` — Create a new Autonomous Identifier
- `rotateAid()` — Rotate keys for an existing AID
- `signPayload()` — Sign arbitrary data
- `getCurrentKel()` — Retrieve the Key Event Log
- `verifySignature()` — Verify a signature against a public key

UI code is completely mode-agnostic — no platform branching in screens.

### Component Details

1. **Go Backend (`identity-agent-core/`)** — The orchestration layer:
   - Serves the public API on port 5000 (`/api/*`)
   - Manages data persistence (file-based store, swappable to BadgerDB/PostgreSQL)
   - Spawns and manages the Python KERI driver process (desktop only)
   - Bridges Flutter requests to the KERI driver
   - Serves Flutter web build as static files
   - API endpoints: `/api/health`, `/api/info`, `/api/inception`, `/api/identity`
   - Available on BOTH desktop and mobile (but Python driver only on desktop)

2. **Python KERI Driver (`drivers/keri-core/`)** — The KERI protocol engine (desktop only):
   - Runs on `127.0.0.1:9999` (never exposed publicly)
   - Uses keripy v1.1.17 (hard requirement, no fallback)
   - Cannot run on mobile OS

3. **Flutter Frontend (`identity_agent_ui/`)** — The controller UI:
   - Dark cyberpunk theme, monospace fonts
   - BIP-39 mnemonic seed phrase generation and backup flow
   - Setup Wizard for new identity creation
   - KeriService dependency injection — mode-agnostic

4. **Rust Bridge (`identity_agent_ui/rust/`)** — Mobile KERI engine:
   - THCLab keriox/keri-core (EUPL-1.2 licensed)
   - flutter_rust_bridge v2 for Dart ↔ Rust FFI
   - 5 bridge functions: incept_aid, rotate_aid, sign_payload, get_current_kel, verify_signature
   - Compiled locally with native toolchains (Xcode/NDK), not on Replit

5. **KeriHelperClient** — Remote Helper HTTP client:
   - Separate from primary server — distinct trust boundary
   - Configurable via KERI_HELPER_URL
   - Operations: format-credential, resolve-oobi, generate-multisig-event

### Driver Pattern (Desktop)

- **Development/Replit (Linux):** Go spawns Python as a child process via `exec.Command()`. Communication via `localhost:9999`.
- **Production (Server):** Python driver runs as a separate service. Go connects via `KERI_DRIVER_URL` environment variable.

Key environment variables:
- `KERI_DRIVER_URL` — If set, Go connects to this URL instead of spawning Python
- `KERI_DRIVER_PORT` — Port for the managed Python driver (default: 9999)
- `KERI_DRIVER_SCRIPT` — Path to server.py (default: `./drivers/keri-core/server.py`)
- `KERI_DRIVER_PYTHON` — Python binary path (default: `python3`)
- `PRIMARY_SERVER_URL` — Remote server URL for Mobile Remote Mode
- `KERI_HELPER_URL` — Public stateless Remote Helper URL for Mobile Standalone Mode

### Build System (Shell Scripts, No Node.js)

- `scripts/start-backend.sh` — Installs Python deps, builds Go binary, launches Go server
- `scripts/build-flutter.sh` — Builds Flutter web assets only; Go picks them up automatically
- No package.json, no npm, no node_modules — pure shell scripts

### Workflows (Fully Decoupled)

- **Start Backend** (`sh ./scripts/start-backend.sh`) — Installs Python deps, builds Go, starts Go server + KERI driver
- **Start Frontend** (`sh ./scripts/build-flutter.sh`) — Builds Flutter web assets independently

### Cryptographic Key Hierarchy (3-Level)

- **Level 1 — Root Authority:** 128-bit salt / 12-word BIP-39 mnemonic. Never stored on active devices.
- **Level 2 — Device Authority:** Keys generated in device Secure Enclave. Signs daily operations.
- **Level 3 — Delegated Agent:** Operational keys stored in the backend's encrypted database.

### Persistence Layer

- **Default:** File-based JSON store in `./data/` directory (identity.json, kel.json)
- **Configurable:** Modular storage interface (`store.Store`) supports swapping backends
- **Data files:** `data/identity.json` (current identity state), `data/kel.json` (Key Event Log)

### Implementation Roadmap (follow strictly in order)

- **Phase 1 (COMPLETE):** Skeleton — Go HTTP server, Flutter dashboard, bridge between them, health check
- **Phase 2 (COMPLETE):** Inception — BIP-39 mnemonic, KERI inception event via Python driver, KEL persistence, Setup Wizard, adaptive mobile architecture (KeriService abstraction, Rust bridge, Remote Helper client)
- **Phase 3 (next):** Connectivity — Public URL tunneling, OOBI generation, QR scanning, contact resolution
- **Phase 4:** Credentials — Credential schemas, IPEX protocol, organization mode, verification logic

### Key Design Decisions

- **Why Go for backend:** Orchestration layer, compiles to single binary, manages driver lifecycle, available on mobile
- **Why Python for KERI (desktop):** keripy is the most battle-tested KERI implementation; cannot run on mobile
- **Why Rust for KERI (mobile):** THCLab keriox provides native KERI on mobile via FFI; no Python needed
- **Why Driver Pattern:** HTTP-based internal communication means same Go code works everywhere
- **Why Remote Helper is separate:** Zero-trust public service distinct from user's primary server
- **Why Flutter for frontend:** Cross-platform (mobile + desktop + web), native hardware access
- **Why local-first storage:** Sovereignty by default — no third-party accounts required
- **Why no Node.js:** Eliminated unnecessary JavaScript layer; Go serves Flutter web directly

## Key Files

- `identity-agent-core/main.go` — Go backend entry point, HTTP server, API routes, driver lifecycle
- `identity-agent-core/drivers/keri_driver.go` — Go HTTP client for the Python KERI driver
- `identity-agent-core/store/store.go` — File-based persistence (Store interface + FileStore implementation)
- `drivers/keri-core/server.py` — Python Flask HTTP server for KERI operations
- `drivers/keri-core/requirements.txt` — Python dependencies (flask, keri)
- `identity_agent_ui/lib/main.dart` — Flutter app entry point, environment detection, DI routing
- `identity_agent_ui/lib/services/keri_service.dart` — Abstract KeriService interface + AgentEnvironment enum
- `identity_agent_ui/lib/services/desktop_keri_service.dart` — Desktop mode: Flutter → Go → Python keripy
- `identity_agent_ui/lib/services/remote_server_keri_service.dart` — Mobile Remote mode: Flutter → Remote Server
- `identity_agent_ui/lib/services/mobile_standalone_keri_service.dart` — Mobile Standalone: Rust bridge + Helper
- `identity_agent_ui/lib/services/keri_helper_client.dart` — HTTP client for public stateless Remote Helper
- `identity_agent_ui/lib/bridge/keri_bridge.dart` — Dart interface for Rust FFI (flutter_rust_bridge)
- `identity_agent_ui/rust/src/api/keri_bridge.rs` — Rust KERI implementation (THCLab keriox)
- `identity_agent_ui/rust/Cargo.toml` — Rust dependencies (keri-core, flutter_rust_bridge, said, cesrox)
- `identity_agent_ui/lib/services/core_service.dart` — HTTP client for Go API (health, info, identity)
- `identity_agent_ui/lib/screens/setup_wizard_screen.dart` — Setup Wizard (mnemonic + inception)
- `identity_agent_ui/lib/screens/dashboard_screen.dart` — Main dashboard UI
- `identity_agent_ui/lib/crypto/bip39.dart` — BIP-39 mnemonic generator
- `identity_agent_ui/lib/crypto/keys.dart` — Ed25519 key derivation from mnemonic
- `identity_agent_ui/lib/config/agent_config.dart` — Backend URL + PRIMARY_SERVER_URL + KERI_HELPER_URL config
- `scripts/start-backend.sh` — Build + launch script (Go + Python driver)
- `scripts/build-flutter.sh` — Flutter web build script
- `docs/adr/001-core-architecture-stack.md` — ADR: original architecture decisions
- `docs/adr/002-keri-driver-pattern.md` — ADR: Python driver pattern, keripy requirement
- `docs/adr/003-adaptive-architecture.md` — ADR: Three operating modes, trust boundaries, Remote Helper

## External Dependencies

### Backend (Go)
- `github.com/go-chi/chi/v5` — HTTP router
- `github.com/go-chi/cors` — CORS middleware
- Standard library (net/http, encoding/json, crypto/ed25519, os/exec)

### KERI Driver (Python, desktop only)
- `flask` — Lightweight HTTP server
- `keri` (required) — WebOfTrust reference KERI library v1.1.17 (hard requirement, no fallback)

### Rust Bridge (mobile only)
- `keri-core` 0.11 — THCLab KERI implementation (EUPL-1.2)
- `flutter_rust_bridge` 2.7.0 — Dart ↔ Rust FFI bridge
- `said` 0.5, `cesrox` 0.6 — KERI supporting crates

### Frontend (Flutter/Dart)
- Flutter SDK (v3.22.0)
- `http` — HTTP client for API calls
- `crypto` — SHA-256 for key derivation
- `ed25519_edwards` — Ed25519 key generation

### Infrastructure
- Replit hosting environment
- Python 3.11 runtime (for KERI driver, desktop only)

## Recent Changes

- 2026-02-18: Created adaptive architecture with three operating modes (Desktop, Mobile Remote, Mobile Standalone)
- 2026-02-18: Created KeriService abstract interface + AgentEnvironment enum for mode-agnostic UI
- 2026-02-18: Created DesktopKeriService, RemoteServerKeriService, MobileStandaloneKeriService implementations
- 2026-02-18: Created KeriHelperClient for public stateless Remote Helper (zero trust, public data only)
- 2026-02-18: Created Rust bridge infrastructure (Cargo.toml, keri_bridge.rs) with THCLab keriox/keri-core
- 2026-02-18: Created Dart KeriBridge interface for flutter_rust_bridge FFI bindings
- 2026-02-18: Updated main.dart with runtime environment detection and KeriService dependency injection
- 2026-02-18: Updated AgentConfig with PRIMARY_SERVER_URL and KERI_HELPER_URL configuration
- 2026-02-18: Refactored SetupWizard and Dashboard to accept KeriService parameter (mode-agnostic)
- 2026-02-18: Created ADR 003 documenting adaptive architecture, trust boundaries, and Remote Helper constraint
- 2026-02-18: Removed all fallback KERI code — keripy is now a hard requirement (no degraded mode)
- 2026-02-18: Replaced custom Go KERI logic with Python KERI driver (Driver Pattern)
- 2026-02-18: Completed Phase 2 — inception events, KEL persistence, Setup Wizard, mobile architecture
