# Identity Agent

## Overview

The Identity Agent is a self-sovereign digital identity platform that unifies identity, data, communications, and assets into a single environment. It implements the KERI (Key Event Receipt Infrastructure) protocol for decentralized identity management. The system uses a three-layer architecture: Go backend (the "Core") for orchestration and persistence, a Python KERI driver (the "Driver") for protocol-correct KERI operations, and a Flutter frontend (the "Controller") for the cross-platform UI.

The project is currently in **Phase 2 ("Inception")** — identity creation, BIP-39 mnemonic, KERI inception events, and KEL persistence are all working end-to-end.

## User Preferences

Preferred communication style: Simple, everyday language.
Design theme: Dark cyberpunk aesthetic with monospace fonts, dark blue/green color scheme.

## System Architecture

### Three-Layer Architecture: Go + Python Driver + Flutter

The system has three components that communicate via HTTP:

1. **Go Backend (`identity-agent-core/`)** — The orchestration layer. Compiled Go binary that:
   - Serves the public API on port 5000 (`/api/*`)
   - Manages data persistence (file-based store, swappable to BadgerDB/PostgreSQL)
   - Spawns and manages the Python KERI driver process
   - Bridges Flutter requests to the KERI driver
   - Serves Flutter web build as static files
   - API endpoints: `/api/health`, `/api/info`, `/api/inception`, `/api/identity`

2. **Python KERI Driver (`drivers/keri-core/`)** — The KERI protocol engine. Internal HTTP microservice that:
   - Runs on `127.0.0.1:9999` (never exposed publicly)
   - Handles all KERI protocol operations (inception events, SAID computation, key digests)
   - Uses keripy (WebOfTrust reference library) as a hard requirement — no fallback
   - Endpoints: `/status`, `/inception`
   - Spawned by Go in development; runs as separate service in production

3. **Flutter Frontend (`identity_agent_ui/`)** — The controller UI. Flutter/Dart app that:
   - User interface and dashboard (dark cyberpunk theme)
   - BIP-39 mnemonic seed phrase generation and backup flow
   - Ed25519 key derivation from mnemonic
   - Setup Wizard for new identity creation
   - Only talks to Go on port 5000 — never directly to the Python driver
   - Backend URL configurable via `AgentConfig` class

### Driver Pattern (Mobile-Ready Architecture)

The Python KERI driver uses an "Internal Network Driver" pattern designed for cross-platform deployment:

- **Development/Replit (Linux):** Go spawns Python as a child process via `exec.Command()`. Communication via `localhost:9999`.
- **Production (Server):** Python driver runs as a separate service. Go connects via `KERI_DRIVER_URL` environment variable.
- **Future Mobile (iOS/Android):** Flutter talks to Go backend over the internet. Go + Python driver remain server-side. Mobile devices never need to run Python.

Key environment variables:
- `KERI_DRIVER_URL` — If set, Go connects to this URL instead of spawning Python (production/external mode)
- `KERI_DRIVER_PORT` — Port for the managed Python driver (default: 9999)
- `KERI_DRIVER_SCRIPT` — Path to server.py (default: `./drivers/keri-core/server.py`)
- `KERI_DRIVER_PYTHON` — Python binary path (default: `python3`)

### Build System (Shell Scripts, No Node.js)

- `scripts/start-backend.sh` — Installs Python deps, builds Go binary, launches Go server (which spawns the KERI driver)
- `scripts/build-flutter.sh` — Builds Flutter web assets only; Go picks them up automatically
- No package.json, no npm, no node_modules — pure shell scripts

### Workflows (Fully Decoupled)

- **Start Backend** (`sh ./scripts/start-backend.sh`) — Installs Python deps, builds Go, starts Go server + KERI driver. API available immediately.
- **Start Frontend** (`sh ./scripts/build-flutter.sh`) — Builds Flutter web assets independently. Go serves them once they exist.

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
- **Phase 2 (COMPLETE):** Inception — BIP-39 mnemonic, KERI inception event via Python driver, KEL persistence, Setup Wizard
- **Phase 3 (next):** Connectivity — Public URL tunneling, OOBI generation, QR scanning, contact resolution
- **Phase 4:** Credentials — Credential schemas, IPEX protocol, organization mode, verification logic

### Key Design Decisions

- **Why Go for backend:** Orchestration layer, high-performance, compiles to single binary, manages driver lifecycle
- **Why Python for KERI:** Reference keripy library is the most battle-tested KERI implementation; Python driver pattern allows using it without embedding Python in mobile
- **Why Driver Pattern:** HTTP-based internal communication means the same Go code works whether Python is spawned locally or running remotely; mobile devices never need Python
- **Why Flutter for frontend:** Cross-platform (mobile + desktop + web), native hardware access
- **Why local-first storage:** Sovereignty by default — no third-party accounts required
- **Why no Node.js:** Eliminated unnecessary JavaScript layer; Go serves Flutter web directly

## Key Files

- `identity-agent-core/main.go` — Go backend entry point, HTTP server, API routes, driver lifecycle
- `identity-agent-core/drivers/keri_driver.go` — Go HTTP client for the Python KERI driver
- `identity-agent-core/store/store.go` — File-based persistence (Store interface + FileStore implementation)
- `drivers/keri-core/server.py` — Python Flask HTTP server for KERI operations
- `drivers/keri-core/requirements.txt` — Python dependencies (flask, keri)
- `identity_agent_ui/lib/main.dart` — Flutter app entry point + routing logic
- `identity_agent_ui/lib/screens/setup_wizard_screen.dart` — Setup Wizard (mnemonic + inception)
- `identity_agent_ui/lib/screens/dashboard_screen.dart` — Main dashboard UI
- `identity_agent_ui/lib/crypto/bip39.dart` — BIP-39 mnemonic generator
- `identity_agent_ui/lib/crypto/keys.dart` — Ed25519 key derivation from mnemonic
- `identity_agent_ui/lib/services/core_service.dart` — HTTP client for Go API
- `identity_agent_ui/lib/config/agent_config.dart` — Backend URL configuration
- `scripts/start-backend.sh` — Build + launch script (Go + Python driver)
- `scripts/build-flutter.sh` — Flutter web build script
- `docs/adr/001-core-architecture-stack.md` — ADR: original architecture decisions
- `docs/adr/002-keri-driver-pattern.md` — ADR: Python driver pattern, keripy requirement, libsodium detection

## External Dependencies

### Backend (Go)
- `github.com/go-chi/chi/v5` — HTTP router
- `github.com/go-chi/cors` — CORS middleware
- Standard library (net/http, encoding/json, crypto/ed25519, os/exec)

### KERI Driver (Python)
- `flask` — Lightweight HTTP server
- `keri` (required) — WebOfTrust reference KERI library v1.1.17 (hard requirement, no fallback)

### Frontend (Flutter/Dart)
- Flutter SDK (v3.22.0)
- `http` — HTTP client for API calls
- `crypto` — SHA-256 for key derivation
- `ed25519_edwards` — Ed25519 key generation

### Infrastructure
- Replit hosting environment
- Python 3.11 runtime (for KERI driver)

## Recent Changes

- 2026-02-18: Removed all fallback KERI code — keripy is now a hard requirement (no degraded mode)
- 2026-02-18: Refactored server.py — clean sections for libsodium detection, keripy imports, HTTP routes
- 2026-02-18: Created ADR 002 documenting the Python driver pattern and keripy decision
- 2026-02-18: Replaced custom Go KERI logic with Python KERI driver (Driver Pattern)
- 2026-02-18: Created `drivers/keri-core/server.py` — Flask-based internal KERI microservice
- 2026-02-18: Created `identity-agent-core/drivers/keri_driver.go` — Go HTTP bridge to Python driver
- 2026-02-18: Go now spawns Python driver on boot, connects via localhost:9999
- 2026-02-18: Added KERI_DRIVER_URL env var for production/external driver mode
- 2026-02-18: Updated start-backend.sh to install Python deps and manage driver lifecycle
- 2026-02-18: Completed Phase 2 — inception events, KEL persistence, Setup Wizard all working
- 2026-02-18: Decoupled Go and Flutter builds — shell script workflows, no Node.js
