# Identity Agent

## Overview

The Identity Agent is a self-sovereign digital identity platform that unifies identity, data, communications, and assets into a single environment. It implements the KERI (Key Event Receipt Infrastructure) protocol for decentralized identity management. The system uses a "Decoupled-but-Bundled" architecture with a Go backend (the "Core") handling cryptography, key event logs, and data persistence, and a Flutter frontend (the "Controller") providing the cross-platform UI and secure key management via device hardware.

The project is currently in **Phase 1 ("The Skeleton")** — completed. Go HTTP server, Flutter dashboard, and health check handshake are all working end-to-end. Ready for Phase 2.

## User Preferences

Preferred communication style: Simple, everyday language.
Design theme: Dark cyberpunk aesthetic with monospace fonts, dark blue/green color scheme.

## System Architecture

### Pure Go + Flutter Architecture (No Node.js Runtime)

The system has two components that communicate via HTTP:

1. **Go Backend (`identity-agent-core/`)** — A compiled Go binary that acts as the persistent "Agent." It handles:
   - KERI protocol operations (KEL — Key Event Log, TEL, IPEX credentials)
   - Cryptographic key management (delegated operational keys)
   - Database persistence (default: embedded key-value store like BadgerDB/BoltDB, swappable to PostgreSQL)
   - Access Control List (ACL) management
   - Network-facing gateway (single public entry point, cryptographically authenticated)
   - Listens on port 5000, serves both the API (`/api/*`) and the Flutter web build as static files
   - API endpoints: `/api/health` (health check), `/api/info` (system info)

2. **Flutter Frontend (`identity_agent_ui/`)** — A Flutter/Dart application compiled for web (and eventually mobile/desktop). It handles:
   - User interface and dashboard (dark cyberpunk theme)
   - Secure key generation and storage via device Secure Enclave/Keychain
   - BIP-39 mnemonic seed phrase generation and backup flow
   - Biometric authentication (FaceID/TouchID)
   - QR code scanning for OOBI (Out-of-Band Introduction) resolution
   - Does NOT store the full KEL — queries the Go Core for state
   - Backend URL configurable via `AgentConfig` class (`--dart-define=CORE_URL`)

### Build System (Shell Scripts, No Node.js)

- `scripts/start-backend.sh` — Builds Go binary, builds Flutter web, launches Go server on port 5000
- `scripts/build-flutter.sh` — Builds Flutter web assets only (for standalone rebuilds)
- A minimal `package.json` exists only as a workflow script adapter (maps npm scripts to shell scripts)
- Zero Node.js runtime dependencies — no node_modules needed at runtime

### Workflows

- **Start Backend** (`npm run server:dev` → `sh ./scripts/start-backend.sh`) — Builds everything and starts the Go server
- **Start Frontend** (`npm run expo:dev`) — No-op; echoes that Flutter is served by Go backend

### Cryptographic Key Hierarchy (3-Level)

- **Level 1 — Root Authority:** 128-bit salt / 12-word BIP-39 mnemonic. Never stored on active devices. Used only for recovery and authorizing new controllers.
- **Level 2 — Device Authority:** Keys generated in device Secure Enclave. Signs daily operations. Managed via ACL on the backend.
- **Level 3 — Delegated Agent:** Operational keys stored in the backend's encrypted database. Signs data as authorized by controllers.

### Persistence Layer

- **Default:** Embedded local key-value store (BadgerDB or BoltDB) — zero configuration, no external dependencies
- **Configurable:** Modular storage layer supports swapping to PostgreSQL or other databases
- **Migration:** Built-in tool for atomic "hot-swap" between storage providers

### Implementation Roadmap (follow strictly in order)

- **Phase 1 (COMPLETE):** Skeleton — Go HTTP server, Flutter dashboard, bridge between them, health check endpoint
- **Phase 2 (next):** Inception — Secure Enclave key generation, BIP-39 mnemonic, KERI inception event, KEL persistence
- **Phase 3:** Connectivity — Public URL tunneling, OOBI generation, QR scanning, contact resolution
- **Phase 4:** Credentials — Credential schemas, IPEX protocol, organization mode, verification logic

### Key Design Decisions

- **Why Go for backend:** High-performance cryptography, strict type safety, compiles to single binary, existing `keri-go` library from WebOfTrust
- **Why Flutter for frontend:** Cross-platform (mobile + desktop + web), native hardware access plugins (NFC, biometrics), strong typing with Dart
- **Why local-first storage:** Sovereignty by default — no third-party accounts required, zero cost, works offline
- **Why split-key architecture:** Root authority is never exposed to daily operations, compromising one device doesn't compromise the identity
- **Why no Node.js:** Eliminated unnecessary JavaScript layer; Go serves Flutter web directly, shell scripts handle builds

## Key Files

- `identity-agent-core/main.go` — Go backend entry point, HTTP server, API routes, static file serving
- `identity_agent_ui/lib/main.dart` — Flutter app entry point
- `identity_agent_ui/lib/screens/dashboard_screen.dart` — Main dashboard UI
- `identity_agent_ui/lib/services/core_service.dart` — HTTP client for Go API
- `identity_agent_ui/lib/config/agent_config.dart` — Backend URL configuration
- `scripts/start-backend.sh` — Build + launch script
- `scripts/build-flutter.sh` — Flutter web build script
- `docs/adr/001-core-architecture-stack.md` — Architecture decision record
- `roadmap.md` — Phase roadmap

## External Dependencies

### Backend (Go)
- Standard library only (net/http, encoding/json, etc.)
- Future: `keri-go` (WebOfTrust KERI protocol), BadgerDB/BoltDB (embedded storage)

### Frontend (Flutter/Dart)
- Flutter SDK (v3.22.0)
- `cupertino_icons` — iOS-style icons
- `http` — HTTP client for API calls
- Future: `nfc_manager`, `biometric_storage`, `mobile_scanner` — hardware access plugins

### Infrastructure
- Replit hosting environment
- Future: tunneling client (ngrok-go or similar) for public HTTPS URLs

## Recent Changes

- 2026-02-18: Completed Phase 1 — Go server + Flutter dashboard + health check handshake working
- 2026-02-18: Removed ALL Expo/React Native/Node.js runtime dependencies
- 2026-02-18: Created shell-script-based build system (no Node.js involvement)
- 2026-02-18: Made Flutter backend URL configurable via AgentConfig class
- 2026-02-18: Added dark cyberpunk theme to Flutter dashboard
