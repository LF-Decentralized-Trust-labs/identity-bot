# Identity Agent

## Overview

The Identity Agent is a self-sovereign digital identity platform that unifies identity, data, communications, and assets into a single environment. It implements the KERI (Key Event Receipt Infrastructure) protocol for decentralized identity management. The system uses a "Decoupled-but-Bundled" architecture with a Go backend (the "Core") handling cryptography, key event logs, and data persistence, and a Flutter frontend (the "Controller") providing the cross-platform UI and secure key management via device hardware.

The project is currently in **Phase 1 ("The Skeleton")** of a 4-phase roadmap, focused on establishing the infrastructure binding between the Go backend and the Flutter frontend, with a health check endpoint as the first demonstrable feature.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Hybrid Client/Server Architecture

The system is split into two main components that communicate via HTTP/WebSocket:

1. **Go Backend (`identity-agent-core/`)** — A compiled Go binary that acts as the persistent "Agent." It handles:
   - KERI protocol operations (KEL — Key Event Log, TEL, IPEX credentials)
   - Cryptographic key management (delegated operational keys)
   - Database persistence (default: embedded key-value store like BadgerDB/BoltDB, swappable to PostgreSQL)
   - Access Control List (ACL) management
   - Network-facing gateway (single public entry point, cryptographically authenticated)
   - Listens on port 5000, serves both the API (`/api/*`) and the Flutter web build as static files

2. **Flutter Frontend (`identity_agent_ui/`)** — A Flutter/Dart application compiled for web (and eventually mobile/desktop). It handles:
   - User interface and dashboard
   - Secure key generation and storage via device Secure Enclave/Keychain
   - BIP-39 mnemonic seed phrase generation and backup flow
   - Biometric authentication (FaceID/TouchID)
   - QR code scanning for OOBI (Out-of-Band Introduction) resolution
   - Does NOT store the full KEL — queries the Go Core for state

### Orchestration Layer (`server/index.ts`)

A TypeScript orchestration script that:
- Builds the Go binary from `identity-agent-core/`
- Builds the Flutter web assets from `identity_agent_ui/`
- Launches the Go binary as a child process on port 5000
- Passes the Flutter web build directory as an environment variable so Go can serve the static files

### Cryptographic Key Hierarchy (3-Level)

- **Level 1 — Root Authority:** 128-bit salt / 12-word BIP-39 mnemonic. Never stored on active devices. Used only for recovery and authorizing new controllers.
- **Level 2 — Device Authority:** Keys generated in device Secure Enclave. Signs daily operations. Managed via ACL on the backend.
- **Level 3 — Delegated Agent:** Operational keys stored in the backend's encrypted database. Signs data as authorized by controllers.

### Persistence Layer

- **Default:** Embedded local key-value store (BadgerDB or BoltDB) — zero configuration, no external dependencies
- **Configurable:** Modular storage layer supports swapping to PostgreSQL or other databases
- **Migration:** Built-in tool for atomic "hot-swap" between storage providers

### Implementation Roadmap (follow strictly in order)

- **Phase 1 (current):** Skeleton — Go HTTP server, Flutter dashboard, bridge between them, health check endpoint
- **Phase 2:** Inception — Secure Enclave key generation, BIP-39 mnemonic, KERI inception event, KEL persistence
- **Phase 3:** Connectivity — Public URL tunneling, OOBI generation, QR scanning, contact resolution
- **Phase 4:** Credentials — Credential schemas, IPEX protocol, organization mode, verification logic

### Key Design Decisions

- **Why Go for backend:** High-performance cryptography, strict type safety, compiles to single binary, existing `keri-go` library from WebOfTrust
- **Why Flutter for frontend:** Cross-platform (mobile + desktop + web), native hardware access plugins (NFC, biometrics), strong typing with Dart
- **Why local-first storage:** Sovereignty by default — no third-party accounts required, zero cost, works offline
- **Why split-key architecture:** Root authority is never exposed to daily operations, compromising one device doesn't compromise the identity

## External Dependencies

### Backend (Go)
- `keri-go` — WebOfTrust KERI protocol implementation
- BadgerDB/BoltDB — Embedded key-value store (default persistence)
- PostgreSQL — Optional configurable database backend (via `pg` package in Node orchestrator)

### Frontend (Flutter/Dart)
- Flutter SDK (v3.22.0)
- `cupertino_icons` — iOS-style icons
- Future: `nfc_manager`, `biometric_storage`, `mobile_scanner` — hardware access plugins

### Orchestration (Node.js/TypeScript)
- `express` — HTTP server (for dev proxy scenarios)
- `tsx` — TypeScript execution
- `esbuild` — Server bundling
- `drizzle-orm` / `drizzle-zod` — ORM layer (available for database schema management if PostgreSQL is configured)
- `@tanstack/react-query` — Data fetching (listed in package.json but may be for future use)
- `expo` / `expo-router` — Listed in package.json; the Replit project scaffolding includes Expo but the actual frontend is Flutter

### Infrastructure
- Replit hosting environment with dev domain proxying
- Future: tunneling client (ngrok-go or similar) for public HTTPS URLs