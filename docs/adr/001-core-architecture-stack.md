# ADR 001: Core Architecture & Language Stack

## Status
Accepted (KERI implementation details superseded by [ADR 002](002-keri-driver-pattern.md) and [ADR 003](003-adaptive-architecture.md))

## Context
We are building an "Identity Agent" that functions as a self-sovereign digital territory. The system requires:
1.  **High-Performance Cryptography:** For KERI event logs (KEL) and signature verification.
2.  **Cross-Platform UI:** Mobile (iOS/Android) and Desktop control.
3.  **Strict Separation of Concerns:** A "Decoupled-but-Bundled" architecture where the UI (Controller) is distinct from the State Machine (Agent).
4.  **Hardware Access:** NFC, Bluetooth, and Secure Enclave usage (future).

## Decision
We will utilize a **Hybrid Local-Client/Server Architecture** composed of the following stack:

### 1. The Backend (The "Core")
* **Language:** Go (Golang)
* **KERI Engine:** Python `keripy` v1.1.17 on desktop (see [ADR 002](002-keri-driver-pattern.md)); Rust `keriox/keri-core` on mobile via FFI (see [ADR 004](004-ffi-bridge-and-ci-pipeline.md)).
* **Role:** Runs as a persistent background service. On desktop, it spawns the Python KERI driver as a child process. On mobile, it runs embedded via gomobile (platform channels) with the KERI driver disabled — the Rust bridge handles crypto instead. Handles data persistence (file-based JSON store), OOBI serving, contact management, and tunneling.
* **API:** Exposes a local HTTP API (port 5050) for the frontend to command.

### 2. The Frontend (The "Controller")
* **Framework:** Flutter (Dart)
* **Key Management:** On desktop, keys are managed by the Python KERI driver via the Go backend. On mobile, keys are managed locally by the Rust KERI bridge via FFI (`flutter_rust_bridge`).
* **Role:** The visual interface. It does *not* store the full KEL database; it queries the Go Core for persisted data.
* **Hardware Access:** Uses Flutter native plugins for QR scanning (`mobile_scanner`), with future support for NFC and biometric storage.

### 3. AI Governance (The "Seatbelt") — Future
* **Integration:** The "Open Claw" agent and "Shadow Auditor" will run as isolated processes or sandboxed logic within the Go Core. This is planned for a future development phase (see roadmap Phase 6).
* **Constraint:** All AI Egress must pass through a strict "Deterministic Whitelist" filter enforced by the Go backend before reaching the network.

## Consequences
* **Pros:** Strict type safety (Go/Dart), high performance, clear separation of UI and Logic (allows the backend to be moved to a cloud server later if the user chooses "Remote" mode). Four operating modes support desktop, mobile standalone, and two remote controller configurations.
* **Cons:** Requires managing multiple build pipelines (Go binary, Go gomobile library, Rust bridge, Flutter bundle) and platform-specific bridges (HTTP on desktop, platform channels + FFI on mobile).
