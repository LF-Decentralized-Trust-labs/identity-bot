# ADR 001: Core Architecture & Language Stack

## Status
Accepted (KERI-related sections superseded by [ADR 002](002-keri-driver-pattern.md))

## Context
We are building a "Identity Agent" (v1.5 Spec) that functions as a self-sovereign digital territory. The system requires:
1.  **High-Performance Cryptography:** For KERI event logs (KEL) and signature verification.
2.  **Cross-Platform UI:** Mobile (iOS/Android) and Desktop control.
3.  **Strict Separation of Concerns:** A "Decoupled-but-Bundled" architecture where the UI (Controller) is distinct from the State Machine (Agent).
4.  **Hardware Access:** NFC, Bluetooth, and Secure Enclave usage.

## Decision
We will utilize a **Hybrid Local-Client/Server Architecture** composed of the following stack:

### 1. The Backend (The "Core")
* **Language:** Go (Golang)
* **Library:** `keri-go` (WebOfTrust implementation)
* **Role:** Runs as a persistent background service (or sidecar process on mobile). It handles the KEL, IPEX (Credentials), Witness communication, and Database storage (BadgerDB/BoltDB).
* **API:** Exposes a local HTTP/WebSocket API (localhost:8080) for the frontend to command.

### 2. The Frontend (The "Controller")
* **Framework:** Flutter (Dart)
* **Key Management:** Uses `signify-ts` (via WebView bridge) or `keri-dart` (via Rust bridge) for key generation and signing.
* **Role:** The visual interface. It holds the "Controller Keys" in the device's Hardware Security Module (Secure Enclave). It does *not* store the full KEL database; it queries the Go Core.
* **Hardware Access:** Uses Flutter native plugins (`nfc_manager`, `biometric_storage`) to interface with physical hardware.

### 3. AI Governance (The "Seatbelt")
* **Integration:** The "Open Claw" agent and "Shadow Auditor" will run as isolated processes or sandboxed logic within the Go Core.
* **Constraint:** All AI Egress must pass through a strict "Deterministic Whitelist" filter enforced by the Go backend before reaching the network.

## Consequences
* **Pros:** strict type safety (Go/Dart), high performance, clear separation of UI and Logic (allows the backend to be moved to a cloud server later if the user chooses "Remote" mode).
* **Cons:** Requires managing two build pipelines (Go binary + Flutter bundle) and an FFI or HTTP bridge between them on mobile devices.
