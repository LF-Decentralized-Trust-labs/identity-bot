# ADR-014: Key Custody, Backend Server Mode, Migration, and Data Partitioning

**Status:** Accepted
**Date:** 2026-03-15
**Extends:** ADR-006 (Standardized Topology — Two Topologies, Four Configurations; revised 2026-05-01)

## Context

ADR-006 (in its 2026-05-01 revision) defines two topologies (Phone + Computer, Computer only) and four launch configurations. The original 6-combination model is preserved internally as `KeriService` implementation choices. Several decisions left open by ADR-006 are now resolved:

1. How and where private keys are stored and used for signing
2. What the "Backend Server" device role is, how it is set up, and what UI label it surfaces
3. What AID the backend server holds and its relationship to the controller's root AID
4. Which data lives on the controller device vs. the backend server
5. The backup strategy for each data tier

This ADR also documents the `SecureKeyStore` implementation and the local Dart signing architecture that was implemented to fix a critical bug (random-seed signing in the Python driver).

---

## Decisions

### 1. Key Custody: Private Keys Never Leave the Controller Device

The signing key and BIP39 mnemonic (Seed phrase) are the property of the controller device in all topological states. The following invariant is non-negotiable and extends ADR-006's trust invariant:

> **Private keys are generated on the controller device, stored on the controller device, and signing operations are performed on the controller device. No other device ever receives, stores, or uses the private key.**

#### Implementation

At inception, the BIP39 mnemonic is saved to `SecureKeyStore` immediately after a successful KERI inception event. `SecureKeyStore` uses `flutter_secure_storage` backed by platform secure storage:

| Platform | Backing Store |
|---|---|
| iOS / macOS | Keychain |
| Android | Android Keystore (EncryptedSharedPreferences) |
| Windows | DPAPI (Credential Manager) |
| Linux | libsecret / kwallet |
| Web | localStorage (insecure; acceptable for localhost-only development web build only) |

At signing time, `DesktopKeriService.signPayload()` loads the mnemonic from `SecureKeyStore`, deterministically derives the Ed25519 key pair via `KeyManager.generateKeysFromMnemonic()`, and signs directly in Dart using `ed25519_edwards`. **No network call is made for signing.** The Go backend and Python driver are never involved in signing operations on desktop.

The Python driver's `/sign` endpoint is therefore bypassed entirely for desktop. It remains in the codebase for potential future use but is not part of any production code path.

#### Key Custody by Topology

| Topology | Controller Device | Backend Server |
|---|---|---|
| Standalone | Holds root AID keys + BIP39. Signs locally. | — (no remote server) |
| Remote WITH Keys | Holds root AID keys + BIP39. Signs locally. | Never receives keys. Compute only. |
| Remote WITHOUT Keys | Holds delegated child AID keys + child BIP39. Signs locally. | Holds root AID keys + root BIP39. Root key custody belongs to this device. |

BIP39 mnemonic recovery applies to whichever device holds the keys for a given AID. Users who run Standalone or Remote WITH Keys on their mobile device are responsible for backing up their mobile's mnemonic. Users who connect to a Grape ID hosted server (Remote WITHOUT Keys) have their root AID managed by Grape ID's institutional key management — no user-facing BIP39 for the root in that case.

---

### 2. Backend Server Mode — A New Onboarding Path

ADR-006 combination 3 (Desktop + Remote WITH Keys) describes a desktop that provides compute and backend services for a controller device that holds the root AID. This ADR formally names and defines the setup path for that desktop role.

#### Naming

| Context | Term |
|---|---|
| User-facing UI label | **"Create Backend Server"** |
| Developer / ADR term | **Backend Server Mode** |
| Existing topology term (ADR-006) | Remote WITH Keys (applied to the desktop acting as the paired server) |

#### UI Placement

"Create Backend Server" appears in the onboarding welcome screen under an **Advanced** expandable section. It is shown on desktop only — the option is hidden on mobile. This prevents confusion for the majority of users who will never set up a backend server and keeps the primary paths (Create New Identity, Connect to Existing Identity) uncluttered.

The Advanced section is also the future home of other infrequent onboarding paths (e.g., Recover from Seed Phrase, Import from Another Agent) without requiring a redesign of the primary screen.

#### Three Onboarding Paths (Updated)

| UI Label | Developer Term | Topology | Device |
|---|---|---|---|
| Create New Identity | Standalone Mode | Standalone | Desktop or Mobile |
| Connect to Existing Identity | Remote Without Keys | Remote WITHOUT Keys | Desktop or Mobile |
| Create Backend Server *(Advanced)* | Backend Server Mode | Remote WITH Keys (server role) | **Desktop only** |

---

### 3. AID Model for Backend Server Mode — Service AID, Not Delegation

When a desktop is set up as a Backend Server, it generates its own **independent service AID**. This is not a KERI-delegated child of the controller's root AID. The relationship between the controller and the backend server is a **service configuration relationship**, not a cryptographic parent-child relationship.

#### Why Not KERI Delegation

KERI delegation (parent → child AID) requires the parent to countersign the child's events. If the backend server's AID were a delegated child of the mobile's root AID, then every backend operation requiring the server's authority would need the mobile to be online and responsive. This defeats the purpose of a backend server — the backend exists precisely so that things work when the mobile is offline.

#### Service AID Properties

| Property | Value |
|---|---|
| Generation | Auto-generated at Backend Server setup. No user interaction. |
| BIP39 mnemonic | Auto-generated and stored in `SecureKeyStore` on the desktop. **Not displayed to the user.** |
| Recoverability | The service AID is replaceable. If the backend server is destroyed, a new service AID is generated during re-provisioning. The controller's root AID is unaffected. |
| Purpose | Authenticating the controller-to-server channel; OOBI endpoint identity; optionally acting as a witness for the root AID (separate role). |
| Authority | None over the root AID. The backend server cannot sign credentials, rotate keys, or issue events on behalf of the root AID. |

The controller's root AID "links" to the backend server via configuration (server URL + server's service AID for channel authentication). This is stored in the controller device's SharedPreferences after the migration handshake.

---

### 4. Migration Process: Standalone → Remote WITH Keys + Paired Backend Server

This migration is initiated from the controller device (the device holding the root AID). It does not require reinstalling the app on the controller.

#### Prerequisites

- Controller device is in Standalone topology with an active identity
- Backend desktop has the Identity Agent installed and has completed Backend Server Mode setup
- Both devices are on the same network or reachable via tunnel

#### Migration Steps

1. **Backend setup (desktop, done first):** User installs Identity Agent on the desktop. On the welcome screen, opens Advanced → "Create Backend Server." The app auto-generates a service AID, starts the Go backend, establishes an OOBI endpoint, and displays a pairing QR code or URL.

2. **Controller initiates migration (mobile/controller device):** From the dashboard, user opens Settings → "Migrate to Backend Server." User scans the backend's pairing QR code or enters the pairing URL.

3. **Mutual authentication:** Controller and backend exchange their respective AIDs and verify each other's service signatures. This establishes a trusted channel for the data transfer (DIDcomm).

4. **Data replication to backend:** The controller pushes the following to the backend server:
   - Full KEL for the root AID
   - All KERI events (inception, rotation, IXN)
   - Contacts, credentials, witness configuration, OOBI endpoints
   - Application data (messages, activity log, etc.)
   - **Private keys and BIP39 mnemonic are explicitly excluded — never transferred.**

5. **Backend acknowledges and begins serving:** The backend stores all received data and begins serving the root AID's OOBI. The backend is now the primary server for all stateless operations.

6. **Controller switches topology:** The controller device updates its configuration:
   - Stores the backend server URL and service AID
   - Switches from Standalone to Remote WITH Keys mode
   - Going forward: stateful KERI ops (signing, rotation) run on the controller locally; stateless ops and backend services use the remote server.

7. **Verification:** The controller confirms the backend is correctly serving its OOBI and that the KERL is accessible via the backend's public endpoint.

#### Reversibility

The controller always retains the root AID keys and complete KEL locally. To revert to Standalone: disconnect from the backend server in Settings. The controller's local engine resumes all operations immediately.

---

### 5. Data Partitioning: Two Tiers

Not all data has the same mobility, size, or backup requirements. Two tiers are defined:

#### Tier 1 — Identity Core Data (Replicated on Both Devices)

This data is replicated on both the controller device and the backend server. The two copies constitute a mutual backup by design — no additional backup procedure is required for Tier 1 data.

| Database / Store | Contents |
|---|---|
| `identity.db` | AID, KEL, key events (icp/rot/ixn), current public key, next key digest, event count |
| KERL / witness receipts | Witness receipt signatures for each key event |
| Credential registry | Issued and held credential SAIDs (hashes + metadata, not full payloads for large creds) |
| Witness configuration | Enrolled witnesses, their AIDs, topology flags, threshold |
| Contact identity records | AID, OOBI endpoint, trust level per contact |

#### Tier 2 — Backend-Only Data (Stored on Backend Server Only)

This data lives exclusively on the backend server. It is not replicated to the controller device. The user is responsible for establishing a backup strategy for Tier 2 data.

| Database / Store | Contents | Why Backend Only |
|---|---|---|
| Message and email store | Full message bodies, attachments, threads | Volume: potentially hundreds of thousands of records |
| Activity log | Full audit trail of all agent operations | High write volume, low mobile value |
| AI memory store (`ai-memory.db`) | Conversation history, FTS5 index | Size and compute dependency |
| Marketplace data | App manifests, container state, sandbox logs | Desktop-only feature |
| Watcher records | Observed third-party AID key states | High volume, reference data |
| Large credential payloads | Full ACDC content for large credentials | Size |

#### Backup Strategy for Tier 2

Tier 2 backup is the user's responsibility, with multiple supported options (to be built out in future phases):

- **Second backend server** — A second Identity Agent instance in Backend Server Mode, receiving Tier 2 replication from the primary backend
- **Remote storage sync** — Encrypted archive exported to S3, Backblaze B2, or any self-hosted object store; credentials for the remote storage location are themselves stored in `identity.db` (Tier 1), ensuring recovery is possible from the controller device
- **Second owned device** — A second desktop or laptop running Identity Agent in Backend Server Mode, synchronized with the primary
- **Scheduled export** — Nightly encrypted export to any removable media or network location

The separation of Tier 1 and Tier 2 ensures that **identity recovery is always possible from the controller device alone**, regardless of whether Tier 2 data is lost. A lost backend server is a data continuity event, not an identity loss event.

---

## Consequences

- The `SecureKeyStore` service is the single point of mnemonic custody. Any code that needs to sign must use it — no other path to private key material is acceptable.
- The Python driver's `/sign` endpoint is no longer on the critical path for desktop. It should not be called for production signing operations.
- Backend Server Mode is a desktop-only onboarding path. The mobile UI must not display this option.
- The Advanced expandable section on the welcome screen is the correct home for infrequent or technical onboarding paths.
- The absence of KERI delegation between the controller and backend server means the backend's service AID can be rotated or replaced without any impact on the root AID or its credentials.
- Tier 1 data replication during migration is a required step — a backend that has not received the full KEL cannot correctly serve OOBI or verify credentials.
- Tier 2 backup is explicitly the user's responsibility. The application should prompt users to configure a Tier 2 backup strategy, but should not block functionality if they decline.
