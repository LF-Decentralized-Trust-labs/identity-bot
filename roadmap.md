Artifact 2: Implementation Milestones
Instruction for Replit Agent: Import this roadmap. Do not deviate from this order. Complete all tasks in a Milestone before proceeding to the next.

Phase 1: The "Skeleton" (Infrastructure & Binding)
Goal: A Flutter app that can launch and talk to the Go backend.

Task 1.1: Initialize the Go Module (identity-agent-core) with a basic HTTP server (Echo or Chi router) listening on localhost:8080.

Task 1.2: Initialize the Flutter App (identity_agent_ui) with a basic Dashboard layout.

Task 1.3: Implement the "Bridge." Use flutter_rust_bridge or compile Go to a C-Shared library to allow Flutter to start/stop the Go process on Android/iOS.

Task 1.4: Create a "Health Check" ping. Flutter sends GET /health -> Go responds {"status": "active", "agent": "keri-go"}.

Phase 2: Inception (Identity & Key Storage)
Goal: Use Case 1: "Create your own Identity."

Task 2.1 (Security): Implement Flutter logic to generate keys in the Secure Enclave/Keychain (The "Device Authority").

Task 2.2 (Recovery): Implement the BIP-39 Mnemonic generator and the UI flow for "Seed Phrase Backup."

Task 2.3 (KERI Core): Implement the keri-go logic to accept a public key from Flutter and generate a KERI Inception Event.

Task 2.4 (Storage): Wire up BadgerDB in the Go backend to persist the KEL (Key Event Log).

Demonstrable: User opens app, scans face (Biometrics), and an AID (e.g., EAbc...123) appears on screen.

Phase 3: Connectivity & Witnessing
Goal: The Agent can talk to the outside world.

Task 3.1 (Tunneling): Integrate a tunneling client (like ngrok-go or similar) into the Go backend to acquire a public HTTPS URL.

Task 3.2 (OOBI): Generate the OOBI URL (https://.../oobi/{AID}).

Task 3.3 (Scanning): Implement the QR Code scanner in Flutter (mobile_scanner).

Task 3.4 (Resolution): When scanning another Agent's OOBI, the Go backend resolves their KEL and stores it in the "Contact Rolodex."

Demonstrable: Two phones scan each other; they appear in each other's "Contacts" list.

Phase 4: Credentials (The "School Pickup")
Goal: Use Case 2: The School Pickup / Delegation.

Task 4.1 (Schema): Define the DelegationSchema and EmployeeCredentialSchema in JSON-LD format within the Go backend.

Task 4.2 (IPEX): Implement the IPEX (Issuance Protocol) in the Go backend to allow sending/receiving credentials.

Task 4.3 (Org Mode): Create the "Organization Vault" toggle in Flutter (switching views between Personal and Business).

Task 4.4 (The Logic): Implement the verification logic: If Credential A (Guardian) + Credential B (Employee) are present -> Allow Action.

Demonstrable: A "Mother" phone issues a credential to a "Grandpa" phone. The "School" tablet scans Grandpa's phone and gets a green "Authorized" checkmark.

Phase 5: Hardening (NFC & Recovery)
Goal: Use Case 3 & 4: NFC Backup & Account Recovery.

Task 5.1 (NFC Write): Implement nfc_manager in Flutter. Create a flow to write the raw Salt/Seed to an NDEF tag.

Task 5.2 (NFC Read/Restore): Create the "Wipe & Restore" flow. App reads the card and regenerates the exact same AID.

Task 5.3 (Social Recovery): Implement the KERI Rotation Event logic, allowing a pre-defined set of "Trusted Friends" (Witnesses) to sign a recovery rotation.

Demonstrable: Delete the app. Reinstall. Tap the NFC card. The Identity is fully restored.

Phase 6: The "Leash" (AI Governance)
Goal: Use Case 5: Open Claw with a Seatbelt.

Task 6.1 (Open Claw): Integrate the Open Claw (or similar agent framework) as a child process managed by the Go Core.

Task 6.2 (The Jailer): Implement the "Egress Filter." The AI tries to send a request; the Go Core intercepts it.

Task 6.3 (The Policy): Create a JSON policy file (e.g., max_spend: 0, allowed_domains: ["google.com"]).

Task 6.4 (The Shadow Auditor): A background routine that logs every AI attempt and blocks any that violate the Policy.

Demonstrable: Tell the AI: "Go to Amazon and buy a Ferrari." The AI attempts it, but the Agent throws a red error: POLICY_VIOLATION: Limit Exceeded. Then tell it: "Summarize this article." It succeeds.
