# ADR 009: Two-Layer OOBI Exchange Architecture

**Date:** 2026-03-07
**Status:** Accepted
**Relates to:** ADR-003 (Adaptive Architecture — OOBI/Contacts), ADR-007 (External HTTP Routing)

## The Problem This Solves

The original OOBI exchange flow mixed two fundamentally different concerns into a single operation:

1. **Cryptographic identity verification** — resolving the remote agent's AID, fetching and verifying its Key Event Log (KEL). This is a KERI protocol operation that establishes whether the remote agent's identity is cryptographically valid.

2. **Application-level intent** — what the user actually wants to do with this resolved identity. Adding a contact, requesting a payment, verifying a credential, or any other interaction.

Mixing these concerns created several problems:

- **Tight coupling:** The OOBI resolution endpoint returned both protocol data (AID, KEL verification) and application data (jCard profile, photo) in a single response. Adding a new intent (e.g., "Request Payment") would require modifying the protocol-level resolution logic.
- **Privacy leak:** Profile data (name, organization, title, photo) was always transmitted during OOBI resolution, even when the receiver hadn't consented to the interaction yet. A malicious scanner could harvest profile data by resolving OOBIs without ever completing the contact flow.
- **No extensibility path:** The OOBI URL had no mechanism to signal what the scanner intended to do. Every OOBI scan assumed "add contact," with no way to route to other interaction flows.

## The Decision

### Two Conceptual Layers

The OOBI exchange is now designed as two sequential layers:

```
Layer 1: Cryptographic Trust (Protocol)
────────────────────────────────────────
  OOBI URL → Resolve AID → Fetch KEL → Verify
  
  Output: AID, public key, KEL verification status
  No profile data. No application logic.
  Independent of what the user wants to do.

         ↓ (Layer 1 succeeds)

Layer 2: Application Intent (User)
────────────────────────────────────────
  Intent parameter determines the flow:
  - add_contact → fetch profile, show consent popup
  - request_payment → show payment request form (future)
  - verify_credential → show credential verification (future)
  
  Profile data (jCard, photo) fetched here, not in Layer 1.
```

### Layer 1: Cryptographic Trust

Layer 1 is a mandatory KERI handshake that runs identically regardless of intent:

1. Scanner reads an OOBI URL (via QR code, link, or manual entry).
2. The Go backend resolves the OOBI URL, fetching the remote agent's AID and KEL.
3. The KEL is checked for presence (`kel_verified: kelCount > 0`). Full cryptographic signature verification of the KEL chain is planned for a future iteration.
4. Result: the remote agent's AID, public key, and KEL verification status.

Layer 1 is the protocol-level foundation. It answers the question: "Does this KERI identity have a valid Key Event Log?" It does not determine user intent.

**Current implementation note:** The `/api/contacts/resolve` endpoint currently returns both Layer 1 data (AID, KEL status) and Layer 2 data (jCard, photo) in a single response. This is a pragmatic optimization — a single HTTP round-trip fetches everything. The two-layer model is a **conceptual separation** that governs how the UI treats each data category, not necessarily a physical separation of network requests. Layer 1 data (AID, KEL status) is displayed for identity verification. Layer 2 data (jCard, photo) is displayed for the consent decision. Both come from the same resolve call, but the UI processes them at distinct stages.

### Layer 2: Application Intent

After Layer 1 succeeds, the user's intended interaction is executed. The `intent` parameter in the OOBI URL determines which flow runs:

| Intent | Current Status | What Happens |
|---|---|---|
| `add_contact` | Implemented | Fetch jCard + photo from OOBI endpoint, show consent popup with identity details, accept or reject |
| `request_payment` | Planned | Show payment request form with amount and currency |
| `verify_credential` | Planned | Show credential verification UI with claim details |
| (no intent) | Default | Falls back to `add_contact` |

Layer 2 is where profile data (jCard, photo) is fetched and displayed. This separation means:

- Profile data is only transmitted when the user has already passed Layer 1 verification.
- Different intents can fetch different data (a payment request doesn't need the full jCard).
- New intents can be added without modifying the KERI resolution logic.

### OOBI URL Format (Current and Planned)

**Current implementation:** OOBI URLs do not include an `intent` parameter. All OOBI scans are treated as `add_contact`. The scanner checks for `/oobi/` in the URL and always runs the add-contact flow.

**Planned extension:** The OOBI URL will include an optional `intent` query parameter:

```
https://grapeid.org/alice/oobi/{AID}?action=add_contact
https://grapeid.org/alice/oobi/{AID}?action=request_payment
https://grapeid.org/alice/oobi/{AID}                        (defaults to add_contact)
```

The QR code displayed in the Share Menu will encode this full URL. The scanner will extract the intent and route to the appropriate Layer 2 flow. Unrecognized intents will show a "Coming Soon" dialog.

### Contact Photo & jCard in Layer 2

When the intent is `add_contact`, Layer 2 fetches profile data from the remote agent's OOBI serve endpoint:

```
GET /oobi/{aid}
Response:
{
  "aid": "ED4zKj...",
  "kel": [...],
  "kel_verified": true,
  "photo": "<base64-encoded profile photo>",
  "jcard": {
    "full_name": "Alice",
    "org": "Acme Corp",
    "title": "Engineer",
    "email": "",
    "tel": ""
  }
}
```

The `photo` and `jcard` fields are only present in the full OOBI serve response, not in the Layer 1 resolution result. The Go backend's resolve endpoint (`/api/contacts/resolve`) forwards these fields from the OOBI response for the UI to display.

### Reverse Introduction (Inbound Contact Requests)

When Agent B scans Agent A's OOBI QR code, Agent A receives an inbound introduction via the exchange endpoint. This reverse flow also follows the two-layer model:

1. **Layer 1:** Agent B's OOBI resolution of Agent A establishes cryptographic trust.
2. **Layer 2:** Agent B sends its own profile data (jCard, photo) to Agent A via the exchange payload. Agent A's UI shows a consent popup with Agent B's details.

The exchange payload includes `sender_photo` and `sender_jcard` fields. WebSocket events (`introduction_received`) carry these fields so the UI can display real-time popups with the sender's identity.

## Data Flow Summary

### Outbound (Scanner scans someone else's QR)

```
1. Scan QR → extract OOBI URL + intent
2. Layer 1: POST /api/contacts/resolve {oobi_url}
   → Go backend resolves AID, verifies KEL
   → Returns: aid, alias, kel_verified, photo, jcard
3. Layer 2: Show ContactActionPopup
   → Display: photo, name, AID (truncated), KEL verified badge
   → User taps "Add Contact" or "Dismiss"
4. If accepted: POST /api/contacts {oobi_url, alias}
   → Go backend stores contact, sends reverse introduction
```

### Inbound (Someone else scans your QR)

```
1. Remote agent resolves your OOBI (Layer 1 on their side)
2. Remote agent sends exchange payload with sender_photo + sender_jcard
3. Go backend receives exchange → broadcasts WebSocket event
4. EventService delivers 'introduction_received' to UI
5. Layer 2: Show ContactActionPopup
   → Display: sender photo, name, AID, action label
   → User taps "Add Contact" (accept) or "Dismiss" (reject)
6. If accepted: POST /api/contacts/{aid}/accept
   If rejected: POST /api/contacts/{aid}/reject
```

## Consequences

### Positive

- **Clean separation of concerns.** Protocol-level KERI verification is independent of application-level user interactions. Adding new intents does not require modifying the KERI resolution code.
- **Privacy-oriented design.** The UI only displays profile data (jCard, photo) during the Layer 2 consent step, after the AID/KEL has been checked. Note: the current implementation fetches both layers in a single resolve call, so profile data is technically available before the consent popup. A future optimization could defer profile fetching to a separate request, fully enforcing the privacy boundary at the network level.
- **Extensible.** New interaction types (payments, credentials, messaging) can be added as new Layer 2 intent handlers without changing Layer 1.
- **Consistent consent model.** Every Layer 2 interaction goes through a consent popup (`ContactActionPopup`), ensuring the user explicitly approves each interaction.

### Negative

- **Two-step process.** The separation adds a conceptual step for developers — they must think about which layer their code belongs to.
- **Profile data requires a second fetch.** In the `add_contact` flow, the OOBI serve endpoint is called once for Layer 1 (AID/KEL) and the profile data comes along with it. Currently there is no separate fetch — the data is included in the same response. A future optimization could defer the profile fetch until Layer 2 explicitly requests it, but this would add latency to the consent popup display.

## Key Files

| File | Role |
|---|---|
| `identity-agent-core/server/server.go` | OOBI serve endpoint (`/oobi/{aid}`) — includes photo + jCard in response |
| `identity-agent-core/server/server.go` | Resolve endpoint (`/api/contacts/resolve`) — forwards photo + jCard from OOBI response |
| `identity-agent-core/server/server.go` | Exchange endpoint — processes inbound introductions, broadcasts WebSocket events |
| `identity_agent_ui/lib/widgets/contact_action_popup.dart` | Unified consent popup for both outbound (scan) and inbound (QR receive) flows |
| `identity_agent_ui/lib/screens/mobile/mobile_qr_scanner.dart` | Outbound flow — resolves OOBI, shows ContactActionPopup |
| `identity_agent_ui/lib/screens/mobile/share_menu.dart` | Inbound flow — receives WebSocket events, shows ContactActionPopup |
