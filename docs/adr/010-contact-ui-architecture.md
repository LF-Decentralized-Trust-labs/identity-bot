# ADR 010: Contact UI Architecture — Unified Popup, Real-Time Events & Dashboard Refresh

**Date:** 2026-03-07
**Status:** Accepted
**Relates to:** ADR-009 (Two-Layer OOBI Exchange), ADR-003 (Adaptive Architecture — OOBI/Contacts)

## The Problem This Solves

The contact management UI had grown organically across three separate implementations:

1. **`_ConsentDialog`** in `mobile_qr_scanner.dart` — shown when the user scans someone's QR code (outbound flow). An `AlertDialog` with avatar, name, jCard fields, AID snippet, and KEL verified badge.

2. **`_ConnectionPopup`** in `share_menu.dart` — shown when someone scans the user's QR code (inbound flow via WebSocket). An animated overlay with avatar, name, and generic "Add" / "Dismiss" buttons.

3. **`AlertCard`** on the dashboard — shown for pending contact requests. A card with name, AID, and "Accept" / "Reject" buttons.

These three components displayed the same information (a contact's identity) with inconsistent layouts, different button labels, and divergent behavior. The `_ConnectionPopup` for inbound requests lacked critical identity verification data (AID, KEL status) and had no wired accept/reject API calls — tapping "Dismiss" or the backdrop just closed the popup without any backend action.

Additionally, the dashboard did not refresh its alert counts when the user returned from scanning, sharing, or managing contacts, causing stale badge counts.

## The Decisions

### Decision 1: Unified `ContactActionPopup` Widget

A single reusable popup widget (`lib/widgets/contact_action_popup.dart`) replaces both `_ConsentDialog` and `_ConnectionPopup`. The widget accepts parameters for customization:

| Parameter | Type | Purpose |
|---|---|---|
| `name` | String | Display name |
| `photo` | String | Base64-encoded profile photo (empty string for no photo) |
| `aid` | String | The contact's AID (displayed truncated) |
| `kelVerified` | bool? | KEL verification status (null = not checked, true = verified, false = unverified) |
| `confidenceScore` | int | Confidence score placeholder (default 82%) |
| `intentLabel` | String | What the contact wants (e.g., "Wants to add you as a contact") |
| `confirmLabel` | String | Confirm button text (e.g., "Add Contact") |
| `dismissLabel` | String | Dismiss button text (e.g., "Dismiss") |
| `onConfirm` | VoidCallback | Called when confirm button is tapped |
| `onDismiss` | VoidCallback | Called when dismiss button is tapped |
| `onBackdropTap` | VoidCallback? | Called when the semi-transparent backdrop is tapped. Defaults to `onDismiss` if not provided. |

**Layout (top to bottom):**
1. Avatar — photo (with base64 decode) or initials fallback (first letters of name)
2. Display name — 18pt bold, max 2 lines
3. AID — truncated monospace text in a rounded chip
4. Verification row — KEL verified/unverified icon + label (when `kelVerified` is provided), green check + confidence score
5. Intent label — secondary text describing what the contact wants
6. Two buttons — "Dismiss" (outlined) and "Add Contact" (filled primary)

**Animation:** Scale-in (0.8 → 1.0) with `easeOutBack` curve + fade-in, matching the previous `_ConnectionPopup` behavior.

### Decision 2: Separate Backdrop Tap from Reject

The popup has three interactive zones:

| Zone | Action | Backend Effect |
|---|---|---|
| **Confirm button** ("Add Contact") | Calls `onConfirm` | Calls `POST /api/contacts/{aid}/accept` |
| **Dismiss button** ("Dismiss") | Calls `onDismiss` | Calls `POST /api/contacts/{aid}/reject` |
| **Backdrop** (semi-transparent area) | Calls `onBackdropTap` (defaults to `onDismiss`) | No backend call by default — just closes the popup |

This separation is critical for the inbound flow in `share_menu.dart`. Previously, tapping anywhere outside the popup triggered `onDismiss`, which is now wired to `rejectContact()`. An accidental backdrop tap would permanently reject a legitimate contact request. With the `onBackdropTap` parameter, the share menu sets backdrop taps to close-only (no reject), while the explicit "Dismiss" button calls reject.

For the outbound flow in `mobile_qr_scanner.dart`, `onBackdropTap` is not set, so backdrop taps default to `onDismiss` (which returns `false` from the dialog — no reject API call, just cancel).

### Decision 3: Accept/Reject Wiring in Share Menu

The inbound contact popup in `share_menu.dart` now calls the backend:

- **"Add Contact" button** → `CoreService.acceptContact(aid)` — upgrades the pending introduction to a mutual contact.
- **"Dismiss" button** → `CoreService.rejectContact(aid)` — removes the pending introduction.

Both methods already existed in `CoreService` and map to:
- `POST /api/contacts/{aid}/accept`
- `POST /api/contacts/{aid}/reject`

Previously, the popup had an "Add" button that popped the share sheet and navigated to contacts, but never called the accept endpoint. The reject flow had no implementation at all.

### Decision 4: Dashboard Refresh on Return

The `MobileDashboard` state class is made public (`MobileDashboardState`) with a `refreshAlerts()` method. The parent `_MobileAppState` uses a `GlobalKey<MobileDashboardState>` to call `refreshAlerts()` when returning from any sub-screen:

| Navigation Path | Refresh Trigger |
|---|---|
| QR Scanner → pop | `.then()` on `Navigator.push` |
| Share Menu → close | `.then()` on `showModalBottomSheet` |
| Share Menu → Add Contact Screen → pop | `onAddContactComplete` callback on `ShareMenu` widget |
| Contacts Screen → pop | `.then()` on `Navigator.push` |

The `ShareMenu` widget accepts an `onAddContactComplete` callback because the navigation path is two-step: the bottom sheet pops first (triggering the `showModalBottomSheet.then()`), then `_AddContactScreen` is pushed. The bottom sheet's `.then()` fires before the add-contact flow completes, so a separate callback ensures the dashboard refreshes after the actual contact interaction finishes.

### Decision 5: Real-Time Event System (WebSocket)

The Go backend includes a WebSocket-based EventHub (`identity-agent-core/server/events.go`):

- **Endpoint:** `GET /api/ws/events` — upgrades to WebSocket, pushes events to all connected clients.
- **Event types:**
  - `introduction_received` — a new inbound contact request arrived (carries `sender_display_name`, `sender_aid`, `sender_photo`, `sender_jcard`)
  - `contact_accepted` — a contact was upgraded to mutual
  - `pending_request_received` — an OOBI-unreachable sender left a pending request

The Flutter `EventService` singleton (`lib/services/event_service.dart`) maintains a persistent WebSocket connection:
- Auto-reconnects with linear backoff: 2s, 4s, 6s, 8s, 10s for the first 5 attempts, then 30s for all subsequent attempts (`2 * (attempt + 1)` for attempts 0–4, then 30s)
- Generation-based connection tracking to prevent stale listeners from interfering with new connections
- Broadcasts events via a `StreamController` that UI components subscribe to

**Web build compatibility:** On Flutter Web, `baseUrl` is empty (relative URLs per ADR-007). The `EventService` detects this and constructs the WebSocket URL from `Uri.base` (the current page origin), replacing `http` with `ws` / `https` with `wss`.

**Popup behavior:** Connection request popups only appear on the `_AddContactScreen` (inside `share_menu.dart`), not on the dashboard or other screens. The dashboard updates alert badge counts silently via WebSocket events, with a 60-second HTTP fallback poll as a safety net.

## Contact Photo Flow

Profile photos flow through the entire stack from storage to display:

```
Go Store (profile.json)
  → OOBI serve endpoint (/oobi/{aid}) includes "photo" field
  → Resolve endpoint (/api/contacts/resolve) forwards "photo"
  → Exchange payload includes "sender_photo"
  → WebSocket event includes "sender_photo"
  → ContactActionPopup displays photo or initials fallback
  → Contact cards, detail screens, alert cards all use same pattern
```

`ContactRecord` in Go (`store.go`) has a `Photo string` field for base64-encoded profile photos. The photo is populated when:
- The contact's OOBI is resolved (photo included in OOBI serve response)
- A reverse introduction is received (sender includes their photo in the exchange payload)

All Flutter UI surfaces use a consistent avatar pattern:
1. Try to decode `photo` as base64 → display as `CircleAvatar` with `MemoryImage`
2. If photo is empty or decode fails → display initials (first letters of display name) in a `CircleAvatar` with primary color background

## Consequences

### Positive

- **Consistent identity display.** All contact popups now use the same widget with the same layout: photo, name, AID, confidence score, and intent label. KEL verification status is shown when available — the outbound scan flow passes `kelVerified` from the resolve response, while the inbound WebSocket flow does not currently include KEL status (the `kelVerified` parameter is omitted, so the badge is hidden). Future work may add KEL data to WebSocket introduction events.
- **No accidental rejects.** Backdrop taps on inbound request popups close the popup without calling reject. Only the explicit "Dismiss" button triggers a backend reject.
- **Dashboard stays fresh.** Alert badge counts update immediately when returning from any sub-screen, without waiting for the 60-second fallback poll.
- **Single widget to maintain.** Bug fixes and design changes to the contact popup only need to happen in one file (`contact_action_popup.dart`), not three separate implementations.
- **Real-time responsiveness.** WebSocket events provide instant popup display when a remote agent scans the user's QR code. No polling delay.

### Negative

- **GlobalKey coupling.** The dashboard refresh mechanism uses a `GlobalKey<MobileDashboardState>`, which creates a tight coupling between `_MobileAppState` and the dashboard's internal state class. If the dashboard is refactored to use a different state management approach (e.g., provider, riverpod), the GlobalKey pattern would need to be replaced.
- **Confidence score is a placeholder.** The `confidenceScore` parameter defaults to 82% and is not computed from any real data. This is intentional — the real scoring algorithm will be implemented in a future phase. The UI is designed to display it, but the value is currently hardcoded.

## Key Files

| File | Role |
|---|---|
| `identity_agent_ui/lib/widgets/contact_action_popup.dart` | Unified popup widget (replaces `_ConsentDialog` and `_ConnectionPopup`) |
| `identity_agent_ui/lib/screens/mobile/mobile_qr_scanner.dart` | Outbound flow — uses `ContactActionPopup` for scan consent |
| `identity_agent_ui/lib/screens/mobile/share_menu.dart` | Inbound flow — uses `ContactActionPopup` for WebSocket-triggered popups, wires accept/reject |
| `identity_agent_ui/lib/screens/mobile/mobile_dashboard.dart` | Dashboard with public `MobileDashboardState.refreshAlerts()` |
| `identity_agent_ui/lib/screens/mobile/mobile_app.dart` | Parent — holds `GlobalKey<MobileDashboardState>`, triggers refresh on return from sub-screens |
| `identity_agent_ui/lib/services/event_service.dart` | WebSocket client — connects to `/api/ws/events`, broadcasts events |
| `identity_agent_ui/lib/services/core_service.dart` | `acceptContact()` and `rejectContact()` API methods |
| `identity-agent-core/server/events.go` | WebSocket EventHub — broadcasts events to connected clients |
| `identity-agent-core/store/store.go` | `ContactRecord.Photo` field for base64-encoded photos |
