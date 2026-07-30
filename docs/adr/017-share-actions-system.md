# ADR-017: Share Actions System

**Status:** Accepted
**Date:** 2026-03-21
**Deciders:** Rob Andersen

---

## Context

The Identity Agent needs a way for users to share their identity with others through different interaction types — adding a contact, showing their ID, requesting payment, sharing a file, sharing a credential, and more. These interaction types are expected to grow over time as new protocols and use cases are implemented.

### The problem with hardcoding

The naive approach is to hardcode the list of share actions in the Flutter UI. This has a critical limitation: **every change to the list — adding an action, renaming one, enabling one that was previously "coming soon", or changing the user flow it triggers — requires a full app update pushed to every user.**

For a self-hosted, user-controlled identity agent this is particularly unacceptable because:

1. Users self-host and self-install. There is no forced update mechanism.
2. The Data Manager (a sandboxed app service provider) needs to be able to extend and configure the agent's capabilities without modifying the core Identity Agent binary.
3. Different deployments may want different action sets enabled for their users.

---

## Decision

Store the share action list in the `identity.db` SQLite database under a `share_actions` table. The table is seeded on first run by migration 7 with the same actions previously hardcoded on mobile. Actions can be created, updated, and deleted at runtime through the REST API — primarily by the Data Manager sandbox app.

### Schema

```sql
CREATE TABLE share_actions (
    id          TEXT PRIMARY KEY,
    action_key  TEXT NOT NULL UNIQUE,  -- used as ?action= param in OOBI URLs
    name        TEXT NOT NULL DEFAULT '',
    subtitle    TEXT NOT NULL DEFAULT '',
    icon        TEXT NOT NULL DEFAULT '',  -- Material Icons name string
    is_enabled  INTEGER NOT NULL DEFAULT 1,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL DEFAULT ''
);
```

### Seeded actions (migration 7)

| action_key        | Name              | Enabled | Notes                              |
|-------------------|-------------------|---------|-------------------------------------|
| `add_contact`     | Add Contact       | ✅       | Fully functional — OOBI QR flow     |
| `show_id`         | Show ID           | ❌       | Coming soon                         |
| `request_payment` | Request Payment   | ❌       | Coming soon                         |
| `share_file`      | Share a File      | ❌       | Coming soon                         |
| `credential_request`| Share / request a verifiable credential | ❌ | Coming soon |

### REST API

| Method | Endpoint                    | Description                        |
|--------|-----------------------------|------------------------------------|
| GET    | `/api/share-actions`        | Fetch all actions (ordered by sort_order) |
| POST   | `/api/share-actions`        | Create a new action                |
| PUT    | `/api/share-actions/{id}`   | Update an existing action          |
| DELETE | `/api/share-actions/{id}`   | Remove an action                   |

The Data Manager sandbox app has write access to `identity.db` through these endpoints. No other sandboxed app has write access to the identity domain.

---

## UI behavior

### Mobile (ShareMenu)

Tapping the **Share** button in the bottom navigation opens `ShareMenu` as a bottom sheet. The sheet:

1. Fetches `/api/share-actions` on open (non-blocking)
2. While fetching, or if the fetch fails, renders a hardcoded fallback list identical to the seeded DB values — so the sheet is never empty
3. Actions with `is_enabled = true` are tappable; their `action_key` determines the navigation target
4. Actions with `is_enabled = false` show a "Soon" badge and are non-interactive

**Action routing on mobile:**

| action_key         | Handler                                          |
|--------------------|--------------------------------------------------|
| `add_contact`      | Navigate to `_AddContactScreen` (QR + OOBI URL)  |
| All others         | "Coming Soon" dialog                             |

### Desktop (Engagement section — Share QR Code card)

The dashboard's right-column Engagement section contains two cards: **Share QR Code** and **Scan**.

**Share QR Code card:**

- Renders immediately using a 3-item fallback list (Add Contact, Request Payment, Share a File) so the card is always interactive even before the backend connects
- Clicking opens `_ShareQrDialog`, a stateful dialog that:
  1. Shows a dropdown of all actions from the loaded list
  2. Defaults to the first enabled action (`add_contact`)
  3. On dropdown change, calls `GET /api/oobi?action=<action_key>` and renders the QR code + copyable OOBI URL inline
  4. Disabled actions show a "Soon" badge and are non-selectable in the dropdown
  5. The dialog re-fetches the OOBI URL whenever the selected action changes

**Scan card:**

- Uses a conditional import (`camera_service.dart`) to detect camera availability
  - Web build: calls `window.navigator.mediaDevices.enumerateDevices()` via `dart:html`
  - Native desktop build: always returns `false` (stub)
- If a camera is detected: card is enabled, shows "Camera available — scan a contact QR code"
- If no camera: card is grayed out at 45% opacity, shows "Device not available"
- Scan flow is not yet implemented (shows "Coming soon" snackbar)

### Fallback list rationale

Both mobile and desktop initialize with a hardcoded fallback list of 3 actions before any API response arrives. This ensures:

- The Engagement card is never blank during backend startup
- Users on an older backend that predates migration 7 still see a usable UI
- Airplane-mode or connectivity edge cases don't break the share flow

The fallback is intentionally a subset (3 items) rather than all 5, reflecting the most useful actions to surface immediately.

---

## Consequences

### Positive

- **No app update required** to add, rename, enable, or disable a share action — the Data Manager can push changes that take effect on next app launch or sheet open
- **Single source of truth** — both mobile and desktop fetch from the same `/api/share-actions` endpoint
- **Extensible** — new `action_key` values automatically appear in both UIs once the Data Manager adds them; the UI routes based on `action_key` so new flows can be wired in incrementally
- **Resilient** — the fallback list ensures the UI works even without a backend connection

### Negative / Trade-offs

- The UI must handle a loading state (brief) before actions arrive — mitigated by the pre-seeded fallback
- New `action_key` values require a corresponding handler to be coded into the Flutter clients before they become truly interactive; enabling an unknown key will show "Coming Soon" until a client update ships
- The Data Manager does not yet exist as a sandbox app — the REST endpoints are available but the management UI is future work

---

## Implementation notes

- `store.ShareAction` in `identity-agent-core/store/store.go` is the canonical Go struct
- `ShareAction` in `identity_agent_ui/lib/services/core_service.dart` is the Dart model; uses `const` constructor so fallback lists can be compile-time constants
- `camera_service.dart` / `camera_service_web.dart` / `camera_service_stub.dart` follow the existing conditional import pattern from ADR-013
- The `action_key` field is the stable identifier used as `?action=<key>` in OOBI URLs; `id` is the DB primary key (prefixed `sa-`)

---

## Amendment (2026-07-21): canonical action registry

The runtime `share_actions` table is now backed by a **canonical, machine-readable registry** so the set of actions is defined once and imported everywhere, rather than hardcoded per seed. See the spec in [`docs/action-code-registry.md`](../action-code-registry.md) and the data in [`identity-agent-core/actions/registry.json`](../../identity-agent-core/actions/registry.json) (validated by `registry.schema.json`).

**Identifier reconciliation.** Each action now has **two identifiers that bind to one registry entry**:
- **`code` (integer `t`) — canonical on the wire.** It is what an Ask envelope carries (`"t": 3`) and is immutable once assigned.
- **`key` (string) — the stable human/URL handle.** It is what this ADR called `action_key` (`?action=add_contact`, `share_actions.action_key`).

So `share_actions` rows reference a registry entry by `key`, and the same entry's `code` is the wire identifier. The registry entry also carries a `ui` block (`share_menu`, `icon`, `enabled`, `sort_order`, `subtitle`) — the seed source for the presentation fields this ADR defined.

**Relationship of the two lists.** `share_actions` is the **user-initiable share-menu view** — the subset of registered actions a person can start from the Share sheet (those with `ui.share_menu = true`). The registry is the full protocol vocabulary (including actions a person only ever *receives*, e.g. `login`). Actions in this ADR's original seed that do not yet have an assigned `code` (e.g. `show_id`, `request_payment`, `share_file`) remain UI-menu entries pending a registry `code` assignment via the proposal process in the spec.

**Intended seeding path (follow-up).** The migration that seeds `share_actions` should read `registry.json` (filtered to `ui.share_menu = true`) rather than hardcoded values, so adding a share action is a registry change, not a code change. That wiring is a distinct change tracked separately; this amendment establishes the canonical data + identifier binding it depends on.
