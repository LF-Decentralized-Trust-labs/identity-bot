# Backend Migration Specification

**Status:** Draft
**Created:** 2026-02-25
**Last Updated:** 2026-02-25

## Overview

Backend migration is the process of transferring an Identity Agent's backend from one device to another — most commonly from a mobile standalone device to a desktop server. The primary motivation is to increase compute power, storage, and uptime by moving the backend "brain" from a resource-constrained mobile device to a dedicated desktop or server environment.

After migration, the user's identity (AID, keys, contacts, tunnel URL, etc.) continues to function seamlessly on the new device. The mobile device may then operate as a Remote Controller (WITH or WITHOUT Root Keys) connected to the new desktop backend, or it may be decommissioned entirely.

### Migration Direction

The initial and most common migration path is:

```
Mobile Standalone → Desktop Standalone
```

Future migration paths may include:

- Desktop Standalone → Desktop Standalone (server replacement)
- Mobile Standalone → Mobile Standalone (phone upgrade)
- Any Standalone → Remote Controller + new Standalone (splitting roles)

## Migration Flow

### High-Level Process

1. **Source device** (mobile) generates a migration bundle containing all transferable state.
2. **Target device** (desktop) initiates onboarding and selects "Connect to Existing Identity."
3. Target connects to source's OOBI endpoint and requests the migration bundle.
4. Target receives and applies all settings, identity data, contacts, and tunnel configuration.
5. Target claims the same tunnel name (if using Grape ID or similar named provider) and establishes a new tunnel connection.
6. Source device either transitions to a Remote Controller role or is decommissioned.

### Transfer Mechanism

The migration bundle is served via the source device's OOBI endpoint. When the target device connects during the "Connect to Existing Identity" onboarding flow, it can request the full migration bundle alongside the standard OOBI resolution. This leverages the existing cryptographic trust establishment (OOBI verification, KEL validation) to ensure the migration is authenticated.

The bundle could be:
- A single JSON payload served at a dedicated endpoint (e.g., `GET /api/migration/export`)
- Included as extended fields in the OOBI response
- Transferred via a QR code containing a migration-specific OOBI URL

## Data Transfer Requirements

### 1. Identity Data (Critical)

These are the core KERI identity artifacts. Without them, the identity cannot operate.

| Data | Source | Notes |
|------|--------|-------|
| AID (Autonomic Identifier) | KERI engine state | The primary identifier |
| Root keys (signing + rotation) | KERI engine state | Private keys for the AID |
| Key Event Log (KEL) | `data/kel/` or KERI engine | Full event history |
| Inception event | KEL | The genesis event |
| BIP-39 mnemonic seed | User-provided during onboarding | Used to derive keys; user must re-enter or transfer securely |

**Security note:** Private keys and mnemonic seeds require the highest level of protection during transfer. The migration channel must be encrypted and authenticated.

### 2. Tunnel Settings

These settings ensure the same public URL continues working after migration.

| Data | Source File | Notes |
|------|-------------|-------|
| `tunnel_provider` | `data/settings.json` | e.g., "grapeid", "cloudflare", "ngrok" |
| `tunnel_domain` | `data/settings.json` | e.g., "grapeid.org" |
| `tunnel_extension` | `data/settings.json` | e.g., "alice" — the claimed name |
| `ngrok_auth_token` | `data/settings.json` | If using ngrok |
| `cloudflare_tunnel_token` | `data/settings.json` | If using authenticated Cloudflare tunnels |

### 3. Contact Data

| Data | Source File | Notes |
|------|-------------|-------|
| Verified contacts | `data/contacts.json` | All mutual, pending_inbound, and rejected contacts |
| Pending requests | `data/pending_requests.json` | Failed OOBI resolutions with error reasons and expiry dates |

### 4. Application Settings

| Data | Source File | Notes |
|------|-------------|-------|
| Onboarding state | SharedPreferences | Mode selection, completion flags |
| User preferences | Future settings store | Theme, notification preferences, etc. |

## Provider Continuity

A critical invariant of migration is **URL continuity** — the same public URL must remain accessible after migration, regardless of tunnel provider.

### Grape ID

- **Name persistence:** grapeid.org stores claimed names in a PostgreSQL database. Names persist across server restarts and client reconnections.
- **Migration process:** The target device claims the same name via `POST /claim-name`. If the source device's tunnel is still active, the name will be reported as "already taken." The source must disconnect its tunnel first, then the target can claim the name.
- **Recommended flow:** Source device stops its tunnel → target device claims the same name → target establishes Chisel connection → same URL is now served by the target.
- **Note:** There is currently no "transfer name" API on grapeid.org. If the source device is unreachable (lost, broken), the name cannot be released. A future `/release-name` endpoint on grapeid.org would address this.

### Cloudflare (Quick Tunnels)

- Quick tunnels generate random URLs (e.g., `random-words.trycloudflare.com`) that change on every restart. URL continuity is **not possible** with quick tunnels.
- Authenticated Cloudflare tunnels with named routes can maintain the same URL if the tunnel token is transferred to the new device.

### ngrok

- Free ngrok tunnels generate random URLs that change on restart. URL continuity requires a paid ngrok plan with reserved domains.
- The `ngrok_auth_token` must transfer to the new device.

### None

- When no tunnel is configured, the server uses `PUBLIC_URL` env var or the request host header. URL continuity depends on DNS/network configuration.

## Tunnel Reconnection Behavior (Mobile)

On mobile devices, the tunnel connection lifecycle is tied to the app lifecycle:

| Event | Tunnel State | Public URL |
|-------|-------------|------------|
| App opens / foregrounds | Tunnel connects, name re-claimed | Reachable |
| App backgrounds (briefly) | Connection may persist | Likely reachable |
| App closed / phone sleeps | Connection drops | Unreachable (502/timeout) |
| App reopens after sleep | Tunnel reconnects, name re-claimed | Reachable again |
| Phone has no network | Connection impossible | Unreachable |

### Name Reservation

With Grape ID, the name stays reserved in the database even when the tunnel is disconnected. No other device can claim it. When the app reopens, it claims the same name again and gets re-assigned a port.

### UI Requirements

The dashboard should display a **tunnel status indicator** showing:
- **Connected** (green): Tunnel is active, public URL is reachable
- **Disconnected** (amber): Tunnel is not connected, public URL is unreachable
- **Error** (red): Tunnel failed with an error (with error details)

This lets the user confirm at a glance whether their agent is reachable from the outside.

## Future Additions

> **This section is a living checklist.** When new features or backend functionality are added that would need to transfer during migration, add an entry here with the feature name, what data needs to transfer, and where it is stored.

| Feature | Data to Transfer | Storage Location | Added Date |
|---------|-----------------|------------------|------------|
| Tunnel settings | provider, domain, extension, auth tokens | `data/settings.json` | 2026-02-25 |
| Contacts | contact records, pending requests | `data/contacts.json`, `data/pending_requests.json` | 2026-02-25 |
| Identity (KERI) | AID, keys, KEL, inception events | KERI engine state / `data/kel/` | 2026-02-25 |
| Profile (jCard) | display name, given/family name, org, title, email, phone, note, photo (base64) | `data/profile.json` | 2026-03-02 |
| _Example: Credentials_ | _Issued/held verifiable credentials_ | _`data/credentials/`_ | _TBD_ |
| _Example: Message history_ | _Encrypted message threads_ | _`data/messages/`_ | _TBD_ |
