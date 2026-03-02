# Grape ID Hub — AID-Based Tunnel Reconnection Specification

**Status:** Draft
**Created:** 2026-03-02
**Purpose:** Enable Identity Agent servers to reconnect to their previously-claimed tunnel names across restarts using AID-based ownership.

## Overview

Currently, the Grape ID hub treats every `/claim-name` request as a new registration. If an agent restarts and the name is still reserved in the hub's database, the claim is rejected with "name is already taken" — even though the same agent is requesting it. This prevents reconnection after restarts.

This specification adds AID-based ownership to tunnel names and introduces two new endpoints (`/reconnect` and `/release-name`) to support the full lifecycle: register → reconnect → release.

**Future enhancement:** The `aid` field will eventually be accompanied by KERI signature headers for cryptographic proof of ownership. The current implementation uses a trust-on-first-use (TOFU) model where the AID is associated with the name on first claim and verified on subsequent reconnects.

## Database Schema Changes

Add an `aid` column to the table that stores claimed names/tunnels:

```sql
ALTER TABLE tunnels ADD COLUMN aid TEXT;
```

Or if creating the table fresh:

```sql
CREATE TABLE tunnels (
    name TEXT PRIMARY KEY,
    port INTEGER NOT NULL,
    aid TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Endpoint Changes

### 1. `POST /claim-name` (Modified)

**Purpose:** First-time registration of a new tunnel name.

**Changes:** Accept an optional `aid` field. Store it with the name record.

**Request body:**
```json
{
    "name": "alice",
    "aid": "ED4zKjGVbjhKp-otddHszlj0bNERyTKYDS3nTqS7J_av"
}
```

**Logic:**
1. If `name` is not claimed → allocate port, store `name`, `aid`, and `port` → return success
2. If `name` is already claimed → return 409 Conflict (do NOT allow re-claim via this endpoint; agent should use `/reconnect`)

**Success response (200):**
```json
{
    "name": "alice",
    "port": 10042,
    "tunnel_path": "/tunnel",
    "message": "Name claimed successfully"
}
```

**Conflict response (409):**
```json
{
    "error": "name is already taken"
}
```

### 2. `POST /reconnect` (New)

**Purpose:** Re-establish a previously claimed tunnel connection after agent restart.

**Request body:**
```json
{
    "name": "alice",
    "aid": "ED4zKjGVbjhKp-otddHszlj0bNERyTKYDS3nTqS7J_av"
}
```

**Logic:**
1. Look up `name` in the database
2. If `name` not found → return 404
3. If `name` found but `aid` does not match the stored AID → return 403
4. If `name` found and `aid` matches → allocate a new port (or reuse the existing one), update the record → return success

**Success response (200):**
```json
{
    "name": "alice",
    "port": 10042,
    "tunnel_path": "/tunnel",
    "message": "Reconnected successfully"
}
```

**Not found response (404):**
```json
{
    "error": "name not found"
}
```

**AID mismatch response (403):**
```json
{
    "error": "aid mismatch: name is owned by a different identity"
}
```

**Implementation notes:**
- The response format is identical to `/claim-name` so the agent can handle both with the same code
- The port may be the same as before or a newly allocated one — the agent doesn't care, it uses whatever port is returned
- If the previous Chisel connection is still lingering (not yet timed out), the hub should close it before allocating the new port

### 3. `POST /release-name` (New)

**Purpose:** Voluntarily release a claimed name during graceful shutdown. Frees the port immediately.

**Request body:**
```json
{
    "name": "alice",
    "aid": "ED4zKjGVbjhKp-otddHszlj0bNERyTKYDS3nTqS7J_av"
}
```

**Logic:**
1. Look up `name` in the database
2. If `name` not found → return 404
3. If `name` found but `aid` does not match → return 403
4. If `name` found and `aid` matches → delete the record, free the port → return success

**Success response (200):**
```json
{
    "message": "Name released successfully"
}
```

**Not found response (404):**
```json
{
    "error": "name not found"
}
```

**AID mismatch response (403):**
```json
{
    "error": "aid mismatch: name is owned by a different identity"
}
```

**Implementation notes:**
- This is called on graceful shutdown. If the agent crashes, this endpoint is never called — the name stays reserved, and the agent uses `/reconnect` on the next startup
- After release, the name is available for anyone to claim again via `/claim-name`

## Agent-Side Flow

The Identity Agent implements this flow on startup:

```
1. Load saved tunnel settings (provider, domain, extension/name)
2. Load agent AID from identity store

3. Try POST /reconnect {"name": "<extension>", "aid": "<AID>"}
   → 200? Parse response, connect Chisel tunnel. Done.
   → 404 (name not found)? Go to step 4.
   → 403 (AID mismatch)? Fail with error — someone else owns this name.
   → Connection error / other? Go to step 4.

4. Try POST /claim-name {"name": "<extension>", "aid": "<AID>"}
   → 200? Parse response, connect Chisel tunnel. Done.
   → 409 (already taken)? Fail with error.
   → Other error? Fail with error.
```

On graceful shutdown:
```
1. POST /release-name {"name": "<extension>", "aid": "<AID>"}
   → Best-effort, 3-second timeout. Log result but don't block shutdown.
2. Close Chisel client.
```

## Backward Compatibility

- **Agent with new code, hub without new endpoints:** The agent tries `/reconnect` first, gets a 404 (endpoint doesn't exist on hub), then falls back to `/claim-name` with the `aid` field. Old hubs ignore the extra `aid` field. Behavior is the same as before.
- **Agent with new code, hub with new endpoints:** Full reconnect flow works. Names persist across restarts.
- **Hub with new endpoints, agent without new code:** Old agents don't call `/reconnect` or send `aid`. The `/claim-name` endpoint stores `NULL` for `aid`. Names without an AID cannot be reconnected (no ownership proof), but existing behavior is unchanged.

## Future: KERI Signature Verification

In a future iteration, all requests will include a KERI signature header:

```
X-KERI-AID: ED4zKjGVbjhKp-otddHszlj0bNERyTKYDS3nTqS7J_av
X-KERI-Signature: <base64-encoded Ed25519 signature of request body>
```

The hub will:
1. Resolve the AID's Key Event Log (KEL) to obtain the current signing key
2. Verify the signature against the request body
3. Only proceed if the signature is valid

This upgrades from TOFU to full cryptographic verification. The current `aid` field lays the groundwork by establishing the ownership association.
