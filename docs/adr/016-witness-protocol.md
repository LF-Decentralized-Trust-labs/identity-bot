# ADR-016: Witness Protocol — Inter-Agent Witness Request Workflow

**Status:** Stub (endpoints defined, full implementation deferred to Sprint 4)
**Date:** 2026-03-21

## Context

In KERI, a witness is an Identity Agent that countersigns key events and serves as an independent receipt point. Our Identity Agent implements the concept of `is_witness` (a boolean flag on a contact record) which tracks whether a contact's Identity Agent is currently serving as a witness for our key events.

The witness designation is **not** a contact relationship category chosen by the user. It is the result of a cryptographic protocol exchange between two Identity Agents. The user never manually assigns a witness — the agent does this automatically based on capacity and policy.

## Decision

### Two-Layer Separation

1. **Contact Type** (`contact_type` field) — user-facing relationship category managed by the user.
   Values: `general` | `trusted` | `professional`

2. **Is Witness** (`is_witness` field) — KERI protocol flag managed automatically by the agent.
   Set to `true` only after the witness exchange protocol completes successfully.

These two concepts are independent. A trusted contact may or may not be a witness. A witness contact may be categorized as general, trusted, or professional.

### Witness Protocol Flow (server-to-server, fully automated)

```
Requester Agent                         Recipient Agent
      |                                       |
      |  POST /api/witness/request            |
      |  { requester_aid, requester_oobi,     |
      |    event_json }                       |
      |-------------------------------------->|
      |                                       |
      |                           [Agent evaluates capacity & policy]
      |                           [Creates task: witness_request_received]
      |                           [Decides: accept or decline]
      |                                       |
      |  POST /api/witness/accept             |
      |  { task_id, requester_aid,            |
      |  { decision: "accepted"|"declined",   |
      |    reason }                           |
      |<--------------------------------------|
      |                                       |
      |  [On accepted: set contact.is_witness = true]
      |  [Create task: witness_request_sent → completed]
      |  [Emit WebSocket event]               |
```

### Key Properties

- **Server-to-server only** — no human action required or presented. Both accept and decline are automatic.
- **Task-based tracking** — a `task` record is created for each witness request (type: `witness_request_sent` or `witness_request_received`). Tasks are visible on the dashboard tasks card.
- **Fast resolution** — the recipient agent responds quickly (typically within seconds). If the connection is interrupted, the task remains `pending` until a response arrives or the task times out.
- **No notifications** — no alert is shown to the user. The task card provides passive visibility.
- **`is_witness` flag** — set on the contact record only after the full exchange completes successfully. Cleared if the witness relationship is later revoked (future: rotation events).

### Endpoint Specification

#### `POST /api/witness/request` (inbound — we receive this)

Receives a witness request from a remote Identity Agent.

**Request body:**
```json
{
  "requester_aid": "E...",
  "requester_oobi": "https://agent.example.com/oobi/E...",
  "event_json": "{...}"
}
```

**Response (202 Accepted):**
```json
{
  "status": "received",
  "message": "Witness request received. Processing automatically."
}
```

**Behavior (Sprint 4):**
1. Verify requester AID is a known contact with `status = accepted`.
2. Check witness capacity (max 3 witnesses concurrently).
3. Evaluate policy (future: configurable rules).
4. Create task `witness_request_received` with status `in_progress`.
5. Call `POST <requester_oobi>/api/witness/accept` with decision.
6. Update task to `completed` or `failed`.

#### `POST /api/witness/accept` (inbound — we receive this)

Receives the accept/decline response from a remote Identity Agent to a witness request we sent.

**Request body:**
```json
{
  "task_id": "uuid",
  "requester_aid": "E...",
  "decision": "accepted",
  "reason": ""
}
```

**Response (200 OK):**
```json
{
  "status": "received",
  "message": "Witness decision received."
}
```

**Behavior (Sprint 4):**
1. Look up the pending task by `task_id` or `requester_aid`.
2. If `decision == "accepted"`: set `contact.is_witness = true`, update task to `completed`.
3. If `decision == "declined"`: update task to `failed` with `detail = reason`.
4. Emit a WebSocket event to notify connected UI.

### Task Types

| `type` | Created by | Resolved by |
|---|---|---|
| `witness_request_sent` | Our agent, when we send a witness request | Incoming `/api/witness/accept` |
| `witness_request_received` | Our agent, when we receive `/api/witness/request` | Our agent, after deciding and calling accept on requester |

## Consequences

- The `is_witness` flag on `ContactRecord` is the single source of truth for active witness status.
- The witness badge in the UI reflects `contact.is_witness` — no other logic determines witness display.
- The user-facing Contact Type dropdown never includes "witness" — witness status is shown as a separate badge.
- Stub endpoints are live as of Sprint 3. They log and acknowledge but do not apply state changes.
- Full implementation is deferred to Sprint 4.
