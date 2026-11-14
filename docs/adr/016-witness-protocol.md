# ADR-016: Witness Protocol — Inter-Agent Witness Request Workflow

**Status:** Accepted. Three statements are superseded by ADR-070 (2026-10-24): that this is a stub, that at most 3 witnesses are served concurrently, and the description of the receipt. The endpoints and request workflow below stand.
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
2. Check witness capacity (at most `MaxOutgoingWitnessing` (15) identities witnessed for concurrently; corrected by ADR-070, which found 3 contradicted by the code).
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

**Amended 2026-10-24: the answer is signed, and acted on only when it was asked for.**
The route is public, and acting on an answer makes its sender a witness, so an
unsigned answer added a stranger as a trusted contact and enrolled it. The body now
names the responder and its witness key, and carries `stamp` and `signature`:

```json
{
  "requester_aid": "E...",
  "responder_aid": "E...",
  "witness_key": "B...",
  "decision": "accepted",
  "reason": "",
  "backend_type": "desktop",
  "task_id": "...",
  "request_id": "...",
  "stamp": "2026-10-24T18:00:00.123456789Z",
  "signature": "0B..."
}
```

The signature is by the responder's witness key, the non-transferable identifier it
receipts under and publishes with its OOBI, over the statement
`witness-accept/v2\n<requester_aid>\n<responder_aid>\n<witness_key>\n<decision>\n<backend_type>\n<request_id>\n<stamp>`.
`request_id` is the identifier the requester gave the request this answers; an answer is acted on only if it names a request the requester sent to that responder and has not completed.
That key is checked from the identifier alone, every witness holds it, and it is the
key the requester will rely on for that witness's receipts. Before anything is
written, the requester checks that `witness_key` is the one the responder published,
that the signature verifies against it, that the stamp is within five minutes and
newer than the last answer it acted on from that responder, and that a request to
that contact is still pending. The requester records its request as pending before
sending it, because the answer arrives on a separate connection and can come first.
A decline is held to the same rule. An answer never creates a contact. An unsigned
answer from an older version is refused, so a request to an Identity Agent that has
not been updated stays pending until it is.

### Identities a witnessed identity delegated (amended 2026-10-22)

Witnessing an identity's delegates is consented to, not assumed. A witness request says
whether it covers the identities the requester delegates (`covers_delegates`); an Identity
Agent that anchors its record through a delegated identity asks for it. A witness that
accepted such a request, and whose operator allows it, witnesses an identity that
requester delegated, from its delegated inception, when the key log it holds for the
delegator approves exactly that inception, and only once the inception's own signature
holds. It witnesses the delegate only while it still witnesses the delegator: when it
stops, by withdrawal or otherwise, it stops witnessing the delegates too. The operator can
switch delegate witnessing off (`witness.delegates` = `off`) or cap how many delegates one
delegator may have witnessed (`witness.delegates_max`; 1024 when none is set). A request that does not ask covers
no delegate.

The request route is open, so the signature is the gate. The request carries a `request_id`, a `stamp`
and the requester's `signature`, by its current key, over `witness-request/v3`, its identifier, the identifier
of the witness it asks, the OOBI the answer is to be sent to, the `request_id`, whether it covers its
delegates, and the stamp, to the nanosecond. A witness enrols a requester, answers it, or changes
whether its delegates are covered, only on a request whose signature verifies against the requester's
current key (from the key log the witness holds, or else the key its contact resolved) and
whose stamp is within five minutes and newer than the last such request it acted on from
that requester. Anything else, a replay or a request meant for another witness or another
address included, is refused as `unsigned_request`: nothing is created and nothing is sent. The answer says whether the requester's delegates are now covered
(`covers_delegates`). An identity already witnessed for, asking again, takes no more
capacity. An Identity Agent that anchors its record asks its witnesses when its record
identity is made, and again once after each start, and reports the ones that will not
cover it.

An event the witness already holds is answered with the receipt it gave, so a controller
sending its key log from where it thinks the witness stopped carries on; something else at
the same place is refused as a conflicting history. Sequence numbers are read as KERI
writes them, in hexadecimal.

`GET /witness/kel/{aid}/tip?nonce=…` answers how far the witness holds an identity's key
log: the newest event's place and digest, signed by the witness's own key together with
the asker's nonce, so the answer is fresh and the witness's own. A controller asks this
before sending, and sends only what the witness lacks; a witness that has confirmed holding
the log as far as it goes, by its tip or its receipts, is not asked again until there is
more to send, or until an hour has passed, so a witness that has fallen behind is noticed
and filled again; a witness's signed tip is believed as it stands, lower than before too. `GET /witness/kel/{aid}/event/{sn}` hands back one event of a key log
exactly as its controller published and signed it; the asker checks it extends its own
key log and is signed by the identity's key before believing it. An event is sent to
exactly the witnesses it names, and a send that runs in the background is not cut short
by its caller returning.

### The key state notice and a witness's location (added 2026-11-13)

Two signed statements a witness makes about itself are defined in the `witnessproto`
module, so that a witness or watcher outside this core and the core itself build and
check them with one implementation. No route in the core serves or asks for them yet;
this fixes their form.

**The key state notice** is KERI's reply `/ksn/{witness}`: the route names the witness
that signs it, not the identifier it is about, as keripy's does, and the reply carries
keripy's key state record of the identifier after its newest event (`vn`, `i`, `s`, `p`,
`d`, `f`, `dt`, `et`, `kt`, `k`, `nt`, `n`, `bt`, `b`, `c`, `ee`, `di`, in keripy's
order). The witness signs the reply's bytes with its own non-transferable key, the
unindexed `0B` signature keripy attaches to a reply from such a key. A reader believes a
notice only when it is signed by the witness it asked (a key it took from the log it is
checking, never one the answer names), its route names that witness, its digest commits
to it, it is about the identifier asked, and it is dated within five minutes of now.

**A witness's location** is KERI's `/loc/scheme` reply for the witness itself, signed the
same way, naming an `http` or `https` address with a host and nothing but a host, port and
path. Any other address is refused when it is built and when it is read. A controller's
own address is the separate `endpoint-record/1` of ADR-062; this one is a witness's
statement of its own address, in the form KERI defines for exactly that.

Both are pinned against keripy 1.3.6: `witnessproto/testdata/keripy_key_state_notice.json`
holds a notice, a key state record and a location keripy made, and witnessproto reads
them and makes the same bytes and signatures.

Where this departs from keripy, so nobody takes it for more:

- **Carried as JSON with a detached signature** (`rpy_b64`, `witness_aid`, `signature`),
  not as a CESR stream with the signature attached, so keripy's own reactor will not
  ingest it as it stands. The reply and the signature are keripy's.
- **A notice for an identifier the witness holds nothing for**, or that the asker may not
  read, is still given, with a record naming only the identifier. keripy gives no reply.
  The asker must be able to tell an answer from no answer, and must not be able to tell
  "not held" from "not allowed to read".
- **Fresh by its date only.** keripy's reply carries no nonce from the asker, so neither
  does this: a notice recorded just before a rotation can be replayed for up to five
  minutes. Where an answer must be made for one question and no other, the nonce-signed
  tip above is the one to ask.
- **`f` is written equal to `s`.** keripy's `f` is the first-seen ordinal, which differs
  from `s` only after a recovery rotation has superseded events; the record here follows
  one chain.

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
