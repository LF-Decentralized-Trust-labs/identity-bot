# ADR-024: KERI Network Participation — Witness, Watcher, Relay, did:webs Publisher

**Status:** Accepted; the relay client's transport and enrolment token are superseded by ADR-048 (2026-10-21)
**Date:** 2026-06-19
**Amended:** 2026-11-09 — the owner can opt an identity out of what the watcher tells others (see "Amendment, 2026-11-09" at the end)
**Amended:** 2026-11-11 — what peers are asked and told, and who chooses them (see "Amendment, 2026-11-11" at the end)
**Deciders:** Rob Andersen

---

## Context

KERI's security does not come from a blockchain or a central registry — it comes from a small set of network roles. **Witnesses** receipt an identity's key events so the controller can't later equivocate about its own history. **Watchers** observe identities they care about and detect *duplicity* (an identity presenting two conflicting versions of its KEL). And to be reachable at all, an always-on agent needs a stable public URL and a way to publish its KEL so others can resolve it.

A user-controlled Identity Agent should participate in these roles itself rather than renting them from a platform. An always-on agent (a desktop left on, a hosted "black box") has exactly the uptime a witness needs. A watcher is just disciplined record-keeping plus cross-checking. And `did:webs` lets an agent publish its KEL over plain HTTPS. The open question each role raises is *scope and trust*: who do we witness for, whose duplicity do we check and how aggressively, and how do we get a public URL without becoming dependent on one provider.

---

## Decision

### Witness — every always-on agent witnesses for its trusted contacts

An always-on Identity Agent runs a witness service that receipts the key events of the contacts it has accepted. The service (`witness.Service`, `identity-agent-core/witness/service.go`) receives a contact's event (`ReceiveEvent`), stores a KEL replica, and returns a receipt (the five-field KERI `rct` with an indexed signature over the event, in the agents' JSON envelope, per ADR-070; this said "a CESR receipt" before, which it did not return); it also broadcasts the user's own events to its enrolled witnesses and waits for finalization (`BroadcastEvent`). Enrollment is a two-step request/accept handshake (`SendWitnessRequest` / `ProcessInboundRequest` / `ApplyAcceptCallback`).

Witnessing is **scoped to trusted contacts only** (`IsContactWitnessEligible`, `identity-agent-core/witness/eligibility.go`): the contact must be `accepted` and of a durable type (general / trusted / professional / coworker); transactional contacts are excluded, and only always-on backends (desktop / hosted / commercial) are eligible — a mobile agent never advertises itself as a witness. The protocol caps the witness set (max 9, target 7, default threshold 5) and self-heals when a witness goes offline (heartbeat every 15 minutes; dropped after 4 consecutive failures). Pairwise AIDs may only use commercial witnesses, keeping per-RP identities off peers' witness pools.

### Watcher — three layers, L1 is authoritative for blocking

The watcher (`watcher.Service`, `identity-agent-core/watcher/`) detects duplicity across three escalating layers:

| Layer | Role | Source |
|---|---|---|
| **L1** | Self-watch: store the first-seen KEL digest per (AID, seq) locally | the agent's own store |
| **L2** | Since-inception / standing: query a shared standing watcher for its digest | a numbered standing-watcher host's `/public/kel-digest` (`DefaultL2DigestURL`) |
| **L3** | Peer duplicity detection: cross-check the digest with peer agents | a peer's `/public/kel-check` |

L1 records first-seen digests (`RecordFirstSeen`) and compares incoming digests against them (`VerifyKel`). L2 (`L2Client.QueryDigest`) fetches a signed standing digest from a shared watcher. L3 (`L3Client.CrossCheck`) asks peers whether their first-seen digest matches.

The blocking rule is deliberately conservative: duplicity **blocks** only on (a) a repeat L1 mismatch — a different digest at a sequence we've already seen — or (b) proof of duplicity from a standing watcher (ADR-075). A digest mismatch alone from L2 or L3 never blocks; it raises an escalation. Detected duplicity is recorded as a `DuplicityAlert` and anchored to the agent's own KEL (default-on) so the alert itself is tamper-evident. The verdict is a `VerifyKelResult` carrying the per-source outcomes and any alert.

### Relay client — the IA side of an open URL-relay protocol

An always-on agent behind NAT still needs a stable public URL to serve its `did:webs` artifacts and receive inbound requests. The relay client (`identity-agent-core/relay/`) is the **agent side of an open relay protocol** (version `IARELAY10JSON`): the agent connects *out* to a public relay (e.g. `relay.grapeid.org`), which assigns it a stable public hostname and tunnels inbound HTTPS back over a persistent WebSocket.

The flow is descriptor → enroll → allocate → serve:

1. `Client.FetchDescriptor` reads the relay's `/.well-known/url-relay-service.json` to discover its endpoints, path allowlist, and rate limits.
2. `Client.Enroll` registers the agent's AID/OOBI/public key and receives an enrollment token.
3. `Client.Allocate` (signed) requests a public URL with the intent to serve did:webs artifacts; it is idempotent (a 409 returns the existing allocation). `Client.Release` decommissions it.
4. *(Superseded by ADR-048: the frame protocol and its schema are removed; the session is `relayproto`.)* `TunnelAgent.Run` maintained the outbound WebSocket with exponential-backoff reconnect, receives request frames (`t:"req"`), dispatches them to the local HTTP server, and streams responses back as `res` / `res_chunk` frames (32 KB chunks, base64url bodies). Its frame schema was removed with it.

Allocation requests are signed over one canonical form, set by ADR-049 (sorted keys, string fields only, no HTML escaping, signature field left out), so the relay can authenticate the agent but cannot impersonate it. Because the protocol is open and discovery-driven, the agent is not bound to any single relay operator — `relay.grapeid.org` is one provider, not a dependency.

### did:webs publisher — serve your KEL over HTTPS

The publisher (`identity-agent-core/didwebs/publisher.go`, routed in `server/didwebs_handlers.go`) is the complement to the resolver in ADR-023: it serves an agent's **pairwise** AIDs as `did:webs` documents over whatever public host the relay assigned. For each pairwise AID it serves:

- `GET /{aid}/did.json` — a W3C DID document with an Ed25519 `verificationMethod`, `authentication`/`assertionMethod`, and a KERI-OOBI service entry (`BuildDidJSON`).
- `GET /{aid}/keri.cesr` — the KEL as a CESR/JSON stream, with witness-receipt headers (`X-Keri-Cesr-Witness-Receipts`, `X-Keri-Cesr-Complete` once receipts meet threshold).
- `GET /{aid}/oobi` — the OOBI endpoint.

Only pairwise AIDs are published — never the agent's root AID — keeping the root key off the public web while still letting any KERI-compliant resolver fetch and replay a per-relationship identity.

---

## Consequences

### Positive

- **The network is the agents.** Witnessing, watching, and relaying are performed by the same always-on Identity Agents that use them — no platform tier required for the core trust roles.
- **Duplicity caught without false positives.** A flaky or lying watcher or peer never blocks a legitimate identity: a standing watcher refuses a contact only by showing two events the controller signed at one place (ADR-075), and otherwise L2/L3 only escalate.
- **Reachability without lock-in.** The relay protocol is open and discovery-driven; relays and standing watchers are interchangeable providers, not dependencies.
- **Resolvable identities, protected root.** `did:webs` publishing makes pairwise AIDs resolvable over plain HTTPS while the root AID stays off the public web.

### Negative / Trade-offs

- A witness must be always-on; mobile agents are excluded, so users in the phone+computer topology rely on their computer (own or hosted) for witnessing.
- The relay tunnel is a persistent outbound WebSocket — it consumes a connection and depends on the relay's uptime for inbound reachability (mitigated by reconnect and the ability to switch relays).
- Some publisher paths defer full CESR-stream generation to the KERI driver; until that lands, the stream is served as JSON KEL events.
- L2/L3 cross-checking adds network calls on first contact; these are advisory and rate-limited, but they are extra latency on the cold path.

---

## Implementation notes

- Witness: `identity-agent-core/witness/` (`service.go`, `enrollment.go`, `pool.go`, `eligibility.go`, `types.go`).
- Watcher: `identity-agent-core/watcher/` (`service.go` = L1, `l2_client.go`, `l3_client.go`, `types.go`); the standing watcher the agent asks is `DefaultL2DigestURL` in `l2_client.go`.
- Relay client: `identity-agent-core/relay/` (`client.go`, `manager.go`, `protocol.go`) on `relayproto` (ADR-048), which removed the frame protocol and its schema; public URL `relay.grapeid.org`.
- did:webs publisher: `identity-agent-core/didwebs/publisher.go`, `urls.go`, served by `server/didwebs_handlers.go`. The resolver / verification side is ADR-023.

---

## Amendment, 2026-11-09: opting an identity out of the watcher

**What it means.** The owner can opt an identity out of what this agent's
watcher says about it. From then on every answer the watcher gives about that
identity, on its public routes and in the owner's own debug listing, is the
same as the answer for an identity it has never seen: `/public/kel-digest` returns
the same signed empty digest, `/public/kel-check` returns no match and no
digest, and the owner's debug listing returns no records. Status code, body
and the store queries behind the answer are the same in both cases.

**Who may set and read it.** Only the owner may set or clear it
(`PUT /api/watcher/opt-out`, on the owner-only list of ADR-050). The owner and
its paired controllers may read it (`GET /api/watcher/opt-out`).

**What keeps happening.** First-seen records are still written for an
opted-out identity. The opt-out hides what the watcher says; it does not stop
the watcher remembering, because a watcher that stopped recording could not
catch a later fork of that identity's key log.

**How it is enforced.** The watcher's reads of first-seen records and
duplicity alerts are unexported, and the only exported ways to read them are
`Service.Disclosable`, `DisclosableAll` and `DisclosableAlerts`, which apply the
opt-out. A test fails on any other exported method returning an observation,
and a second test walks every route a non-owner can reach and fails on one
nobody has classified. This keeps another package from skipping the check; it
does not stop code inside the watcher package from reading its own store, and
the owner's event stream still reports each verification's outcome.

**The one outside consequence.** Verification still uses what the watcher has
seen. A credential whose issuer's key log is a fork of one this agent has
already recorded is refused with the reason "L1 digest mismatch at same
sequence": `handleVerifyCredential` returns that reason, and
`verifyPresentedCredentialACDC` refuses the sign-in with its one fixed phrase
and logs it. So a caller
who holds a validly signed fork of an identity's key log, and presents a
credential from it, learns that this agent has seen that identity. It does not
learn whether the identity opted out, because the refusal is the same either
way. Refusing a forked issuer is the purpose of the watcher, so this is
accepted rather than closed.

---

## Amendment, 2026-11-11: what peers are asked and told, and who chooses them

**Why.** Asking a peer whether it holds a digest tells it whom this agent is
dealing with, and answering tells the asker whom this agent has met and when:
the digest of any identity's key log can be computed by whoever can fetch the
log. Layer L3 as first written asked every contact about every identity and
answered anybody with the digest and the time it was first seen.

**`/public/kel-digest` is for public watcher services.** It answers truthfully
(digest, `first_seen_at`, `observed_since`) only on an Identity Agent whose owner
has opted it in as a public watcher service (`public_watcher_service`, off by
default). Everywhere else it gives the signed "never seen" answer, which is a
valid digest statement, so published test vectors and existing clients still
verify it. The shared hosted watcher is such a service.

**`/public/kel-check` is for contacts.** The request is
`{aid, seq, digest, requester, at, signature}`; `our_digest` and
`our_first_seen_at` are no longer in the response, which is `{"match": bool}`.
The signature is over `KelCheckRequestStatement` with `to` set to the answering
agent's own public base URL, made with the key of the identifier the answering
agent's contact knows the asker by (the per-contact identifier, not the witness
key, so the signature tells the contact nothing it does not already know and
nothing it could show another party). It is answered only if `requester` is an
accepted contact of the answering agent, the signature verifies against the key
recorded for that contact, `|now - at| <= 60 s`, and the (requester, at, aid,
seq) has not been answered inside that window, and the identity is one whose log
the answering agent serves at its own address (the set `GET /public/oobi/{aid}`
answers), compared with its own copy of that log, so a contact cannot ask whether
the owner has met some third party. The
address a request must name comes from the answering agent's endpoint service or
relay allocation, never from the request's Host or forwarding headers; with
neither known nothing is answered. Every other request, an unsigned
one, one from a stranger, a stale or repeated one, and a question about an
identity not held, never seen or opted out, gets the same `{"match": false}`.
That closes the match/no-match oracle for identities whose key log a prober can
fetch. Every caller is limited (60 a minute) before any signature is checked,
and a requester that is not a contact costs the same signature check as one that
is. Strangers are then limited per caller (20 a minute) and together (600 a
minute); contacts are limited per contact and do not draw on the strangers'
budget. A relayed request is counted by the visitor address the relay passes on.

**Older clients.** A client that reads `OurDigest == nil` as "the peer holds
nothing" keeps working: the field is gone, so it is always nil, which reads as
unknown. A client that does not sign is answered no match, so its cross-checks
return unknown, never agreement.

**Who is asked, and when.** Peer checks are off until the owner turns them on
(`peer_watch_enabled`, off by default). Then only contacts the owner chose, at
most five, in `GET`/`PUT /api/watcher/peers` (`PUT` owner-only, `GET` open to the
owner's controllers, ADR-050), and only about an identity the contact plausibly
knows: it is where this agent met the identity's log, now or before, and it is
not the identity itself. A contact is asked only on a repeat contact whose record
this agent holds and agrees with, while the hosted watcher holds a different
digest. That disagreement always raises a non-blocking `kel_l3_escalation` event,
broadcast to the owner's connected apps, and the verification still passes. A contact's
answer is context: it is recorded in the sources queried and never quiets or
changes the escalation, because the contact able to answer about an identity is
its own controller, the party that showed this agent the branch in question.
Duplicity is therefore not a network property through contacts: a contact cannot
confirm or clear it. The escalation is not stored as a duplicity alert, since an
open alert blocks the next check of that identity and a disagreement that proves
nothing must not. A peer's "no match" never blocks, because it cannot tell a
different history from one it never saw. Installs that existed before this
amendment have chosen nobody, so contact cross-checks stay off until the owner
turns them on and chooses, through the route above. Registered watcher services are consulted for
their digest (L2) and are not asked for a cross-check.
