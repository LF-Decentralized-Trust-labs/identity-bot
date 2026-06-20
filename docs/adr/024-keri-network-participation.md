# ADR-024: KERI Network Participation — Witness, Watcher, Relay, did:webs Publisher

**Status:** Accepted
**Date:** 2026-06-19
**Deciders:** Rob Andersen

---

## Context

KERI's security does not come from a blockchain or a central registry — it comes from a small set of network roles. **Witnesses** receipt an identity's key events so the controller can't later equivocate about its own history. **Watchers** observe identities they care about and detect *duplicity* (an identity presenting two conflicting versions of its KEL). And to be reachable at all, an always-on agent needs a stable public URL and a way to publish its KEL so others can resolve it.

A self-sovereign Identity Agent should participate in these roles itself rather than renting them from a platform. An always-on agent (a desktop left on, a hosted "black box") has exactly the uptime a witness needs. A watcher is just disciplined record-keeping plus cross-checking. And `did:webs` lets an agent publish its KEL over plain HTTPS. The open question each role raises is *scope and trust*: who do we witness for, whose duplicity do we check and how aggressively, and how do we get a public URL without becoming dependent on one provider.

---

## Decision

### Witness — every always-on agent witnesses for its trusted contacts

An always-on Identity Agent runs a witness service that receipts the key events of the contacts it has accepted. The service (`witness.Service`, `identity-agent-core/witness/service.go`) receives a contact's event (`ReceiveEvent`), stores a KEL replica, and returns a CESR receipt; it also broadcasts the user's own events to its enrolled witnesses and waits for finalization (`BroadcastEvent`). Enrollment is a two-step request/accept handshake (`SendWitnessRequest` / `ProcessInboundRequest` / `ApplyAcceptCallback`).

Witnessing is **scoped to trusted contacts only** (`IsContactWitnessEligible`, `identity-agent-core/witness/eligibility.go`): the contact must be `accepted` and of a durable type (general / trusted / professional / coworker); transactional contacts are excluded, and only always-on backends (desktop / hosted / commercial) are eligible — a mobile agent never advertises itself as a witness. The protocol caps the witness set (max 9, target 7, default threshold 5) and self-heals when a witness goes offline (heartbeat every 15 minutes; dropped after 4 consecutive failures). Pairwise AIDs may only use commercial witnesses, keeping per-RP identities off peers' witness pools.

### Watcher — three layers, L1 is authoritative for blocking

The watcher (`watcher.Service`, `identity-agent-core/watcher/`) detects duplicity across three escalating layers:

| Layer | Role | Source |
|---|---|---|
| **L1** | Self-watch: store the first-seen KEL digest per (AID, seq) locally | the agent's own store |
| **L2** | Since-inception / standing: query a shared commercial watcher for the consensus digest | `watcher.grapeid.org/public/kel-digest` |
| **L3** | Peer duplicity detection: cross-check the digest with peer agents | a peer's `/public/kel-check` |

L1 records first-seen digests (`RecordFirstSeen`) and compares incoming digests against them (`DetectDuplicity`). L2 (`L2Client.QueryDigest`) fetches a signed standing digest from a shared watcher. L3 (`L3Client.CrossCheck`) asks peers whether their first-seen digest matches.

The blocking rule is deliberately conservative: duplicity **blocks** only on (a) a repeat L1 mismatch — a different digest at a sequence we've already seen — or (b) a first-contact conflict between L1 and the L2 standing digest. L2/L3 mismatches alone never block; they only raise an escalation. Detected duplicity is recorded as a `DuplicityAlert` and anchored to the agent's own KEL (default-on) so the alert itself is tamper-evident. The verdict is a `VerifyKelResult` carrying the per-source outcomes and any alert.

### Relay client — the IA side of an open URL-relay protocol

An always-on agent behind NAT still needs a stable public URL to serve its `did:webs` artifacts and receive inbound requests. The relay client (`identity-agent-core/relay/`) is the **agent side of an open relay protocol** (version `IARELAY10JSON`): the agent connects *out* to a public relay (e.g. `relay.grapeid.org`), which assigns it a stable public hostname and tunnels inbound HTTPS back over a persistent WebSocket.

The flow is descriptor → enroll → allocate → serve:

1. `Client.FetchDescriptor` reads the relay's `/.well-known/url-relay-service.json` to discover its endpoints, path allowlist, and rate limits.
2. `Client.Enroll` registers the agent's AID/OOBI/public key and receives an enrollment token.
3. `Client.Allocate` (signed) requests a public URL with the intent to serve did:webs artifacts; it is idempotent (a 409 returns the existing allocation). `Client.Release` decommissions it.
4. `TunnelAgent.Run` (`relay/tunnel.go`) maintains the outbound WebSocket with exponential-backoff reconnect, receives request frames (`t:"req"`), dispatches them to the local HTTP server, and streams responses back as `res` / `res_chunk` frames (32 KB chunks, base64url bodies). The frame schema is pinned in `identity-agent-core/contracts/relay/relay-tunnel-frame.schema.json`.

Allocation requests are signed over a canonical (sorted-key, signature-field-stripped) body, so the relay can authenticate the agent but cannot impersonate it. Because the protocol is open and discovery-driven, the agent is not bound to any single relay operator — `relay.grapeid.org` is one provider, not a dependency.

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
- **Duplicity caught without false positives.** The L1-authoritative, conservative blocking rule means a flaky shared watcher or peer never blocks a legitimate identity; L2/L3 only escalate.
- **Reachability without lock-in.** The relay protocol is open and discovery-driven; `relay.grapeid.org` / `watcher.grapeid.org` are interchangeable providers, not dependencies.
- **Resolvable identities, protected root.** `did:webs` publishing makes pairwise AIDs resolvable over plain HTTPS while the root AID stays off the public web.

### Negative / Trade-offs

- A witness must be always-on; mobile agents are excluded, so users in the phone+computer topology rely on their computer (own or hosted) for witnessing.
- The relay tunnel is a persistent outbound WebSocket — it consumes a connection and depends on the relay's uptime for inbound reachability (mitigated by reconnect and the ability to switch relays).
- Some publisher paths defer full CESR-stream generation to the KERI driver; until that lands, the stream is served as JSON KEL events.
- L2/L3 cross-checking adds network calls on first contact; these are advisory and rate-limited, but they are extra latency on the cold path.

---

## Implementation notes

- Witness: `identity-agent-core/witness/` (`service.go`, `enrollment.go`, `pool.go`, `eligibility.go`, `types.go`).
- Watcher: `identity-agent-core/watcher/` (`service.go` = L1, `l2_client.go`, `l3_client.go`, `types.go`); public URLs `watcher.grapeid.org`.
- Relay client: `identity-agent-core/relay/` (`client.go`, `tunnel.go`, `protocol.go`); frame schema `contracts/relay/relay-tunnel-frame.schema.json`; public URL `relay.grapeid.org`.
- did:webs publisher: `identity-agent-core/didwebs/publisher.go`, `urls.go`, served by `server/didwebs_handlers.go`. The resolver / verification side is ADR-023.
