# ADR-048 — One relay protocol: a public or private address, admitted by signature

**Status:** Accepted
**Date:** 2026-10-21
**Supersedes:** ADR-008 (the Chisel tunnel provider); the transport and enrolment-token parts of ADR-024's relay client
**Amends:** ADR-042 §1 (ingress modes) and §5 (what a relay does)
**Relates to:** ADR-033 (An identifier travels with an address), ADR-036 (A computer you pair with does not publish who you are), ADR-037 (One KERI engine on every platform)

## Context

An Identity Agent behind NAT, or on a machine that must not listen, still has to be
reachable. Two mechanisms grew up for that, and both carry internet traffic to an
agent that only dials out:

- **A tunnel provider** (ADR-008): one stable public name per agent, carried by
  Chisel's SSH reverse ports. Chisel always lets an admitted client open outbound
  channels to anything the server can reach. Its login cannot be bound to an HTTP
  admission, and it admits everybody when it holds no logins. An operator can
  restrict none of that.
- **A URL relay** (ADR-024): one opaque address per relationship, carried by a
  frame format of its own. The frames drop query strings, flatten repeated headers,
  buffer whole responses and cannot carry a websocket. The enrolment token that
  opens the tunnel is a bearer token, so whoever holds it can replace the owner's
  session.

These are the same job done twice, once unsafely and once incompletely. What
differs is only what address an identity is given and what that address passes.

## Decision

**One protocol, one implementation, two modes.** The `relayproto` package in the
core is the protocol. A relay server imports it, and the Identity Agent imports it,
so the two ends cannot drift. The core's relay client moves onto this package, and
Chisel, the tunnel provider and the earlier frame protocol are then removed.

### 1. Public or private is the identity's choice

| Mode | What the identity gets | What the address passes |
|---|---|---|
| **public** | one stable address that anybody may find: a name at the relay, or the identity's own domain | every request. The Identity Agent's own gate decides, exactly as for any other ingress (ADR-042 §3). |
| **private** | one unlinkable address per relationship | identity artifacts and messages, and nothing else (§6) |

The protocol ties neither mode to any kind of identity. An identity may hold both,
from different relays. Which mode an instance uses is a setting (`resolveIngressMode`).
The per-entity default is supplied by whoever deploys the software. With nothing
supplied, the core is private for every identity, because privacy is the safe
default. (`defaultIngressModeForEntity` still picks the tunnel provider for an
organisation until the client moves onto this package.)

An operator runs public and private service as **separate deployments**, each with
its own domain, database and certificate. One abuse report or blocklisting of a
public address must not take every private address down with it. One operator's
records must not join an identity's public name to its relationships.

### 2. The transport: HTTP over one multiplexed session

1. The Identity Agent opens **one websocket** to the relay, over TLS 1.3, with the
   subprotocol `iarelay.v2`.
2. After admission (§3), the websocket carries a **yamux** session. **Only the
   relay opens streams.** The relay closes any stream the agent opens, so an
   admitted agent cannot reach anything through the relay.
3. Each inbound request gets **its own stream**. The stream starts with a
   **preamble** the relay writes: a two-byte big-endian length, then JSON
   `{"allocation", "mode", "host"}`, at most 1 KiB. Ordinary HTTP/1.1 follows.
4. The relay's proxy **never reuses a stream** (keep-alives disabled), and the
   Identity Agent **serves one request per stream** (its keep-alives disabled too).
   Reuse would let one allocation's request be read as another's.
5. The Identity Agent reads the preamble **before any HTTP bytes** and attaches it
   to the request's context (`relayproto.PreambleFrom`). The allocation is never an
   HTTP header, so nothing a caller sends can claim one.
6. The relay adds the standard forwarding headers. A relayed request therefore
   reaches the agent's gate as remote, and the owner-by-loopback test in ADR-042
   §3 cannot be met through a relay.

Because the stream carries real HTTP, everything else comes from HTTP itself:
websocket upgrades, streamed responses, query strings, repeated headers, request
cancellation and backpressure.

### 3. Admission: a signature bound to this connection and this relay

There is no password and no token.

1. The relay sends a **challenge**: protocol, the relay's own name, a 32-byte nonce
   and its time.
2. The Identity Agent answers with a **statement**
   `{purpose, protocol, service, nonce, exporter, aid, t}`. It is signed with
   Ed25519 over its canonical JSON (keys sorted) by the key the enrolment
   identifier's key event log names now. Alongside it travels that log as a CESR
   stream. The log may be omitted when the relay already holds it unchanged.
   - `exporter` is the TLS connection's **RFC 9266 channel binding**
     (`EXPORTER-Channel-Binding`, 32 bytes).
3. The relay checks:
   - that every field matches its challenge, its own name and this connection's
     exporter;
   - that the time is within two minutes of its own;
   - the log, with keri-go: structure, chaining, pre-rotation and every signature
     against the key state in force;
   - that the log establishes the named identifier with exactly one signing key;
   - the signature, against that key.
4. **Each part closes one way of reusing a statement.**
   - The nonce makes it useless for any other challenge.
   - The channel binding makes it useless on any other connection. That includes a
     relay in the middle opening its own connection onward, because the relay must
     terminate the TLS of the admission connection itself. A relay behind a
     TLS-terminating proxy cannot run this protocol.
   - The relay's name makes it useless at any other relay.
   - The time bounds how long it is worth anything at all.
5. **The log is bounded.** It may be at most 64 KiB and 256 events. A log the relay
   already holds for an identifier may **only be extended**. A presented log that
   does not begin with the held one is a rewritten history and is refused. Witness
   receipts are not required for an enrolment identifier: it is pairwise to one
   relay, and the relay is its only verifier.
6. Every admission is logged with the identifier, the key and the session, so each
   connection traces back to the identity that holds it.

### 4. A session is a lease

- **One admission lasts ten minutes.** One minute before it ends, the relay opens a
  control stream (preamble mode `renew`) and challenges again. The agent answers
  with a fresh statement under the same channel binding, carrying any new key
  events. A session that does not answer in time, or answers with a statement that
  does not verify, is closed when its lease ends.
- A renewal does not interrupt anything in flight. Long-polls and inner websockets
  carry on.
- **A rotation is seen at the next renewal at the latest.** A relay that learns
  sooner that a key has been rotated or an identifier revoked (from a watcher, say)
  closes the session at once (`Registry.Revoke`).
- **A reconnect replaces the session in one step.** The new session becomes the
  identifier's session first, and the old one is closed after, with all its
  streams. An old session that ends late never removes its replacement.

### 5. Limits

These are part of the protocol, and both ends enforce them.

| Limit | Value |
|---|---|
| Requests in flight per session | 256. The relay answers 503 beyond it. |
| Bytes in flight per stream, before the receiver reads | 256 KiB (the yamux stream window) |
| Websocket message carrying the session | 1 MiB |
| Requests per allocation per minute | 1,200 public, 120 private |
| Request body on a private allocation | 1 MiB |
| Key event log at admission | 64 KiB, 256 events |
| Admission or renewal exchange | 30 seconds |

**Large bodies wait to be accepted.** A body over 1 MiB, or of unknown length, is
offered with `Expect: 100-continue`. The Identity Agent's gate can then refuse the
request on its headers before any of the body crosses the relay.

**What ends an inner websocket.** A websocket opened inside a stream (an event
socket, say) lives as long as both ends keep it. It ends when either end closes it,
or when its session ends: lease not renewed, revoked, replaced or dropped. It is
never ended by a renewal.

### 6. What a private address may reach

The relay passes, on a private allocation:
- `GET` or `HEAD` of `/{aid}/did.json`, `/{aid}/kel`, `/{aid}/keri.cesr`,
  `/{aid}/oobi`, `/oobi/{aid}` and `/.well-known/did-configuration.json`;
- **`POST /didcomm`**, the identity's message endpoint. Without it, two Identity
  Agents behind NAT could resolve each other but never write to each other.

**The Identity Agent enforces the same, and more.** It learns the allocation from
the preamble, never from a header, and checks each request against what that
allocation was made for. The relay's check is defence in depth, because a relay is
assumed to be adversarial. Adding a message endpoint to this list is a change to
this ADR.

**Allocation labels are 128 random bits**, written as a 26-character lowercase
base32 DNS label. They are never derived from an identifier.

### 7. Public names and custom domains

A public allocation is either a name at the relay or the identity's own domain.
- **A name** belongs to the first proven key that claims it, and only that key
  releases it. A relay limits how many names one identity may hold, and keeps a
  reserved list of names nobody may claim.
- **A custom domain** is activated only after a DNS TXT record proves the domain is
  the identity's. Only then does the relay request a certificate for it. A custom
  domain keeps an identity's `did:webs` identifier independent of any one operator.
- The management surface stays on loopback in every mode (ADR-042 §2). A public
  address reaches it only by a controller's signature.

### 8. Finding an address that moved

When an Identity Agent's address changes (a new relay, a new name, a new domain),
it publishes a signed KERI endpoint record (`rpy` with route `/loc/scheme`) and
gives it to its witnesses and watchers. Hosts and apps re-resolve from there, never
from the address that just moved. An address is a property of the identifier's
current state, not a string handed out once (ADR-033).

### 9. What a relay can and cannot see

- **A relay never sees a key** and never signs anything. It serves only what the
  Identity Agent produces.
- **A live relay can link.** It sees which allocations arrive on one session, and
  from which source address. Not storing that link protects only a copy of the
  relay's data at rest. It does not protect against the operator while it runs.
  Relationships that must not be linkable by any one operator should be spread
  across operators. An identity may also register each private allocation under
  its own pairwise enrolment identifier and session; the protocol allows it, at the
  cost of a session per relationship.
- **A relay can refuse service,** like any network path. Moving to another relay
  and publishing the new address (§8) is the remedy.

## Consequences

- One implementation to secure instead of two, and a vendored dependency (Chisel)
  removed.
- Admission is cryptographic end to end. No credential is shared between agents,
  nothing is stored that could be replayed, and every session traces to an
  identifier's current key.
- Websockets, streaming and large bodies work through a relay, so a public address
  serves everything a directly reachable Identity Agent does.
- **The relay must terminate TLS itself.** This rules out running a relay behind a
  proxy that terminates TLS. That is a deployment constraint the channel binding
  imposes, and the reason the binding is worth having.
- Sessions live in the relay's memory on one machine. Running a relay on more than
  one machine needs inbound requests routed to the machine that holds the session.
- A relay that has not upgraded and still speaks the earlier frame protocol
  (`IARELAY10JSON`) is not compatible. The earlier frames, their schema, and the
  tunnel provider are removed from the core when its client moves onto this
  package.

## Contract

`identity-agent-core/contracts/relay/relay-admission.schema.json` pins the JSON
messages:
- the challenge;
- the admission and its statement;
- the relay's answer;
- the stream preamble.

The package's tests exercise each property above. Among them: a captured statement
failing on another connection, at another relay and after it goes stale; a log that
rewrites history being refused; a lease renewed in place; a session that cannot
renew being closed; and a caller unable to claim another allocation.
