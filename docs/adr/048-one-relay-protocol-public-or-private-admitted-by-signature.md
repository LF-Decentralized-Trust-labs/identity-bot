# ADR-048 — One relay protocol: a public or private address, admitted by signature

**Status:** Accepted
**Date:** 2026-10-21
**Amended:** 2026-10-22: an address carries the protocol and never a page (§12)
**Supersedes:** ADR-008 (the Chisel tunnel provider); the transport and enrolment-token parts of ADR-024's relay client
**Amends:** ADR-042 §1 (ingress modes), §3 (how a relayed request is recognised) and §5 (what a relay does); ADR-007's tunnel-name rows
**Relates to:** ADR-033 (An identifier travels with an address), ADR-036 (A computer you pair with does not publish who you are), ADR-037 (One KERI engine on every platform)

## Context

An Identity Agent behind NAT, or on a machine that must not listen, still has to be
reachable. Two mechanisms grew up for that, and both carry internet traffic to an
Identity Agent that only dials out:

- **A tunnel provider** (ADR-008): one stable public name per Identity Agent,
  carried by Chisel's SSH reverse ports. Chisel always lets an admitted client open
  outbound channels to anything the server can reach. Its login cannot be bound to
  an HTTP admission, and it admits everybody when it holds no logins. An operator
  can restrict none of that.
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
so the two ends cannot drift. The core's relay client moves onto this package. The
Chisel tunnel provider and the earlier frame protocol are then removed.
Development tunnels (Cloudflare, ngrok) stay, labelled not private.

### 1. Public or private is the identity's choice

| Mode | What the identity gets | What the address passes |
|---|---|---|
| **public** | one stable address that anybody may find: a name at the relay, or the identity's own domain | every request but a browser loading a page. The Identity Agent's own gate decides, exactly as for any other ingress (ADR-042 §3). Answers pass only as protocol data (§12). |
| **private** | one unlinkable address per relationship | identity artifacts, messages and key registration, and nothing else (§6). Answers pass only as protocol data (§12). |

**The protocol ties neither mode to any kind of identity.** An identity may hold
both, from different relays. Which mode an instance uses is a setting
(`resolveIngressMode`): `relay` for private, `public` for public, each with its
own relay operator setting.

**Defaults.** The open-source core defaults every identity to private
(`defaultIngressModeForEntity`), because privacy is the safe default. A product
built on the core supplies its own per-entity default
(`CoreServer.DefaultIngressMode`). Any identity can choose either mode in its
settings.

**A public allocation MUST use its own enrolment identifier,** never one the
Identity Agent uses for a private allocation. Sharing one would let the relay join
the identity's public name to its relationships through the enrolment alone.

**An operator runs public and private service as separate deployments,** each with
its own domain, database and certificate.
- One abuse report or blocklisting of a public address must not take every private
  address down with it.
- One operator's records must not join an identity's public name to its
  relationships.

### 2. The transport: HTTP over one multiplexed session

1. The Identity Agent opens **one websocket** to the relay, over TLS 1.3, with the
   subprotocol `iarelay.v2`.
2. After admission (§3), the websocket carries a **yamux** session. **Only the
   relay opens streams.** The relay closes any stream the Identity Agent opens, so
   an admitted Identity Agent cannot reach anything through the relay.
3. Each inbound request gets **its own stream**. The stream starts with a
   **preamble** the relay writes: a two-byte big-endian length, then JSON
   `{"allocation", "mode", "host"}`, at most 1 KiB. Ordinary HTTP/1.1 follows.
4. The relay's proxy **never reuses a stream** (keep-alives disabled), and the
   Identity Agent **serves one request per stream** (its keep-alives disabled too).
   Reuse would let one allocation's request be read as another's.
5. The Identity Agent reads the preamble **before any HTTP bytes** and attaches it
   to the request's context (`relayproto.PreambleFrom`). The allocation is never an
   HTTP header, so nothing a caller sends can claim one.
6. **The Identity Agent marks every relayed request itself.** It sets
   `X-IA-Via-Ingress: relay` on each request it serves from a stream, overwriting
   anything a caller sent under that name. Its gate treats any request carrying
   that header as remote (ADR-042 §3), so the owner-by-loopback test cannot be met
   through a relay. This does not depend on what the relay adds. The relay also
   adds the standard forwarding headers, which the gate reads the same way.
7. **The relay forwards only to the host it recorded** for the allocation. A
   request with no recorded host is refused, never forwarded under the caller's
   `Host`.

Because the stream carries real HTTP, everything else comes from HTTP itself:
websocket upgrades, streamed responses, query strings, repeated headers, request
cancellation and backpressure.

### 3. Admission: a signature bound to this connection and this relay

There is no password and no token.

1. The relay sends a **challenge**: protocol, the relay's own name, a 32-byte nonce
   and its time.
   - The relay's name is the host name the Identity Agent dials. The Identity Agent
     refuses a challenge naming any other relay, so it never signs a statement for a
     relay it did not dial.
2. The Identity Agent answers with a **statement**
   `{purpose, protocol, service, nonce, exporter, aid, t}`.
   - It is signed with Ed25519 in the one signing form of ADR-049, by the key the
     enrolment identifier's key event log names now.
   - The log travels alongside it as a CESR stream. It may be omitted when the
     relay already holds it unchanged.
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
   - The channel binding makes it useless on any other connection, including one a
     relay in the middle opens onward (§10).
   - The relay's name makes it useless at any other relay.
   - The time bounds how long it is worth anything at all.
5. **The log is bounded and only ever moves forward.**
   - It may be at most 64 KiB and 256 events.
   - The relay keeps the log of every identifier it admits. It is told each one
     (`OnAdmit`, `OnRenew`) only once the session holding it is the identifier's
     own, and reads its record back (`Enrolled`). Its store must keep a log only
     if it extends the one stored, so two admissions racing cannot leave the older
     behind. A relay that keeps no such record admits nobody: it could not tell a
     current key from one rotated away.
   - A presented log must extend the **newest** log the relay has seen for the
     identifier, whether that is its stored record or the live session's.
   - "Extends" compares events as keri-go reads them, by sequence number, type and
     SAID, never bytes. The same event may travel later with more attachments (a
     witness receipt, say) or re-serialised, and that is not a new history.
   - The registry refuses a session whose log does not extend the one it would
     replace. So somebody holding a key rotated away since, and the log that named
     it, cannot displace the owner.
   - Witness receipts are not required for an enrolment identifier: it is pairwise
     to one relay, and the relay is its only verifier.
   - **Not verified: delegation.** keri-go checks a delegated inception's own
     signatures, but not that its delegator anchored it. An enrolment identifier is
     expected to be single-signature and not delegated.
6. **Every admission, renewal, refusal and session end is logged** with the
   identifier (quoted, since a refused one is unverified), the key and the session.
   A relay that supplies no logger gets the standard one. Each connection traces
   back to the identity that holds it.
7. **Nothing unbounded is read before admission.**
   - The relay reads at most 96 KiB from a connection it has not admitted, and from
     each renewal answer.
   - The Identity Agent reads at most 4 KiB from the relay during admission and
     during each renewal.

### 4. A session is a lease

- **One admission lasts ten minutes.** One minute before it ends, the relay opens a
  control stream (preamble mode `renew`) and challenges again. The Identity Agent
  answers with a fresh statement under the same channel binding, carrying any new
  key events.
- **A renewal is held to what admission was.** The Identity Agent answers only a
  renewal challenge in this protocol that names the relay it dialled.
- **A renewal that fails closes the session at once.** It fails if the answer is
  late, does not verify, or presents a log that does not extend the session's.
- **A renewal takes no request slot.** A session with every request slot busy can
  still renew.
- A renewal does not interrupt anything in flight. Long-polls and inner websockets
  carry on.
- **A rotation is seen at the next renewal at the latest.** A relay that learns
  sooner that a key has been rotated or an identifier revoked (from a watcher, say)
  closes the session at once (`Registry.Revoke`).
- **A reconnect replaces the session in one step.** The new session becomes the
  identifier's session first, and the old one is closed after, with all its
  streams. An old session that ends late never removes its replacement.

### 5. Limits

These numbers are part of the protocol. The table says which end enforces each.

| Limit | Value | Enforced by |
|---|---|---|
| Streams per session, counting inner websockets and half-closed streams | 256, plus the renewal's control stream. The relay answers 503 beyond it. | both |
| Requests in flight per allocation | 128 public, 16 private. 503 beyond it. | relay |
| Requests per allocation per minute | 1,200 public, 120 private. 429 beyond it. | relay (`Forward`) |
| Bytes in flight per stream, before the receiver reads | 256 KiB (the yamux stream window) | both |
| Websocket message carrying the session | 1 MiB | both |
| A stream on which nothing moves, either way | ends after 2 minutes | both |
| A stream closed at one end, waiting for the other | reset after 5 seconds | both |
| Request body on a private allocation | 1 MiB | relay |
| Key event log at admission | 64 KiB, 256 events | relay |
| Read before admission, and per renewal answer | 96 KiB | relay |
| Read from the relay during admission and renewal | 4 KiB | Identity Agent |
| Admission or renewal exchange | 30 seconds | both |
| Sessions per relay | 10,000 unless the relay sets its own, plus an optional budget hook. Counted atomically as a session is put in place. An identifier that already holds a session may always replace it, so a full relay never locks an owner out of reconnecting. | relay |

**Large bodies.** A body over 1 MiB, or of unknown length, is offered with
`Expect: 100-continue`. That lets the Identity Agent's gate refuse a request on its
headers before any of the body crosses the relay. It is a courtesy, not a gate: a
client may send its body regardless, and the limits above are what bound it.

**What ends an inner websocket.** A websocket opened inside a stream (an event
socket, say) lives as long as both ends keep it.
- It ends when either end closes it, after two minutes with nothing sent either
  way, or when its session ends: lease not renewed, revoked, replaced or dropped.
- It is never ended by a renewal.
- An inner websocket that may sit quiet must ping more often than every two
  minutes. The core's event socket pings every 30 seconds.

### 6. What a private address may reach

The relay passes, on a private allocation, at exactly these paths:
- `GET` or `HEAD` of `/{aid}/did.json`, `/public/{aid}/did.json`, `/{aid}/kel`,
  `/{aid}/keri.cesr`, `/{aid}/oobi`, `/oobi/{aid}` and `/public/oobi/{aid}`;
- **`POST /didcomm`**, the identity's message endpoint. Without it, two Identity
  Agents behind NAT could resolve each other but never write to each other.
- **`POST /_register` and `POST /public/_register`**, where a counterparty's
  pairwise signer registers the key it will be resolved by.

A private address refuses:
- any other path or method;
- a trailing slash or any other spelling of these paths, including percent-encoding;
- a protocol upgrade.

**The Identity Agent applies its own rule as well.**
- It learns the allocation from the preamble, never from a header.
- It **looks up that allocation's mode in its own records.** It never trusts the
  preamble's `mode`, which is only what the relay claims.
- It checks each request against what that allocation was made for.

The relay's check is defence in depth, because a relay is assumed to be
adversarial.

**Deviation: the list is written out, not derived.** The design was to derive it
from the core's list of public routes (`publicRoutes`). It is not, because
`relayproto` is imported by relay servers and must not import the core's server.
The list above is the subset of those public routes a relationship needs. It has
one copy, `relayproto.PrivateRoutes`: the relay matches it against a request's
path, and the Identity Agent against the route pattern its router matched, and a
core test holds every entry to be a public route. Adding a route here is a change
to this ADR.

**Amended 2026-10-22: `/public/oobi/{aid}` is on the list.** Counterparties
resolve an identity at that path (it is the OOBI form this core hands out), and
the Identity Agent's own rule already passed it, so a relay that refused it broke
resolution at a private address for no gain.

**Deviation: the witness and receipt endpoints are not passed.** These are
`/api/witness/*` and `/api/receipt/submit`. Witnessing is a relationship between an
identity and its witnesses, run at the identity's public or witness address. It is
not run at a per-relationship address handed to a counterparty.

**Allocation labels are 128 random bits**, written as a 26-character lowercase
base32 DNS label. They are never derived from an identifier.

### 7. Public names and custom domains

A public address is a name at the relay, or the identity's own domain.
- **A name** belongs to the first proven key that claims it, and only that key
  releases it. A relay limits how many names one identity may hold, and keeps a
  reserved list of names nobody may claim (its own paths, and names such as
  `login`, `support`, `admin`, `www` and `api`). A released name is held back
  from anybody else for a time, so it cannot be picked up at once to
  impersonate whoever gave it up.
- **A custom domain** is activated only after a DNS TXT record proves the domain
  is the identity's: `TXT _iarelay.<domain>` carrying `iarelay-aid=<identifier>`.
  Only then does the relay request a certificate for it. A custom domain keeps an
  identity's `did:webs` identifier independent of any one operator.
- The management surface stays on loopback in every mode (ADR-042 §2). A public
  address reaches it only by a controller's signature.

### 8. Discovery, addresses and control requests

**Discovery.** A relay publishes `GET /.well-known/url-relay-service.json`:
`protocol` (this protocol's version), `service` (the name its challenges and
control requests carry), `mode`, `connect_host`, `tunnel_endpoint` (the `wss://`
session endpoint), and `endpoints`, which maps each control `op` below to the
URL it is sent to.

**Two front doors.** A relay has a **connect host**, where Identity Agents are
admitted and send control requests, and **caller-facing** addresses, where
everybody else reaches them. They may be different hosts.
- The session and every control request go to the connect host, and nowhere
  else. `tunnel_endpoint` and every entry in `endpoints` are at it.
- The connect host is the relay's own host or a name under it (for example
  `connect.<relay>`). The descriptor may reach the Identity Agent through
  whatever sits in front of callers, so an Identity Agent refuses a descriptor
  naming a connect host outside the relay's name, or an endpoint away from the
  connect host: anything in front of callers that rewrote it would otherwise
  have the Identity Agent admitted, and its addresses served, by somebody else.
- The Identity Agent's dialled-host check (§3) applies to the connect host.
- Everything the Identity Agent publishes uses the caller-facing URLs the relay
  returns (`public_url`), never the connect host.

**Enrolment is the first admission.** The key event log travels with it
(§3). There is no separate enrol call and no enrolment token.

**Where an address is, and what reaches the Identity Agent:**

| Address | Form | What the Identity Agent receives |
|---|---|---|
| private | a path at the private relay: `https://<private-relay>/<label>/...` | the request with `/<label>` removed from its path, and `X-Forwarded-Prefix: /<label>`. Links it writes must carry that path. |
| public name | a host under the public relay: `https://<name>.<public-relay>/...` | the request unchanged |
| custom domain | `https://<domain>/...` | the request unchanged |

The stream's preamble names the label, name or domain. The Identity Agent
takes what an address is, and the URL it writes about itself there, from its
own record of the addresses it holds (§6), never from a header a caller could
send.

**Control requests.** Everything an Identity Agent asks of a relay is signed in
the one signing form of ADR-049, by the key its enrolment identifier's log names
now. Every request carries:

| Field | |
|---|---|
| `op` | which request it is, so a signature for one cannot be used as another |
| `relay` | the relay's `service` name, so it cannot be used at another relay |
| `signed_by` | the enrolment identifier |
| `t` | RFC 3339, within two minutes of the relay's clock |
| `nonce` | 16 to 64 characters, never accepted twice |
| `signature` | Ed25519, base64url without padding, over the request's other fields in the form of ADR-049 (`relayproto.CanonicalBody`) |

The relay accepts a control request only while `signed_by` holds a live
session, and checks it against the key that session's log names now.

**Private addresses:**

| `op` | Fields | Does |
|---|---|---|
| `allocate` | `commitment`: base64url SHA-256 of a secret of 32 or more random bytes the Identity Agent keeps | makes an address: `allocation` (a 128-bit random label) and `public_url` |
| `bind` | `allocation`, `secret` | attaches an address to the caller's session |
| `release` | `allocation`, `secret` | ends an address |

The relay stores each label and the commitment to its secret, **never which
identifier made it**. Which session serves which label it keeps in memory only.
So after every admission the Identity Agent sends `bind` for each private
address it holds; the secret proves the address is its own. An Identity Agent
whose `bind` is refused (the relay no longer has the address, or the secret is
not the one it was made with) no longer holds that address, and makes a new
one.

**Public addresses:**

| `op` | Fields | Does |
|---|---|---|
| `claim-name` | `name`: 3 to 32 lowercase letters, digits and single inner hyphens | the first proven key to claim a name holds it; claiming a name one already holds is harmless |
| `release-name` | `name` | only its holder may release it |
| `request-domain` | `domain` | returns `txt_name` and `txt_value`, the record that proves the domain |
| `verify-domain` | `domain` | checks the record; only then is the domain served and a certificate requested |
| `release-domain` | `domain` | only its holder may release it |

A public relay gives an address only at a name or a proven domain.

**What this replaces from ADR-024:** the enrolment call and its token, the
allocate and release bodies signed by token-bearing enrolments, and the frame
protocol (`IARELAY10JSON`) and its schema. The discovery descriptor survives,
reshaped as above.

### 9. Finding an address that moved

When an Identity Agent's address changes (a new relay, a new name, a new domain),
it publishes a signed KERI endpoint record (`rpy` with route `/loc/scheme`) and
gives it to its witnesses and watchers. Hosts and apps re-resolve from there, never
from the address that just moved. An address is a property of the identifier's
current state, not a string handed out once (ADR-033).

### 10. Proxies between the two ends

The admission is bound to the TLS connection between the relay and the Identity
Agent, so that connection must run end to end between them. That binds only the
connect host (§8). Callers' traffic is ordinary HTTPS, so a relay may put a
proxy that terminates TLS (a CDN, say) in front of its caller-facing addresses.

| Proxy | Works? |
|---|---|
| A TLS-terminating proxy in front of the caller-facing addresses | yes |
| A TCP or SNI pass-through in front of the connect host (a load balancer that forwards TLS unopened) | yes |
| A TLS-terminating proxy in front of the connect host | no. The relay sees a different TLS connection from the Identity Agent's, and cannot admit anybody. A relay must never put one there. |
| A TLS-inspecting proxy on the Identity Agent's network | no. It cannot be admitted, for the same reason. |
| A plain HTTP CONNECT proxy on the Identity Agent's side (`HTTPS_PROXY`, honoured through `ProxyFromEnvironment`) | yes. It tunnels the TLS connection unopened. |

A proxy in front of callers sees what callers send. A private address passes
only what §6 allows, and what crosses it is what any counterparty may fetch or
send, so this is the same exposure as any public web host.

### 11. What a relay can and cannot see

- **A relay never sees a key** and never signs anything. It serves only what the
  Identity Agent produces.
- **A live relay can link.** It sees which allocations arrive on one session, and
  from which source address. Not storing that link protects only a copy of the
  relay's data at rest. It does not protect against the operator while it runs.
  - Relationships that must not be linkable by any one operator should be spread
    across operators.
  - An identity may also register each private allocation under its own pairwise
    enrolment identifier and session. The protocol allows it, at the cost of a
    session per relationship.
- **A relay can refuse service,** like any network path. Moving to another relay
  and publishing the new address (§9) is the remedy.

### 12. An address carries the protocol, never a page

*Amendment, 2026-10-22.*

Anybody may hold a public address, and the software is open, so anybody can run
an Identity Agent changed to answer with whatever it likes. Before this
amendment a public address passed every answer, so such an agent could put a
web page at an address a relay operator is answerable for: a fake sign-in form
is enough. The usual remedy is an operator who reads reports, judges content
and takes addresses down. This protocol does not do that, and no operator of it
should have to decide whether something said through it is true or harmful.

Instead, the relay checks what kind of thing an answer is, never what it says,
and the same way for every identity:
- **A browser loading a page never reaches the Identity Agent.** A request that
  says it is loading a document or a frame (`Sec-Fetch-Dest`, `Sec-Fetch-Mode`,
  or, from a browser too old to send those, an `Accept` naming both `text/html`
  and `application/xhtml+xml`, as every such browser does when loading a page
  and other clients do not) is answered by
  the relay itself, at either kind of address, with one short page that is the
  same at every address: what the address is, and where to get an Identity
  Agent. The operator chooses that link; the default is this project. The page
  carries nothing the Identity Agent sent.
- **An answer passes only as protocol data:** a body with exactly one
  `Content-Type`, which is `application/json` or any `application/...+json`,
  `application/cesr`, `application/octet-stream` or `text/plain`, or no body at
  all. A page, a script, an image, a document, a redirect, a body with no type,
  or an answer naming two types (browsers differ in which they believe) is
  refused, and the caller gets the relay's own error. No informational (1xx)
  answer passes but a protocol switch, since it would reach the caller before
  the final answer is checked. A websocket may open only at a public address, where an
  identity's own front ends keep one; a browser cannot load a page from one.
- **Only the protocol's headers pass.** Of an Identity Agent's answer the relay
  keeps `Content-Type`, `Content-Length`, `Content-Encoding`, `ETag`,
  `Last-Modified`, `Date`, `Vary`, `Retry-After`, the `X-Keri-` key-state
  headers, and the cross-origin headers a relying party's page needs to call a
  public identity's sign-in routes (`Access-Control-Allow-Origin`, `-Methods`,
  `-Headers`, `-Expose-Headers`, `-Max-Age`; never `-Allow-Credentials`). Every
  other header is dropped, so anything a browser could act on (a redirect, a
  preload, a sign-in prompt, a cache lifetime, a download name) is absent by
  construction rather than by a list of what to remove. A cookie passes only at a
  public address and only if it is that address's own; at a private address,
  where every address shares one origin, none passes. A protocol switch keeps
  only `Upgrade`, `Connection` and the `Sec-WebSocket-` headers.
- **Every answer is sealed for browsers and kept from caches.** The relay sets
  `X-Content-Type-Options: nosniff`,
  `Content-Security-Policy: default-src 'none'; sandbox; frame-ancestors 'none'`,
  `X-Frame-Options: DENY` and `Cache-Control: private, no-store`. One URL
  answers a browser with the visitor page and an Identity Agent with data, and a
  cache in front of the relay may ignore `Vary` (content delivery networks
  commonly do), so neither the visitor page nor any answer may be kept; every
  answer also varies on `Sec-Fetch-Mode`, `Sec-Fetch-Dest` and `Accept`.

A public address still passes every request, not a list of routes: the
identity's own front ends (a machine acting for its owner, ADR-042) reach it
there, and what bounds a dishonest Identity Agent is what it may answer, not
what it may be asked. The Identity Agent applies the same rule to itself, so a
relay that applies none still carries no page from it: every answer it gives a
relayed request passes through `CheckProtocolResponse` before any of it is
sent, a page load is refused, and it does not serve its web app there.

What this does not do: it cannot make what an Identity Agent says true. Someone
can still send false data through an address, as they can in any message. That
is a question of whether to trust an identity, which is for the people dealing
with it, not for the relay.

`relayproto` holds the rule (`IsBrowserNavigation`, `CheckProtocolResponse`,
`ServeVisitorPage`) and applies it in `Session.Forward`, so every relay built on
it enforces it; the core client applies the same functions in its own handler
for relayed requests.

## What is built, and what is not

**Built, in `relayproto`, with tests for each property:**
- the transport;
- admission and renewal;
- the forward-only key log;
- the registry;
- the limits in §5;
- the relay's private-address rule;
- the relay marker;
- allocation labels.

`relayproto` is its own Go module, `github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto`, with no dependency on the rest of the core. A relay server anywhere can `go get` it, and the core will consume it from the same path.

**Built in the core:** the private default and the product's default seam
(`DefaultIngressMode`). The core bundles no relay operator; a product names its
relays through `RELAY_BASE_URL` and `PUBLIC_RELAY_BASE_URL`, which a desktop app
sets with `BackendProcessService.environmentDefaults` and a phone app with
`mobilecore.DeclareRelays` before start. The environment, and a relay chosen in
settings, still win.

**An instance set to public with no name to be reached at** (no public name and
no address already held) is shown a notice at start-up asking the owner to
choose one, and the relay status gives the same reason, until they next save
reachability.

**An instance that used the retired Chisel provider** is moved at start-up to a
public relay address under the name it held, and the owner is shown a notice
saying so until they next save reachability.

**Built in the core client (`relay/`):** the session through `relayproto`, the
control requests above, private addresses held by their secrets and bound again
after every admission, public names, reconnection with backoff, and the
Identity Agent's per-allocation rule (§6): an address is looked up in its own
records, never trusted from the preamble, and a private one reaches only
`relayproto.PrivateRoutes`. Each mode has its own enrolment identifier and its
own record. The earlier frame protocol and the Chisel tunnel provider are
removed.

**Not built yet:**
- **Republishing the endpoint record** when the address moves (§9). The core
  recomputes its published address; it does not yet send a signed `/loc/scheme`
  record to its witnesses and watchers.
- **A reachability screen in this repository's app.** The core serves owner
  routes for the relay's status, saving and applying reachability, releasing the
  public name, and requesting and verifying a custom domain; the app here has no
  screen for them yet, and offers only development tunnels.
- **One private address per relationship.** The core holds one private address
  and gives it to every counterparty. The protocol allows one per relationship,
  and the client can allocate them; handing a fresh one to each new
  relationship is not wired in.

## Consequences

- One implementation to secure instead of two, and a vendored dependency (Chisel)
  removed.
- Admission is cryptographic end to end. No credential is shared between Identity
  Agents, nothing is stored that could be replayed, and every session traces to an
  identifier's current key.
- Websockets (at a public address), streaming and large bodies work through a
  relay, so a public address serves everything a directly reachable Identity
  Agent does except pages (§12).
- **An Identity Agent's web app is not reachable through a relay** (§12). An
  owner reaches it on the machine, or drives the identity from an app acting for
  it.
- **Nothing that needs a browser to load a page works at a relay address**
  (§12). A sign-in flow that sends a person's browser to the Identity Agent and
  redirects it back (an OpenID Connect authorisation page, say) cannot run there,
  and an identity's own custom domain served through a relay shows the visitor
  page to browsers too. Such a flow needs an address that is not a relay's.
- **A cache in front of a relay keeps nothing** (§12), including artifacts that
  would be safe to cache. That is the price of one URL answering both a browser
  and an Identity Agent.
- **The relay must terminate TLS itself at its connect host** (§8, §10). That is
  a deployment constraint the channel binding imposes, and the reason the
  binding is worth having. Caller-facing addresses may sit behind any proxy.
- **Sessions live in the relay's memory on one machine.** Running a relay on more
  than one machine needs inbound requests routed to the machine that holds the
  session.
- **A relay that still speaks the earlier frame protocol (`IARELAY10JSON`) is not
  compatible.**

## Contract

`identity-agent-core/contracts/relay/relay-admission.schema.json` pins the JSON
messages:
- the challenge;
- the admission and its statement;
- the relay's answer;
- the stream preamble.

The package's tests exercise each property above. Among them:
- a captured statement failing on another connection, at another relay and after
  it goes stale;
- a key rotated away failing to displace the owner;
- a log that rewrites history being refused;
- a lease renewed in place, even with every request slot busy;
- a session that cannot renew being closed;
- a caller unable to claim another allocation or redirect a request's host;
- one address unable to starve the others.
