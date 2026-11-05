# ADR-042 — How an agent is reached, and who may manage it

**Status:** Accepted; §1, §3 and §5 amended by ADR-048 (2026-10-21): URL Relay carries both private and public addresses under one relay protocol; the Chisel tunnel provider goes, while development tunnels (Cloudflare, ngrok) stay; the core defaults every identity to URL Relay and a product sets its own per-entity default; the Identity Agent itself marks every relayed request; §3 amended 2026-10-22: a request from this computer is the owner's only with the secret the core was started with; §3 amended 2026-11-02: the signature is checked, and spent, before the body is read; §3 amended 2026-11-05: a controller's request may name the origin it is sent to (ADR-062)
**Date:** 2026-09-16
**Relates to:** ADR-006 (Standardized Topology), ADR-033 (An identifier travels with an address), ADR-036 (A computer you pair with does not publish who you are), ADR-041 (One neutral scheme for the protocol's device codes)

## Context

Every Identity Agent has to be reachable at some network address, or it is an
agent nobody can use: the OOBI it hands out, the DID document a verifier resolves,
the credential-presentation endpoint a counterparty POSTs to — all point at a URL,
and if that URL answers nowhere, nothing can pair with the agent. But "be
reachable" is not one thing. An agent may sit on a laptop behind NAT, on rented
always-on hardware the owner never physically touches, or on a machine with its
own public DNS name. It may want one discoverable public address (an organisation
is public by nature) or a different opaque address per relationship (an individual
who does not want two counterparties to correlate them by hostname). And whatever
address it hands out, it has to be able to publish where it currently answers,
because that address is expected to change — the portability of an identity is in
the protocol, not in any single string it handed out once (ADR-033).

Two things were tangled together and needed separating. **How** an agent becomes
reachable from outside (the ingress), and **who** is allowed to manage the agent
once a request arrives (the owner gate). Left unseparated, the failure modes are
severe and have both been seen in this codebase: a management surface bound to a
public address becomes a universal correlator ("learn the one URL, ask the agent
anything"); and an owner-trust test based on "the request arrived on loopback"
treats every website the user visits, and every counterparty who learned a
forwarded URL, as the owner.

This ADR records the reachability model **as shipped**. Where the shipped code
does less than the fuller design intends, that is called out explicitly under
"What is shipped, and what is still partial".

## Decision

### 1. One URL manager, three ingress modes

There is exactly one control point that decides how an agent is reachable, and one
default ingress mode per instance. Everything that wires up reachability consults
a single resolver (`resolveIngressMode` in `server/reachability_mode.go`); there is
no second place that opens a public port or turns reachability on. The three modes
are:

- **URL Relay** — a relay operator allocates a URL bound to a signed enrollment and
  carries inbound traffic to the agent over the agent's own outbound tunnel. The
  agent opens no public port; per-relationship opaque URLs give privacy by default
  (one counterparty cannot correlate its URL with another's). Implemented by the
  `relay/` package and wired in `server/relay_wiring.go`.
- **Direct** — the agent answers at its own reachable address (loopback/LAN, a
  port-forward, or its own DNS), with no third party in the path. A
  developer/testing posture, never a shipped product default.
- **Tunnel** — a tunnel provider gives ONE public URL for the whole agent, with no
  per-relationship allocation. Structurally it cannot compartmentalise per
  relationship, so it is honestly not-private; it is a fit for an entity that is
  public by nature and wants a single discoverable address. Implemented by the
  `tunnel/` package (providers include Cloudflare, ngrok, and a Chisel-based tunnel
  such as one fronted at `grapeid.org`).

The default is per instance and is only a *default*. The neutral core defaults
every identity to URL Relay, for privacy by default (`defaultIngressModeForEntity`,
amended by ADR-048: public or private is an identity's choice, not a property of
its entity type). A product built on the core supplies its own per-entity default
through `CoreServer.DefaultIngressMode`, so a product may, for example, default an
organisation to a public address. Direct is never a default, and a product default
of Direct is ignored. A deployment, or the identity itself, overrides the default
with a persisted setting.

Because reachability is a *manager* decision and not a global switch, the manager
may allocate other-mode URLs on the same agent — for example an organisation on a
Tunnel default allocating an opaque relay URL for a confidential counterparty.
Whether a public tunnel is opened at all is gated by the resolved mode
(`loadTunnelConfig` in `server/server.go` returns `ProviderNone` in Relay or Direct
mode), which retired the earlier defect where an agent was published on a public
tunnel merely because no provider had been configured.

### 2. Two listeners, and the root-loopback invariant

An agent runs conceptually two surfaces, and only one of them is ever externally
reachable.

- The **root / management surface** carries the agent's outbound tunnel/relay setup
  and its authenticated owner/management API. It binds **loopback by default**
  (`rootListenAddr` in `server/listen_addr.go` returns `127.0.0.1:<port>`); a
  confidential-VM instance behind a host proxy is the one exception — see the
  sealed-instance deviation note at the end of this section.
  It is never the surface a counterparty reaches. Binding it to a public address
  would make the root URL a universal correlator, which is exactly what the
  per-relationship-URL model exists to prevent.
- The only externally reachable surface is a **manager-governed ingress**. External
  reach arrives in one of two shapes, and in both the management surface stays on
  loopback:
  1. **The agent's own dialled-out relay or tunnel.** The agent opens an outbound
     connection to the operator and the operator reverse-proxies inbound requests
     back down it to the agent (through `relayproto`, ADR-048, each inbound
     request on a stream of its own). Nothing external binds on the agent host.
  2. **A reverse proxy on the host that dials the agent's loopback port** — the
     sealed-instance model. The agent is not directly reachable at all; a reverse
     proxy (for example Caddy) terminates TLS and forwards to the agent's loopback
     port, publishing many instances on one shared hostname each at its own opaque
     path prefix so no per-instance name appears in TLS SNI or certificate logs.
     The proxy is the only party that knows the scheme, host and path prefix the
     person actually used, so it tells the agent via forwarding headers
     (`X-Forwarded-Host`/`-Proto`/`-Prefix`), and the agent — only when the
     deployment has opted in with `TRUST_FORWARDED_HEADERS=1` — records that as its
     published address (`observedPublicBase` → `EndpointService.SetObservedURL`).

**Direct mode is reached on a second listener (amended 2026-11-05).** An agent in
Direct mode with no relay or tunnel is reached off-box on a listener of its own,
bound by `AGENT_DIRECT_LISTEN_ADDR=host:port` (`bindDirectListener` in
`server/direct_ingress.go`); the root surface does not move. That listener serves
only the `GET /{aid}/oobi`, `/{aid}/did.json`, `/{aid}/kel` and `/{aid}/keri.cesr`
routes (`directIngressRoutes`), each already a public route by design in
`publicRoutes`, and nothing else: a router with no other route, so the management
API, the sealed carrier, DIDComm and the OIDC routes answer a bare 404. It answers
for an identifier only when the URL manager has allowlisted that identifier
(`/api/settings/reachability/direct-aids`, owner-only, kept in the data directory),
and only while the resolved ingress mode is Direct; an identifier off the list gets
the same 404 as one the agent has never heard of. The whole-surface hatch
`AGENT_DIRECT_INGRESS_ADDR` is removed, and an agent started with it set refuses to start rather than quietly fall back to loopback; the address a Direct
agent advertises is the direct listener's host and port.

**Deviation — the sealed-instance model on a confidential-VM substrate (2026-10-18).**
Point 2 above describes the sealed instance as a reverse proxy that "dials the
agent's loopback port," and the invariant says the root surface binds loopback. That
holds when the proxy and the agent share a loopback — a proxy process beside the
agent, or a container in its network namespace. It does NOT hold when the agent runs
inside a confidential VM: the host reverse proxy reaches the guest over the VM's
network interface, and the guest's loopback is unreachable from the host across the
VM boundary. An agent that bound only loopback there is unreachable by the proxy and
by the provisioner — which is how this was found: a freshly built image booted, ran,
and could not be provisioned.

So on that substrate the invariant holds in SUBSTANCE, not literally. The root
surface binds the VM's network interface (`AGENT_SEALED_INSTANCE_INGRESS=1`, honoured
by `rootListenAddr`, set only in the measured image). This is neither a universal
correlator nor the dev escape hatch, because: the interface is reachable only from
the host (the VM's user-mode NAT isolates it); the NAT presents every host-originated
request from a non-loopback source, so the §3 management gate classifies it as
remote-and-signed and there is no local caller inside the guest to impersonate (the
agent is the only thing the VM runs); and reaching the management surface through the
host proxy by owner/controller signature is the whole point of a sealed instance —
hiding it would break remote owner management. The signal rides the measured image,
so an owner verifies the posture in the launch measurement. LAN exposure was once a separate dev hatch (`AGENT_DIRECT_INGRESS_ADDR`), because there IS a local caller to protect there. *(Amended 2026-11-05: that hatch is gone; LAN reach is the second listener above.)*

### 3. Who is the owner — the management gate

Ingress answers "can a request reach the agent." A separate gate answers "is this
request the owner." A request is trusted as the genuinely-local owner **only** if
it is a loopback caller, with **no forwarding header**, and **not browser-
originated** (`isLocalOwnerRequest` in `server/mcp_tokens.go`). Anything arriving
through an ingress is remote and must present an owner or controller signature —
the sealed-envelope path or an owner-key signature (`isOwner` in
`server/api_auth.go`); a remote caller otherwise gets only the capability scopes a
positive credential (an MCP access token or a verified capability-grant ACDC)
grants it. A signature made with the owner key, like a controller's or an AI
agent body's, names the Identity Agent it is for (`X-IA-Owner-For`, inside the
signed string), and every other Identity Agent refuses it; one with no identity
yet accepts only a signature naming nobody. An owner proved remotely, by signature or sealed envelope, reaches a
route open to scoped callers as the owner: the scope check, which bounds what
somebody other than the owner may do, does not apply to them, and everything
else that holds for a remote caller does, so a capability that drives this
computer's screen stays local-only.

Three properties make this sound:

- **Connection origin is never identity.** A tunnel daemon or a reverse proxy
  connects to the agent from loopback, so a loopback `RemoteAddr` alone cannot mean
  the owner. The presence of any forwarding header — the standard proxy/tunnel
  headers (`X-Forwarded-For`, `X-Real-Ip`, `Cf-Connecting-Ip`, `True-Client-Ip`,
  `Forwarded`) plus the relay's own marker — flips the request to remote
  (`hasForwardingHeaders`).
- *Amended by ADR-048 (2026-10-21):* under the one relay protocol a relayed
  request never reaches the agent over loopback at all. The Identity Agent serves
  it from a relay stream, and sets `X-IA-Via-Ingress: relay` on every such request
  itself, overwriting anything a caller sent. That the request is remote no longer
  depends on the relay. The paragraph below describes the earlier frame protocol,
  which ADR-048 removed.
- **The relay stamps its own marker.** A relay-forwarded request also reaches the
  agent over loopback, so the earlier frame client set `X-IA-Via-Ingress: relay` on
  the box, after the client's headers are applied, where a client can neither remove
  nor preempt it. Without this, anyone who learned the relay URL would be treated as the
  local owner with no signature required. Request bodies are carried through the
  forward (base64 in the inbound frame, decoded to a real body), so a signed POST — a
  controller grant, a rotation, any owner action — arrives with the bytes it was
  signed over and verifies; forwarding with an empty body previously meant only GETs
  worked over the relay.
- **A browser cannot talk itself out of being a browser.** A web page loaded from
  anywhere reaches loopback as an ordinary connection with no forwarding header, so
  the loopback-only test alone made every website the user's owner.
  `isBrowserOriginated` rejects any request carrying `Origin` or the `Sec-Fetch-*`
  family — forbidden header names a page's script cannot set or remove — which a
  native client on the machine never sends.
- *Amended 2026-10-22:* **being on this computer is not enough.** Every program on
  a desktop, and every app on a phone, reaches loopback the same way, so a local
  request is the owner's only when it also carries the secret the core was started
  with (`X-Local-Owner-Secret`). The app that starts the core chooses it and hands it
  over (`IDENTITY_AGENT_LOCAL_OWNER_SECRET` on a desktop,
  `mobilecore.DeclareLocalOwnerSecret` on a phone); a core started by hand mints one.
  Either way it is written to `local-owner-secret` in the data directory, readable by
  that user alone, for local tools. The connection test above still decides whether
  a request is local (`isLocalConnection`); only the owner test adds the secret, so a
  signed program on the machine keeps its local standing and an unsigned one without
  the secret is treated as remote. Sealed and signed owner requests are unchanged.
- *Amended 2026-11-02:* **the signature is checked before the body is read.** An
  owner's (or a controller's) signature covers a digest of the body, so the agent
  used to read the body to learn what the signature covered, and a caller holding
  no key could make it read up to a route's bound (512 MiB on the recovery
  routes) before the signature failed. The request now carries that digest in
  `X-IA-Body-Digest` — the Blake3 qb64 value (`E` and 43 characters) the signed
  string already contains, sent once. The signed string does not change:
  `IA-REQ-V2` for an owner, `IA-CONTROLLER-REQ-V2` for a controller.
  *(Amended 2026-11-05 by ADR-062: a controller's request that names the origin
  it is sent to is signed in a third form, `IA-CONTROLLER-REQ-V3`, with
  `X-IA-Controller-Origin`. The second form is still read, for a client that names
  no origin, until the agent is made to require one.)*
  - *With the header*, the agent builds the signed string from the header's digest
    and verifies the signature having read **none** of the body. Only then does it
    read the body (up to the bound of the route, `signedBodyBounds`), hashing as it
    reads, and refuses a body whose digest is not the one in the header with `400`
    before any handler sees it. The signature is spent once it verifies, before the
    body is read, so a request that fails on its body has used it and must be signed
    again; a captured request cannot be resent to make the agent read its body twice.
    A header that is present but malformed, or sent twice, is refused,
    never treated as absent.
  - *Without the header* (older clients) the agent reads the body to digest it, as
    before, but only up to the default bound (`maxSignedBodyBytes`, 12 MiB); the
    larger per-route bounds apply only to a request that sends the header.
  - **The header becomes required in a later version**, and the no-header path is
    then removed. Every client sends it now (`SignOwnerRequest` callers, the
    recovery client, and `OwnerSignature`, `OwnerSigningClient`,
    `SigningAsTheIdentityThatOwnsAMachine` and `ControllerSigningClient` in
    `packages/agent_client`).
  - *Vectors*, in `identity-agent-core/server/owner_signature_interop_test.go`
    (`TestTheBodyDigestVectors`) and `packages/agent_client/test/owner_signature_test.dart`,
    both pinned to these values. Seed: bytes 1..32; Identity Agent
    `EGOLDENIDENTITYAGENT`; `POST /api/recovery/start`; timestamp
    `2026-07-27T12:00:00Z`; body `{"archive_b64":"AAAA"}`:
    - `X-IA-Body-Digest: EGYyOU4vRQiXR9KODcp7bLmX2fzoFVAbS9ozYvstod3d`
    - `X-IA-Owner-Sig: 0BCg90nECbDmFqAN13nETR9MK5po24EF5FSlM22NAXpbaag1xsPIPZAOXOA85y2RGF2-UNyC3q7atuiLjxmI5tgD`
    - signed string: `IA-REQ-V2\nEGOLDENIDENTITYAGENT\nPOST\n/api/recovery/start\n2026-07-27T12:00:00Z\nEGYyOU4vRQiXR9KODcp7bLmX2fzoFVAbS9ozYvstod3d`
    - *Mismatch:* the same two headers sent with the body `{"archive_b64":"BBBB"}`
      are refused with `400`, the body never reaching a handler.
  The limit: a program running as the same operating-system user can read the file
  or the starting process's environment, so a program that must not act as the owner
  has to run as a different user.
  - **The secret is sent only to a core that proved it holds it.** Another program
    can hold the port the app expects (on a phone any app may take it first). Before
    sending the secret anywhere, the app asks `GET /api/local-owner/proof?nonce=…`,
    answered to anyone with an HMAC-SHA256, keyed by the secret, of the nonce and the
    port the core is listening on (`server.LocalOwnerProof`). Binding the port means a
    program on the expected port cannot pass the question to the real core on another
    port and hand back its answer. A phone app records the port the core actually
    bound rather than assuming the default.
  - **It never leaves the core.** Read from the environment once and removed there,
    and withheld from every process the core starts (`childenv`); never forwarded to a
    model provider or through the sandbox proxy, and redacted in its logs; never in a
    backup. A sandboxed app's volumes are confined to its own directory, so none can
    mount the data directory.
  - **Windows.** A file's mode means little there; the folder decides who may read it.
    A data directory inside the user's profile inherits an access list only that user
    can read. The core warns loudly when it is anywhere else.
  - A websocket to the core carries the secret as a header like any other request
    (native clients); a browser cannot, and is never the owner.

**What this gives a sealed instance behind a reverse proxy.** The proxy adds a
forwarding header and the instance is not directly reachable, so *every* request is
remote-and-signed and there is no genuinely-local caller to impersonate. The
loopback-owner shortcut simply cannot be reached on such a deployment, which is why
it is safe there to trust the proxy's forwarding headers (they are guaranteed to be
overwritten by something in front).

**The honest limitation.** *(Amended 2026-10-22: an unmarked forwarder over loopback
no longer yields the owner, because it does not hold the local owner secret; it can
still make a request look local, which matters for the local standing a signed caller
has.)* The gate keys on the *presence of a forwarding header*.
An ingress that reached the agent over loopback **without** adding one would look
local. This is why every supported reachability path adds one: a reverse proxy adds
`X-Forwarded-*`, the relay adds its `X-IA-Via-Ingress` marker, and a managed tunnel
adds its provider header. A deployment that puts an un-marking forwarder in front of
the loopback port would defeat the gate, and must not; `TRUST_FORWARDED_HEADERS`
and `AGENT_DIRECT_LISTEN_ADDR` are the two places a deployment states its own shape,
and both are off by default.

### 4. Per-need allocation

The allocation primitive is not a fixed "give me a URL." It carries optional
lifetime, scope and naming so a consumer can ask for the allocation it actually
needs (`AllocateOptions` / `AllocateWithOptions` in `relay/client.go`):

- **lifetime** — `permanent` or `ephemeral` (with a TTL), so a one-transaction URL
  can be short-lived while a relationship URL persists.
- **scope** — `per-relationship` (bound to one Pairwise AID), `identity` (shared
  across a persona), `per-transaction`, `agent-endpoint` (an owner's own device-
  reachable endpoint), or `controller-relationship` (a black box's authenticated
  controller relationship).
- **naming** — `opaque` (a CSPRNG subdomain — the default, unlinkable) or `stable`
  (a chosen, human-meaningful name, for a declared public persona only).

The design is backward-compatible by construction: the zero-value options put
nothing new on the wire, so the request is byte-for-byte the historical
opaque/persistent request and an operator that predates the fields is unaffected;
the operator echoes back the semantics it actually applied so the agent confirms
what it was granted rather than assuming its request was honoured.

**Honest scope of what is wired.** The wire protocol carries the per-need
parameters, but the wired startup path currently makes **one foundational
allocation** — the relay enrollment allocates for its own resource
(`relay_wiring.go` sets `RAID` to the enrollment AID with zero-value options). The
per-relationship fan-out — a distinct opaque allocation per Pairwise AID, which is
what actually delivers URL-layer unlinkability across counterparties — is the
intended extension the primitive is built to support, not yet driven end-to-end.

### 5. The relay only forwards; the agent hosts and signs its own content; relays are per-vendor

A relay is a pure forwarder. It accepts inbound HTTPS at the allocated URL,
terminates TLS, and forwards the request down the agent's outbound tunnel; the
**agent** produces every byte of content and holds every key. The relay never
signs, never mints an identity, and serves only what the agent hosts — the same DID
document and OOBI artifacts the agent would serve directly.

The relay learns an enrollment AID and a public key, and nothing else. Enrollment
is **per-relay**: the agent presents a fresh pairwise enrollment AID to each
operator (derived from the root seed but never the root identity, minted in its own
pool in `relay_wiring.go`), so no operator learns the user's primary identity, and
two operators cannot tell that two enrollments are the same person. The agent signs
its own allocation and release requests with that pairwise enrollment key; the
operator authenticates the agent by verifying the signature it was given at
enrollment, and can never impersonate the agent or silently reassign its hostname.

Relays are therefore **per-vendor, not one central domain**. The neutral core
bundles no relay operator; a deployment that wants URL Relay names one — its own, or
any operator that publishes a conforming service descriptor at
`/.well-known/url-relay-service.json` (`relay/client.go`). The relay protocol is
open: one client, no account, any operator. What a relay does *not* give is a
portable URL — moving operators yields a different hostname, exactly as switching
tunnels would. The portability is in the protocol, so the agent publishes where it
currently answers (the endpoint service republishes on every relay/tunnel change)
rather than relying on a string it handed out once (ADR-033).

## What is shipped, and what is still partial

Shipped and load-bearing today: the single ingress-mode resolver, its private
default and the product's default seam; the root-loopback invariant (the management surface binds `127.0.0.1` in
every mode); the two ingress shapes (dialled-out relay/tunnel, and the reverse-proxy
front with opt-in trusted forwarding); the owner gate (loopback + no-forwarding-
header + not-browser-originated, with the relay's ingress marker and body-carrying
forward); and the per-need allocation options on the wire.

Still partial, and intended to extend the same mechanisms rather than replace them:

- **Per-relationship allocation fan-out.** The wire supports it and the manager can
  request it; the wired path makes one foundational allocation. Driving a distinct
  opaque allocation per Pairwise AID is the remaining step to full URL-layer
  unlinkability across counterparties.
- **DIDComm over Direct.** The direct listener serves identifier documents only;
  `POST /didcomm` is a root route and is not on it. Whether a Direct agent should
  receive first-contact messages off-box, and on what path-scoped form, is not decided here.
- **Pairing a phone over the LAN, in Direct mode (amended 2026-11-05).** Direct mode
  is lookup only. The pairing routes are under `/api` on the root listener, which
  stays on loopback, so a phone on the LAN gets a 404 there; Direct mode does not
  support LAN pairing yet. This is the reason `AGENT_DIRECT_INGRESS_ADDR` existed,
  and it is not replaced.
- **DIDComm in Direct mode (amended 2026-11-05).** Direct mode does not support it
  yet; see the item above.

## Consequences

- Reachability has one answer per instance and one place that decides it, so "how is
  this agent reached" cannot drift between subsystems.
- The management surface is unreachable from outside by construction, in every mode,
  so a leaked ingress URL grants a counterparty only what a positive credential
  authorises — never owner control.
- A sealed instance behind a reverse proxy has no locally-trusted caller to
  impersonate: every request is remote and must be signed, which is what lets a
  remote owner manage hardware they never physically touch while a stranger who
  learned the URL cannot.
- Because the gate keys on forwarding-header presence, the supported deployment
  shapes must each add a marker (proxy header, relay marker, or tunnel header); an
  un-marking forwarder in front of the loopback port is unsupported and unsafe.
- The neutral core depends on no particular relay operator: URL Relay as a default
  means "point at some conforming relay," not a dependency on any one vendor's
  service, and a clone with none configured degrades gracefully to Direct for local
  testing.
