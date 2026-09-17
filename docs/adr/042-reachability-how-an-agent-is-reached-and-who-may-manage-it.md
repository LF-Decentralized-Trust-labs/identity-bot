# ADR-042 — How an agent is reached, and who may manage it

**Status:** Accepted
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

The default is per instance and is only a *default*. The per-product default is
resolved by entity type in `defaultIngressModeForEntity`: an organisation, being
public by nature, defaults to Tunnel; everything else — an individual, and the
neutral core itself — defaults to URL Relay, for privacy by default. Direct is
never a default. A deployment overrides the default with a persisted setting.

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
  and its authenticated owner/management API. It binds **loopback only, in every
  mode** (`rootListenAddr` in `server/listen_addr.go` returns `127.0.0.1:<port>`).
  It is never the surface a counterparty reaches. Binding it to a public address
  would make the root URL a universal correlator, which is exactly what the
  per-relationship-URL model exists to prevent.
- The only externally reachable surface is a **manager-governed ingress**. External
  reach arrives in one of two shapes, and in both the management surface stays on
  loopback:
  1. **The agent's own dialled-out relay or tunnel.** The agent opens an outbound
     connection to the operator and the operator reverse-proxies inbound requests
     back down it to the agent's loopback port (`relay/tunnel.go` delivers each
     framed inbound request to `http://127.0.0.1:<port>`). Nothing external binds
     on the agent host.
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

A developer who needs Direct reach off-box today uses an explicit escape hatch
(`AGENT_DIRECT_INGRESS_ADDR`, read by both `rootListenAddr` and
`endpoint.DirectIngressHost` so bind and advertise cannot disagree). It binds the
**whole** surface to a reachable address and is loud about exposing the management
API; it is developer/testing only. A dedicated, path-scoped, manager-governed
ingress listener that exposes reach *without* exposing the management surface is
the intended home for Direct mode and is not built yet (see the partial-work note
below).

### 3. Who is the owner — the management gate

Ingress answers "can a request reach the agent." A separate gate answers "is this
request the owner." A request is trusted as the genuinely-local owner **only** if
it is a loopback caller, with **no forwarding header**, and **not browser-
originated** (`isLocalOwnerRequest` in `server/mcp_tokens.go`). Anything arriving
through an ingress is remote and must present an owner or controller signature —
the sealed-envelope path or an owner-key signature (`isOwner` in
`server/api_auth.go`); a remote caller otherwise gets only the capability scopes a
positive credential (an MCP access token or a verified capability-grant ACDC)
grants it.

Three properties make this sound:

- **Connection origin is never identity.** A tunnel daemon or a reverse proxy
  connects to the agent from loopback, so a loopback `RemoteAddr` alone cannot mean
  the owner. The presence of any forwarding header — the standard proxy/tunnel
  headers (`X-Forwarded-For`, `X-Real-Ip`, `Cf-Connecting-Ip`, `True-Client-Ip`,
  `Forwarded`) plus the relay's own marker — flips the request to remote
  (`hasForwardingHeaders`).
- **The relay stamps its own marker.** A relay-forwarded request also reaches the
  agent over loopback, so `relay/tunnel.go` sets `X-IA-Via-Ingress: relay` on the
  box, after the client's headers are applied, where a client can neither remove nor
  preempt it. Without this, anyone who learned the relay URL would be treated as the
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

**What this gives a sealed instance behind a reverse proxy.** The proxy adds a
forwarding header and the instance is not directly reachable, so *every* request is
remote-and-signed and there is no genuinely-local caller to impersonate. The
loopback-owner shortcut simply cannot be reached on such a deployment, which is why
it is safe there to trust the proxy's forwarding headers (they are guaranteed to be
overwritten by something in front).

**The honest limitation.** The gate keys on the *presence of a forwarding header*.
An ingress that reached the agent over loopback **without** adding one would look
local. This is why every supported reachability path adds one: a reverse proxy adds
`X-Forwarded-*`, the relay adds its `X-IA-Via-Ingress` marker, and a managed tunnel
adds its provider header. A deployment that puts an un-marking forwarder in front of
the loopback port would defeat the gate, and must not; `TRUST_FORWARDED_HEADERS`
and the direct-ingress hatch are the two places a deployment states its own shape,
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

Shipped and load-bearing today: the single ingress-mode resolver and its per-entity
defaults; the root-loopback invariant (the management surface binds `127.0.0.1` in
every mode); the two ingress shapes (dialled-out relay/tunnel, and the reverse-proxy
front with opt-in trusted forwarding); the owner gate (loopback + no-forwarding-
header + not-browser-originated, with the relay's ingress marker and body-carrying
forward); and the per-need allocation options on the wire.

Still partial, and intended to extend the same mechanisms rather than replace them:

- **Per-relationship allocation fan-out.** The wire supports it and the manager can
  request it; the wired path makes one foundational allocation. Driving a distinct
  opaque allocation per Pairwise AID is the remaining step to full URL-layer
  unlinkability across counterparties.
- **A dedicated path-scoped ingress listener for Direct mode.** Today Direct reach
  off-box uses an explicit whole-surface escape hatch that also exposes the
  management API. The supported end state is a separate, manager-governed, path-
  scoped ingress that exposes reach without exposing the management surface.

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
