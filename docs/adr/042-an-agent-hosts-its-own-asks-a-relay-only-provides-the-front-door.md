# ADR-042 — An agent hosts its own Asks; a relay only provides the front door

**Status:** Accepted
**Date:** 2026-09-08
**Extends:** ADR-041 (One neutral scheme for the protocol's device codes)
**Relates to:** ADR-040 (The protocol's deep-link namespace is vendor-neutral), ADR-006 (Standardized Topology)

## Why this exists

ADR-041 decided the *scheme* for the protocol's links. It named the relay only in
passing — describing `https://host/i/{token}` as "a normal web URL pointing at a
relay" — without ever saying what that relay is or does. That gap left two things
easy to misread:

1. **Is an agent's reachability address a different thing from the addresses it
   hands out?** It is natural to picture a box as having one URL that lets traffic
   in and *separate* URLs it prints into QR codes. It does not.
2. **What is a relay operator's domain (e.g. `agent.grapeid.org`) actually for, and
   does a home box need its own public server on top of it?** It does not.

This ADR settles both from what the code already does, and records the governance
call that follows: relays are **per-vendor**, not one central domain.

## The one address, not two

An agent that anyone but its owner must reach — to fetch an Ask it minted, or its
OOBI — needs a public https address. A box on a home LAN has none: it is behind
NAT, on a private IP no stranger can route to. So it **enrolls with a relay** and is
**allocated one public URL**, and the same URL does both jobs:

- **It is how inbound traffic reaches the box.** The box dials *out* to the relay's
  tunnel endpoint and holds that connection open; the relay accepts requests to the
  allocated hostname and forwards them down the tunnel to the box's local server.
- **It is the base of every URL the box hands out.** `EndpointService.CurrentURL()`
  returns exactly this allocated URL, and `ask_create.go` builds a shared Ask as
  `CurrentURL() + "/i/{token}"`. The OOBI is `CurrentURL() + "/public/oobi/{aid}"`.

So "the URL that lets traffic in" and "the URLs it gives out" are the same string.
There is no second public server address. The only *other* address a box has is its
LAN address for same-network access, and that is never handed to a stranger because
it is not internet-routable.

This is uniform across agent kinds. A desktop ("in front of you") agent is also
behind NAT and reaches the outside world the same way — it enrolls and gets a relay
URL too. The difference that matters is **availability, not mechanism**: a box is
always-on, so an Ask it hosts stays fetchable when someone taps the link hours
later; a desktop agent is reachable only while it runs. That is the reason the
always-on box is the natural host for a *shared* Ask, not a difference in how either
is reached.

## What a relay is, and what it is not

A relay operator's domain does three narrow jobs, and nothing else:

1. **Enrolment / allocation.** It publishes a service descriptor at
   `/.well-known/url-relay-service.json` and, on enrolment, allocates the box a
   public hostname, an allocation token, and a tunnel endpoint (`relay/protocol.go`,
   `relay/client.go`).
2. **Tunnel termination.** It holds the box's outbound tunnel and forwards inbound
   requests down it.
3. **Routing.** It maps the allocated hostname (or mount path) to the right box's
   tunnel — "knowing where the traffic should go."

What it is **not** is a party to the conversation:

- **It never sees the root identity.** Enrolment presents a **pairwise AID minted
  for that one relay and used nowhere else** — never the root
  (`relay/manager.go`; the enrolment body carries `root_aid_enrollment: false`).
  An agent that uses several operators presents each an unrelated AID, so no single
  operator can tell two of its enrolments are the same person, and the AIDs carry
  nothing that lets operators line one up against another.
- **It forwards; it does not answer.** The Ask at `/i/{token}` is minted, held, and
  **signed by the owner's agent** — a relay that tried to answer in the agent's place
  would have to forge a signature it cannot produce. It sees that a token was
  fetched and when, not the meaning of what it carries.

So the trust a relay is given is reachability, not authority. It is the front door,
not the house.

## The decision

1. **A shared Ask is hosted by the asker's own agent, reached through a relay that
   only forwards.** No design in which a relay stores or answers Asks on an agent's
   behalf. This is already how the core works; this ADR fixes it as intended, not
   incidental.

2. **Relays are per-vendor, not one central domain.** Whichever vendor provides a
   user's agent provides (or points at) the relay that gives it a front door. There
   is deliberately no single protocol-wide relay domain every agent must pass
   through — that would be a central chokepoint for both availability and traffic
   metadata, and the protocol's whole point is to not have one. `agent.grapeid.org`
   is *a* vendor's relay, named here only as a concrete example, exactly as one might
   name a hosting provider.

3. **The neutral scheme stays the top priority; a vendor front door is added only
   where a home box physically cannot reach across the internet.** Interoperability
   lives in the neutral `identity-agent://` scheme (ADR-041), in QR scanning, and in
   the neutral signed content an agent serves — all vendor-agnostic. A vendor's relay
   domain supplies only reachability and, for a tapped link, the browser fallback.
   The vendor domain in a URL is whose front door the asker rented; it locks no
   recipient in, because any conforming agent can fetch and verify the neutral signed
   content behind it.

## Which flows are shared (https, self-routing) versus scanned in-app (custom scheme)

This resolves ADR-041's scanned-versus-shared table against the reachability model
above:

| Flow | Reaches | Transport | Form |
|---|---|---|---|
| pair a computer, controller offer, found an org on a box, rent / adopt | you and *your own* device | your app's own camera, or same-network | `identity-agent://…`, read in-app, no relay needed |
| add-contact, login, a transaction request | *another person*, who may not have an app | a tapped link, or a stranger's default camera | `https://<relay-host>/i/{token}` |

The self-and-device flows never need a relay or a tappable link: the app reads the
raw string directly, offline. The person-to-person flows are the ones that go out
over the internet, and they must be `https://` — a `identity-agent://` link tapped
by someone with no app does nothing. One https link serves everyone: the sender
cannot know whether the recipient has an app and does not need to — the OS opens the
app if it is installed and domain-verified, and lands on a web page otherwise.

Two consequences for how those are emitted, so the guarantee actually holds:

- **A QR handed to another person encodes the `https://` link, not the raw custom
  scheme** — otherwise a default camera scanning it has nothing to open. An agent's
  own scanner accepts both.
- **The web landing page bridges or offers a download.** Because a vendor's https
  domain is verified to that vendor's app, a recipient running a *different* vendor's
  app is not opened by it directly; the landing page fires the neutral
  `identity-agent://…` (which any conforming app catches) and, failing that, offers
  the download. The download destination is a **product asset of whichever vendor
  serves the page** (for this project's reference deployment, `grapeid.com`), never a
  host hardcoded in the neutral core — the core defines only the link *shape*.

## Consequences

- No relay-hosted-Ask design is introduced; the relay stays a forwarder. Anyone
  building a relay implements enrolment, tunnelling, and routing — not Ask storage.
- Making a tapped https link open the app is per-vendor operational work: the
  `apple-app-site-association` and `assetlinks.json` verification files live on the
  vendor's relay/landing domain, not in this repo.
- The core hardcodes no download site and no single relay domain; both are supplied
  by the deployment.

## Not decided here

Whether, and how, a relay might cache an Ask to keep it fetchable while an agent is
briefly offline is left open — it trades availability for having the relay hold
content, which this ADR otherwise keeps it from doing, and no current flow needs it
(the always-on box hosts the shared Asks).
